"""Test aigate can detect LiteLLM-style malicious patterns.

Uses synthetic test fixtures — NO real malware is downloaded or executed.
"""

from aigate.config import Config
from aigate.models import PackageInfo, RiskLevel
from aigate.prefilter import run_prefilter
from tests.fixtures.fake_malicious_litellm import PACKAGE_FILES


def _litellm_pkg() -> PackageInfo:
    return PackageInfo(
        name="litellm",
        version="1.82.7",
        ecosystem="pypi",
        author="",  # attacker didn't set author
        description="LLM proxy",
        has_install_scripts=True,
        repository="",
        homepage="",
    )


class TestLiteLLMDetection:
    def test_prefilter_flags_malicious(self):
        """Pre-filter should flag the fake malicious package."""
        result = run_prefilter(_litellm_pkg(), Config(), PACKAGE_FILES)
        assert result.needs_ai_review
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_detects_pth_file(self):
        """Should detect .pth file (auto-execute on Python startup)."""
        result = run_prefilter(_litellm_pkg(), Config(), PACKAGE_FILES)
        pth_signals = [s for s in result.risk_signals if ".pth" in s or "HIGH" in s]
        assert len(pth_signals) > 0, f"No .pth detection in signals: {result.risk_signals}"

    def test_detects_base64_exec(self):
        """Should detect base64 decode + exec pattern."""
        result = run_prefilter(_litellm_pkg(), Config(), PACKAGE_FILES)
        b64_signals = [
            s for s in result.risk_signals if "base64" in s.lower() or "exec" in s.lower()
        ]
        assert len(b64_signals) > 0, f"No base64/exec detection: {result.risk_signals}"

    def test_detects_credential_theft(self):
        """Should detect credential file access (.ssh, .aws)."""
        result = run_prefilter(_litellm_pkg(), Config(), PACKAGE_FILES)
        cred_signals = [s for s in result.risk_signals if ".ssh" in s or ".aws" in s or ".env" in s]
        assert len(cred_signals) > 0, f"No credential theft detection: {result.risk_signals}"

    def test_detects_exfiltration(self):
        """Should detect HTTP exfiltration to unknown domain."""
        result = run_prefilter(_litellm_pkg(), Config(), PACKAGE_FILES)
        net_signals = [
            s for s in result.risk_signals if "request" in s.lower() or "urlopen" in s.lower()
        ]
        assert len(net_signals) > 0, f"No network exfiltration detection: {result.risk_signals}"

    def test_detects_token_theft(self):
        """Should detect env var token reading (GITHUB_TOKEN etc)."""
        result = run_prefilter(_litellm_pkg(), Config(), PACKAGE_FILES)
        token_signals = [s for s in result.risk_signals if "TOKEN" in s]
        assert len(token_signals) > 0, f"No token theft detection: {result.risk_signals}"

    def test_detects_obfuscated_exec(self):
        """Should detect obfuscated code (base64+exec even if entropy check skips short lines)."""
        result = run_prefilter(_litellm_pkg(), Config(), PACKAGE_FILES)
        obf_signals = [
            s
            for s in result.risk_signals
            if "obfuscated_loader" in s
            or ("exec" in s.lower() and "obfuscated" in s.lower())
            or ("base64" in s.lower())
        ]
        assert len(obf_signals) > 0, f"No obfuscation detection: {result.risk_signals}"

    def test_signal_count(self):
        """Should detect multiple risk signals (comprehensive coverage)."""
        result = run_prefilter(_litellm_pkg(), Config(), PACKAGE_FILES)
        # Expect at least 8 signals for a highly malicious package
        assert len(result.risk_signals) >= 8, (
            f"Only {len(result.risk_signals)} signals detected, expected >=8: {result.risk_signals}"
        )
