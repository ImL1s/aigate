"""Regression tests for YAML rule engine migration (Task 2).

Verifies that replacing hardcoded DANGEROUS_PATTERNS with YAML rules
produces identical detection behavior.
"""

from __future__ import annotations

from pathlib import Path

from aigate.config import Config
from aigate.models import PackageInfo, RiskLevel
from aigate.prefilter import check_dangerous_patterns, run_prefilter
from aigate.rules.loader import load_rules
from tests.fixtures.fake_malicious_ctx import PACKAGE_FILES as CTX_FILES


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


class TestYamlRulesDetectEval:
    """eval() in source should produce a signal."""

    def test_eval_in_source(self):
        files = {"lib/helpers.py": "result = eval(user_input)"}
        signals = check_dangerous_patterns(files)
        assert len(signals) > 0
        assert any("eval" in s for s in signals)

    def test_eval_in_source_is_low(self):
        files = {"lib/helpers.py": "result = eval(user_input)"}
        signals = check_dangerous_patterns(files)
        assert all("LOW" in s for s in signals)


class TestYamlRulesDetectExecInSetupPy:
    """exec() in setup.py should produce a HIGH signal."""

    def test_exec_in_setup_py_is_high(self):
        files = {"setup.py": "exec(open('payload.py').read())"}
        signals = check_dangerous_patterns(files)
        assert len(signals) > 0
        high_signals = [s for s in signals if "HIGH" in s or "CRITICAL" in s]
        assert len(high_signals) >= 1

    def test_exec_in_setup_py_labeled_install_script(self):
        files = {"setup.py": "exec(open('payload.py').read())"}
        signals = check_dangerous_patterns(files)
        assert any("install_script" in s for s in signals)


class TestYamlRulesDetectCredentialAccess:
    """.ssh/ access should produce a signal."""

    def test_ssh_dir_access(self):
        files = {"stealer.py": "open(os.path.expanduser('~/.ssh/id_rsa')).read()"}
        signals = check_dangerous_patterns(files)
        assert any(".ssh/" in s for s in signals)

    def test_aws_dir_access(self):
        files = {"stealer.py": "open(os.path.expanduser('~/.aws/credentials')).read()"}
        signals = check_dangerous_patterns(files)
        assert any(".aws/" in s for s in signals)


class TestYamlRulesSameCountAsOld:
    """At least 30 rules loaded from builtin YAML files."""

    def test_at_least_30_rules(self):
        builtin = Path(__file__).resolve().parents[2] / "src" / "aigate" / "rules" / "builtin"
        rules = load_rules(builtin_dir=builtin)
        assert len(rules) >= 30, f"Expected >=30 rules, got {len(rules)}"

    def test_rules_cover_all_categories(self):
        """Rules should span execution, credential_access, exfiltration, obfuscation tags."""
        rules = load_rules()
        all_tags = set()
        for r in rules:
            all_tags.update(r.tags)
        for expected in ("execution", "credential_access", "exfiltration", "obfuscation"):
            assert expected in all_tags, f"Missing tag category: {expected}"


class TestRequestsPackageStillSafe:
    """A requests-like package with normal source should be SAFE (no regression)."""

    def test_requests_like_source_no_high_signals(self):
        """Normal library code should only produce LOW signals, not trigger AI review."""
        files = {
            "requests/__init__.py": "from .api import get, post, put, delete\n",
            "requests/api.py": (
                "import urllib3\n"
                "def get(url, **kwargs):\n"
                "    return request('GET', url, **kwargs)\n"
                "def post(url, data=None, **kwargs):\n"
                "    return request('POST', url, data=data, **kwargs)\n"
            ),
            "requests/models.py": (
                "class Response:\n"
                "    def __init__(self):\n"
                "        self.status_code = None\n"
                "        self.text = ''\n"
            ),
        }
        pkg = _make_pkg(name="requests", version="2.31.0")
        config = Config(whitelist=[])
        result = run_prefilter(pkg, config, files)
        # Normal library code should not escalate to AI review
        # (only LOW signals from pattern matches in source files)
        assert result.risk_level in (RiskLevel.NONE, RiskLevel.LOW)

    def test_clean_source_no_signals(self):
        files = {
            "mylib/__init__.py": "VERSION = '1.0.0'\n",
            "mylib/utils.py": "def add(a, b):\n    return a + b\n",
        }
        signals = check_dangerous_patterns(files)
        assert signals == []


class TestMaliciousFixtureStillCaught:
    """The ctx fixture (PyPI domain hijack) should still be caught."""

    def test_ctx_still_critical(self):
        pkg = _make_pkg(name="ctx", version="0.2.6", ecosystem="pypi")
        result = run_prefilter(pkg, Config(), CTX_FILES)
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_ctx_detects_aws_theft(self):
        pkg = _make_pkg(name="ctx", version="0.2.6", ecosystem="pypi")
        result = run_prefilter(pkg, Config(), CTX_FILES)
        assert any(".aws" in s for s in result.risk_signals)

    def test_ctx_detects_setup_py_high(self):
        pkg = _make_pkg(name="ctx", version="0.2.6", ecosystem="pypi")
        result = run_prefilter(pkg, Config(), CTX_FILES)
        high_signals = [s for s in result.risk_signals if "HIGH" in s or "CRITICAL" in s]
        assert len(high_signals) >= 1

    def test_ctx_needs_ai_review(self):
        pkg = _make_pkg(name="ctx", version="0.2.6", ecosystem="pypi")
        result = run_prefilter(pkg, Config(), CTX_FILES)
        assert result.needs_ai_review
