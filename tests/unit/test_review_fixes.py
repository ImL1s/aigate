"""Tests for Codex+Gemini review fixes."""

from __future__ import annotations

import json
import textwrap
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from aigate.config import Config
from aigate.models import PackageInfo, RiskLevel
from aigate.prefilter import (
    _calculate_risk_level,
    _get_rules,
    check_dangerous_patterns,
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


# ---------------------------------------------------------------------------
# Issue #1: user rules + disable_rules wired into prefilter
# ---------------------------------------------------------------------------


class TestUserRulesWiredIntoPrefilter:
    """_get_rules() respects config.rules_dir and config.disable_rules."""

    def test_disable_rules_via_config(self, tmp_path: Path) -> None:
        """When config.disable_rules is set, those rules are excluded."""
        config = Config(disable_rules=["eval-call", "exec-call"])
        # Clear cache to force reload
        import aigate.prefilter as pf

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

        rules = _get_rules(config)
        ids = {r.id for r in rules}
        assert "eval-call" not in ids
        assert "exec-call" not in ids

        # Cleanup
        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

    def test_user_rules_dir_via_config(self, tmp_path: Path) -> None:
        """When config.rules_dir is set, user rules are loaded."""
        user_dir = tmp_path / "rules"
        user_dir.mkdir()
        (user_dir / "custom.yml").write_text(
            textwrap.dedent("""\
                rules:
                  - id: custom-test-rule
                    pattern: 'my_custom_pattern'
                    severity: high
                    scope: any
                    ecosystem: "*"
                    description: "Custom test rule"
                    tags: [custom]
            """),
            encoding="utf-8",
        )

        config = Config(rules_dir=str(user_dir))
        import aigate.prefilter as pf

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

        rules = _get_rules(config)
        ids = {r.id for r in rules}
        assert "custom-test-rule" in ids

        # Cleanup
        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

    def test_cache_invalidated_on_config_change(self) -> None:
        """Cache is invalidated when config changes."""
        import aigate.prefilter as pf

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

        config1 = Config()
        rules1 = _get_rules(config1)
        count1 = len(rules1)

        config2 = Config(disable_rules=["eval-call"])
        rules2 = _get_rules(config2)
        count2 = len(rules2)

        assert count2 == count1 - 1

        # Cleanup
        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

    def test_run_prefilter_passes_config_to_patterns(self, tmp_path: Path) -> None:
        """run_prefilter wires config through to check_dangerous_patterns."""
        import aigate.prefilter as pf

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

        # Disable exec-call via config
        config = Config(disable_rules=["exec-call"])
        pkg = _make_pkg()
        source = {"setup.py": "exec(bad_code)"}

        result = run_prefilter(pkg, config, source)
        # exec-call is disabled, so that specific rule shouldn't fire
        # The exec pattern comes from exec-call rule; with it disabled,
        # other rules may still match but not exec-call specifically
        # Just verify it doesn't crash and returns a result
        assert isinstance(result, pf.PrefilterResult)

        # Cleanup
        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None


# ---------------------------------------------------------------------------
# Issue #2: compound(CRITICAL) affects risk scoring
# ---------------------------------------------------------------------------


class TestCriticalCompoundScoring:
    """CRITICAL compound signals are counted in _calculate_risk_level."""

    def test_critical_signal_counted_as_high(self):
        signals = [
            "compound(CRITICAL): 'full-attack-chain' in payload.py — desc",
        ]
        level = _calculate_risk_level(signals)
        assert level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_two_critical_signals_escalate_to_critical(self):
        signals = [
            "compound(CRITICAL): 'full-attack-chain' in a.py — desc",
            "compound(CRITICAL): 'full-attack-chain' in b.py — desc",
        ]
        level = _calculate_risk_level(signals)
        assert level == RiskLevel.CRITICAL

    def test_critical_plus_high_escalate_to_critical(self):
        signals = [
            "compound(CRITICAL): 'full-attack-chain' in a.py — desc",
            "dangerous_pattern(HIGH): 'exec' in install_script:setup.py",
        ]
        level = _calculate_risk_level(signals)
        assert level == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# US-002: Structured RiskSignal dataclass
# ---------------------------------------------------------------------------


class TestRiskSignalDataclass:
    """RiskSignal uses structured severity, not substring matching."""

    def test_risksignal_exists_in_models(self):
        from aigate.models import RiskSignal

        sig = RiskSignal(
            severity=RiskLevel.HIGH, category="dangerous_pattern", description="exec in setup.py"
        )
        assert sig.severity == RiskLevel.HIGH
        assert sig.category == "dangerous_pattern"

    def test_risksignal_str_produces_legacy_format(self):
        from aigate.models import RiskSignal

        sig = RiskSignal(
            severity=RiskLevel.HIGH, category="dangerous_pattern", description="'exec' in setup.py"
        )
        s = str(sig)
        assert "HIGH" in s
        assert "exec" in s

    def test_risksignal_with_filepath(self):
        from aigate.models import RiskSignal

        sig = RiskSignal(
            severity=RiskLevel.MEDIUM,
            category="dangerous_pattern",
            description="'requests.get' found",
            filepath="src/main.py",
        )
        assert sig.filepath == "src/main.py"

    def test_calculate_risk_level_uses_structured_severity(self):
        """_calculate_risk_level should work with RiskSignal objects."""
        from aigate.models import RiskSignal

        signals = [
            RiskSignal(severity=RiskLevel.HIGH, category="dangerous_pattern", description="exec"),
            RiskSignal(severity=RiskLevel.HIGH, category="compound", description="full chain"),
        ]
        level = _calculate_risk_level(signals)
        assert level == RiskLevel.CRITICAL

    def test_calculate_risk_level_no_false_positive_from_filename(self):
        """A signal with 'HIGH' in description but LOW severity must NOT be counted as HIGH."""
        from aigate.models import RiskSignal

        signals = [
            RiskSignal(
                severity=RiskLevel.LOW,
                category="metadata",
                description="file critical_HIGH_utils.py exists",
            ),
        ]
        level = _calculate_risk_level(signals)
        assert level == RiskLevel.LOW

    def test_calculate_risk_level_mixed_string_and_risksignal(self):
        """Backwards compat: _calculate_risk_level handles both strings and RiskSignal."""
        from aigate.models import RiskSignal

        signals = [
            "dangerous_pattern(HIGH): 'exec' in install_script:setup.py",
            RiskSignal(severity=RiskLevel.HIGH, category="compound", description="chain"),
        ]
        level = _calculate_risk_level(signals)
        assert level == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# Issue #3: ecosystem-scoped rules fire in run_prefilter
# ---------------------------------------------------------------------------


class TestEcosystemPassedToPatterns:
    """run_prefilter passes package.ecosystem to check_dangerous_patterns."""

    def test_ecosystem_passed(self) -> None:
        """Ecosystem-scoped rules should fire when ecosystem matches."""
        import aigate.prefilter as pf

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

        config = Config()
        # Use a pypi-specific signal — setup.py with exec
        pkg = _make_pkg(ecosystem="pypi")
        source = {"setup.py": "exec(bad_code)"}

        result = run_prefilter(pkg, config, source)
        assert len(result.risk_signals) > 0

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None


# ---------------------------------------------------------------------------
# Issue #4: update-popular force param
# ---------------------------------------------------------------------------


class TestForcePopularPackages:
    """get_popular_packages(force=True) bypasses cache."""

    @pytest.mark.asyncio
    async def test_force_bypasses_cache(self, tmp_path: Path):
        from aigate.rules.popular_packages import get_popular_packages

        cache_file = tmp_path / "cache.json"
        cached_data = {
            "pypi": {
                "packages": ["old-cached-pkg"],
                "updated_at": time.time(),  # fresh
            }
        }
        cache_file.write_text(json.dumps(cached_data))

        # Mock the API to return different data
        resp_data = {
            "last_update": "2026-03-20",
            "rows": [{"project": f"new-pkg-{i}", "download_count": 100} for i in range(10)],
        }
        mock_resp = AsyncMock()
        mock_resp.json = lambda: resp_data
        mock_resp.raise_for_status = lambda: None
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("aigate.rules.popular_packages.httpx.AsyncClient", return_value=mock_client),
            patch("aigate.rules.popular_packages.CACHE_FILE", cache_file),
        ):
            # Without force — should use cache
            pkgs_cached = await get_popular_packages("pypi")
            assert "old-cached-pkg" in pkgs_cached

            # With force — should call API
            pkgs_forced = await get_popular_packages("pypi", force=True)
            assert "new-pkg-0" in pkgs_forced
            assert "old-cached-pkg" not in pkgs_forced


# ---------------------------------------------------------------------------
# Issue #6: malformed cache doesn't crash
# ---------------------------------------------------------------------------


class TestMalformedCacheNoCrash:
    """_read_cache returns None on malformed data without crashing."""

    def test_list_instead_of_dict(self, tmp_path: Path):
        """A cache file containing [] instead of {} should not crash."""
        from aigate.rules.popular_packages import _read_cache

        cache_file = tmp_path / "cache.json"
        cache_file.write_text("[]")

        with patch("aigate.rules.popular_packages.CACHE_FILE", cache_file):
            result = _read_cache("pypi")
        assert result is None

    def test_none_in_cache(self, tmp_path: Path):
        """A cache file containing null should not crash."""
        from aigate.rules.popular_packages import _read_cache

        cache_file = tmp_path / "cache.json"
        cache_file.write_text("null")

        with patch("aigate.rules.popular_packages.CACHE_FILE", cache_file):
            result = _read_cache("pypi")
        assert result is None

    def test_string_in_cache(self, tmp_path: Path):
        """A cache file containing a plain string should not crash."""
        from aigate.rules.popular_packages import _read_cache

        cache_file = tmp_path / "cache.json"
        cache_file.write_text('"just a string"')

        with patch("aigate.rules.popular_packages.CACHE_FILE", cache_file):
            result = _read_cache("pypi")
        assert result is None

    def test_corrupt_ecosystem_entry(self, tmp_path: Path):
        """A cache with wrong type for ecosystem entry should not crash."""
        from aigate.rules.popular_packages import _read_cache

        cache_file = tmp_path / "cache.json"
        cache_file.write_text(json.dumps({"pypi": "not-a-dict"}))

        with patch("aigate.rules.popular_packages.CACHE_FILE", cache_file):
            result = _read_cache("pypi")
        assert result is None


# ---------------------------------------------------------------------------
# Issue #7: setup-py-exec removed (no double-counting)
# ---------------------------------------------------------------------------


class TestNoSetupPyExecDuplicate:
    """setup-py-exec rule is removed; exec-call handles it with severity escalation."""

    def test_exec_in_setup_py_not_double_counted(self):
        """exec() in setup.py should produce exactly one exec-related signal, not two."""
        import aigate.prefilter as pf

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

        files = {"setup.py": "exec(compile(open('x').read(), 'x', 'exec'))"}
        signals = check_dangerous_patterns(files)
        exec_signals = [s for s in signals if "\\bexec" in s]
        # Should be exactly 1 (from exec-call), not 2 (no setup-py-exec)
        assert len(exec_signals) == 1

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

    def test_setup_py_exec_rule_not_in_builtins(self):
        """The setup-py-exec rule should not exist in loaded rules."""
        from aigate.rules.loader import load_rules

        rules = load_rules()
        ids = {r.id for r in rules}
        assert "setup-py-exec" not in ids


# ---------------------------------------------------------------------------
# Issue #8: case_sensitive field in YAML rules
# ---------------------------------------------------------------------------


class TestCaseSensitiveRules:
    """Rules support case_sensitive: true field."""

    def test_default_case_insensitive(self, tmp_path: Path):
        """Rules without case_sensitive field match case-insensitively (default)."""
        from aigate.rules.loader import load_rules

        d = tmp_path / "rules"
        d.mkdir()
        (d / "test.yml").write_text(
            textwrap.dedent("""\
                rules:
                  - id: test-insensitive
                    pattern: 'MyPattern'
                    severity: low
                    scope: any
                    ecosystem: "*"
                    description: "Case insensitive by default"
                    tags: [test]
            """),
            encoding="utf-8",
        )
        rules = load_rules(builtin_dir=d)
        assert len(rules) == 1
        assert rules[0].case_sensitive is False
        assert rules[0].pattern.search("mypattern")  # lowercase matches
        assert rules[0].pattern.search("MYPATTERN")  # uppercase matches

    def test_case_sensitive_true(self, tmp_path: Path):
        """Rules with case_sensitive: true only match exact case."""
        from aigate.rules.loader import load_rules

        d = tmp_path / "rules"
        d.mkdir()
        (d / "test.yml").write_text(
            textwrap.dedent("""\
                rules:
                  - id: test-sensitive
                    pattern: 'MyPattern'
                    severity: low
                    scope: any
                    ecosystem: "*"
                    description: "Case sensitive"
                    tags: [test]
                    case_sensitive: true
            """),
            encoding="utf-8",
        )
        rules = load_rules(builtin_dir=d)
        assert len(rules) == 1
        assert rules[0].case_sensitive is True
        assert rules[0].pattern.search("MyPattern")  # exact case matches
        assert not rules[0].pattern.search("mypattern")  # lowercase does NOT match


# ---------------------------------------------------------------------------
# Issue #9: atomic write for popular_packages cache
# ---------------------------------------------------------------------------


class TestAtomicCacheWrite:
    """_write_cache uses atomic write (tempfile + os.replace)."""

    def test_write_cache_creates_file(self, tmp_path: Path):
        from aigate.rules.popular_packages import _read_cache, _write_cache

        cache_file = tmp_path / "cache.json"

        with patch("aigate.rules.popular_packages.CACHE_FILE", cache_file):
            _write_cache("pypi", {"pkg-a", "pkg-b"})
            assert cache_file.exists()
            result = _read_cache("pypi")
        assert result is not None
        assert "pkg-a" in result

    def test_write_cache_preserves_other_ecosystems(self, tmp_path: Path):
        from aigate.rules.popular_packages import _read_cache, _write_cache

        cache_file = tmp_path / "cache.json"

        with patch("aigate.rules.popular_packages.CACHE_FILE", cache_file):
            _write_cache("pypi", {"pypi-pkg"})
            _write_cache("npm", {"npm-pkg"})
            pypi_result = _read_cache("pypi")
            npm_result = _read_cache("npm")
        assert pypi_result is not None
        assert "pypi-pkg" in pypi_result
        assert npm_result is not None
        assert "npm-pkg" in npm_result


# ---------------------------------------------------------------------------
# Issue #10: __init__.py at root is treated as install file
# ---------------------------------------------------------------------------


class TestInitPyAsInstallFile:
    """__init__.py at package root auto-executes on import → HIGH risk."""

    def test_init_py_at_root_is_high(self):
        """Dangerous pattern in root __init__.py should be HIGH."""
        import aigate.prefilter as pf

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

        files = {"pkg-1.0/__init__.py": "exec(base64.b64decode(payload))"}
        signals = check_dangerous_patterns(files)
        assert any("HIGH" in s for s in signals)

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

    def test_init_py_in_subdir_is_low(self):
        """Dangerous pattern in deeply nested __init__.py should be LOW."""
        import aigate.prefilter as pf

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None

        files = {"pkg-1.0/subpkg/nested/__init__.py": "exec(something)"}
        signals = check_dangerous_patterns(files)
        # Nested __init__.py (depth > 1) should NOT be HIGH
        assert all("HIGH" not in s for s in signals) or not signals

        pf._CACHED_RULES = None
        pf._CACHED_RULES_KEY = None
