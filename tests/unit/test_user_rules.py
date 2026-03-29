"""Tests for user custom rules and rule disable config."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aigate.rules.loader import load_rules


@pytest.fixture()
def builtin_dir(tmp_path: Path) -> Path:
    d = tmp_path / "builtin"
    d.mkdir()
    (d / "base.yml").write_text(
        textwrap.dedent("""\
            rules:
              - id: eval-call
                pattern: '\\beval\\s*\\('
                severity: medium
                scope: any
                ecosystem: "*"
                description: "Dynamic code execution via eval()"
                tags: [execution, dynamic]
              - id: exec-call
                pattern: '\\bexec\\s*\\('
                severity: medium
                scope: any
                ecosystem: "*"
                description: "Dynamic code execution via exec()"
                tags: [execution, dynamic]
        """),
        encoding="utf-8",
    )
    return d


@pytest.fixture()
def user_dir(tmp_path: Path) -> Path:
    d = tmp_path / "user"
    d.mkdir()
    return d


class TestUserRuleOverridesBuiltin:
    """User rules with the same ID override built-in rules."""

    def test_user_rule_overrides_builtin(self, builtin_dir: Path, user_dir: Path) -> None:
        # User overrides eval-call with higher severity
        (user_dir / "custom.yml").write_text(
            textwrap.dedent("""\
                rules:
                  - id: eval-call
                    pattern: '\\beval\\s*\\('
                    severity: critical
                    scope: install_script
                    ecosystem: "*"
                    description: "User override: eval in install script is critical"
                    tags: [execution, dynamic, custom]
            """),
            encoding="utf-8",
        )
        rules = load_rules(builtin_dir=builtin_dir, user_dir=user_dir)
        eval_rules = [r for r in rules if r.id == "eval-call"]
        assert len(eval_rules) == 1
        assert eval_rules[0].severity == "critical"
        assert eval_rules[0].scope == "install_script"
        assert "custom" in eval_rules[0].tags

    def test_user_rule_adds_new_rule(self, builtin_dir: Path, user_dir: Path) -> None:
        (user_dir / "my_rule.yml").write_text(
            textwrap.dedent("""\
                rules:
                  - id: custom-check
                    pattern: 'my_dangerous_func'
                    severity: high
                    scope: any
                    ecosystem: pypi
                    description: "Custom project-specific check"
                    tags: [custom]
            """),
            encoding="utf-8",
        )
        rules = load_rules(builtin_dir=builtin_dir, user_dir=user_dir)
        ids = {r.id for r in rules}
        assert "custom-check" in ids
        assert "eval-call" in ids  # builtin still present


class TestDisableRules:
    """disable_rules config skips specified rule IDs."""

    def test_disable_rules_skips_ids(self, builtin_dir: Path) -> None:
        rules = load_rules(
            builtin_dir=builtin_dir,
            disable_rules=["eval-call"],
        )
        ids = {r.id for r in rules}
        assert "eval-call" not in ids
        assert "exec-call" in ids

    def test_disable_multiple_rules(self, builtin_dir: Path) -> None:
        rules = load_rules(
            builtin_dir=builtin_dir,
            disable_rules=["eval-call", "exec-call"],
        )
        assert len(rules) == 0

    def test_disable_nonexistent_rule_no_error(self, builtin_dir: Path) -> None:
        rules = load_rules(
            builtin_dir=builtin_dir,
            disable_rules=["nonexistent-rule"],
        )
        assert len(rules) == 2  # both builtin rules remain


class TestUserRulesDirMissing:
    """Missing user rules dir should not crash."""

    def test_user_rules_dir_missing_no_crash(self, builtin_dir: Path, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent_dir"
        rules = load_rules(builtin_dir=builtin_dir, user_dir=missing)
        assert len(rules) == 2  # only builtins loaded

    def test_default_user_dir_missing_no_crash(self, builtin_dir: Path) -> None:
        # When user_dir is None, it should work fine
        rules = load_rules(builtin_dir=builtin_dir, user_dir=None)
        assert len(rules) == 2


class TestConfigRulesSection:
    """Config rules section parses correctly."""

    def test_config_rules_dir_default(self) -> None:
        from aigate.config import Config

        config = Config.default()
        assert config.rules_dir == ""
        assert config.disable_rules == []

    def test_config_rules_from_yaml(self, tmp_path: Path) -> None:
        from aigate.config import Config

        cfg_path = tmp_path / ".aigate.yml"
        cfg_path.write_text(
            textwrap.dedent("""\
                models: []
                rules:
                  user_rules_dir: ~/.aigate/rules/
                  disable_rules:
                    - eval-call
                    - exec-call
            """),
            encoding="utf-8",
        )
        config = Config.load(cfg_path)
        assert config.rules_dir == "~/.aigate/rules/"
        assert config.disable_rules == ["eval-call", "exec-call"]
