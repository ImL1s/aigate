"""Tests for YAML rule loader — TDD: written before implementation."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


@pytest.fixture()
def tmp_builtin_dir(tmp_path: Path) -> Path:
    d = tmp_path / "builtin"
    d.mkdir()
    (d / "sample.yml").write_text(
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
        """)
    )
    return d


@pytest.fixture()
def tmp_user_dir(tmp_path: Path) -> Path:
    d = tmp_path / "user"
    d.mkdir()
    (d / "overrides.yml").write_text(
        textwrap.dedent("""\
            rules:
              - id: eval-call
                pattern: '\\beval\\s*\\('
                severity: critical
                scope: install_script
                ecosystem: "pypi"
                description: "eval() override — critical in install scripts"
                tags: [execution, override]
        """)
    )
    return d


class TestLoadBuiltinRules:
    """load_rules() loads all YAML files and returns Rule objects."""

    def test_load_builtin_rules(self, tmp_builtin_dir: Path) -> None:
        from aigate.rules.loader import load_rules

        rules = load_rules(builtin_dir=tmp_builtin_dir)
        assert len(rules) == 2
        ids = {r.id for r in rules}
        assert ids == {"eval-call", "exec-call"}

    def test_rule_has_correct_fields(self, tmp_builtin_dir: Path) -> None:
        import re

        from aigate.rules.loader import Rule, load_rules

        rules = load_rules(builtin_dir=tmp_builtin_dir)
        eval_rule = next(r for r in rules if r.id == "eval-call")

        assert isinstance(eval_rule, Rule)
        assert eval_rule.id == "eval-call"
        assert isinstance(eval_rule.pattern, re.Pattern)
        assert eval_rule.pattern.search("eval(")
        assert eval_rule.severity == "medium"
        assert eval_rule.scope == "any"
        assert eval_rule.ecosystem == "*"
        assert eval_rule.description == "Dynamic code execution via eval()"
        assert eval_rule.tags == ["execution", "dynamic"]


class TestUserRulesOverride:
    """User rules with matching id override builtin rules."""

    def test_user_rules_override_builtin(self, tmp_builtin_dir: Path, tmp_user_dir: Path) -> None:
        from aigate.rules.loader import load_rules

        rules = load_rules(builtin_dir=tmp_builtin_dir, user_dir=tmp_user_dir)
        eval_rule = next(r for r in rules if r.id == "eval-call")

        # User override should win
        assert eval_rule.severity == "critical"
        assert eval_rule.scope == "install_script"
        assert eval_rule.ecosystem == "pypi"
        assert eval_rule.description == "eval() override — critical in install scripts"
        assert eval_rule.tags == ["execution", "override"]

        # Non-overridden rule still present
        assert any(r.id == "exec-call" for r in rules)


class TestInvalidYamlSkipped:
    """Invalid YAML files are skipped with a warning, not crash."""

    def test_invalid_yaml_skipped(self, tmp_path: Path) -> None:
        from aigate.rules.loader import load_rules

        d = tmp_path / "bad"
        d.mkdir()
        (d / "broken.yml").write_text("rules:\n  - id: {{{invalid yaml")
        (d / "good.yml").write_text(
            textwrap.dedent("""\
                rules:
                  - id: good-rule
                    pattern: 'good'
                    severity: low
                    scope: any
                    ecosystem: "*"
                    description: "A good rule"
                    tags: [test]
            """)
        )

        rules = load_rules(builtin_dir=d)
        # Should still load the good rule despite the broken file
        assert len(rules) == 1
        assert rules[0].id == "good-rule"

    def test_missing_dir_returns_empty(self) -> None:
        from aigate.rules.loader import load_rules

        rules = load_rules(builtin_dir=Path("/nonexistent/path"))
        assert rules == []


class TestEcosystemFilter:
    """Rules can be filtered by ecosystem."""

    def test_ecosystem_filter(self, tmp_path: Path) -> None:
        from aigate.rules.loader import load_rules

        d = tmp_path / "eco"
        d.mkdir()
        (d / "mixed.yml").write_text(
            textwrap.dedent("""\
                rules:
                  - id: pypi-only
                    pattern: 'pypi_pattern'
                    severity: medium
                    scope: any
                    ecosystem: "pypi"
                    description: "PyPI only"
                    tags: [test]
                  - id: npm-only
                    pattern: 'npm_pattern'
                    severity: medium
                    scope: any
                    ecosystem: "npm"
                    description: "npm only"
                    tags: [test]
                  - id: universal
                    pattern: 'universal_pattern'
                    severity: high
                    scope: any
                    ecosystem: "*"
                    description: "Applies to all"
                    tags: [test]
            """)
        )

        rules = load_rules(builtin_dir=d, ecosystem="pypi")
        ids = {r.id for r in rules}
        assert "pypi-only" in ids
        assert "universal" in ids
        assert "npm-only" not in ids


class TestBuiltinRuleCount:
    """The real builtin rules directory has at least 30 rules."""

    def test_load_returns_at_least_30_rules(self) -> None:
        from aigate.rules.loader import load_rules

        builtin = Path(__file__).resolve().parents[2] / "src" / "aigate" / "rules" / "builtin"
        rules = load_rules(builtin_dir=builtin)
        assert len(rules) >= 30, f"Expected >=30 rules, got {len(rules)}"
