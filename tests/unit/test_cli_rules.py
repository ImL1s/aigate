"""Tests for `aigate rules` CLI commands."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from aigate.cli import main


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def builtin_dir(tmp_path: Path) -> Path:
    d = tmp_path / "builtin"
    d.mkdir()
    (d / "patterns.yml").write_text(
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
              - id: ssh-access
                pattern: '\\.ssh/'
                severity: high
                scope: any
                ecosystem: pypi
                description: "SSH key file access"
                tags: [credential_access]
              - id: requests-post
                pattern: 'requests\\.post'
                severity: low
                scope: source
                ecosystem: "*"
                description: "HTTP POST via requests"
                tags: [exfiltration, network]
        """),
        encoding="utf-8",
    )
    return d


class TestRulesList:
    """aigate rules list command."""

    def test_rules_list_shows_ids(self, runner: CliRunner, builtin_dir: Path) -> None:
        with patch("aigate.rules.loader.BUILTIN_DIR", builtin_dir):
            result = runner.invoke(main, ["rules", "list"])
        assert result.exit_code == 0
        assert "eval-call" in result.output
        assert "exec-call" in result.output
        assert "ssh-access" in result.output
        assert "requests-post" in result.output

    def test_rules_list_filter_by_tag(self, runner: CliRunner, builtin_dir: Path) -> None:
        with patch("aigate.rules.loader.BUILTIN_DIR", builtin_dir):
            result = runner.invoke(main, ["rules", "list", "--tag", "credential_access"])
        assert result.exit_code == 0
        assert "ssh-access" in result.output
        assert "eval-call" not in result.output
        assert "exec-call" not in result.output

    def test_rules_list_filter_by_tag_no_match(self, runner: CliRunner, builtin_dir: Path) -> None:
        with patch("aigate.rules.loader.BUILTIN_DIR", builtin_dir):
            result = runner.invoke(main, ["rules", "list", "--tag", "nonexistent_tag"])
        assert result.exit_code == 0
        assert "No rules found" in result.output


class TestRulesStats:
    """aigate rules stats command."""

    def test_rules_stats_shows_counts(self, runner: CliRunner, builtin_dir: Path) -> None:
        with patch("aigate.rules.loader.BUILTIN_DIR", builtin_dir):
            result = runner.invoke(main, ["rules", "stats"])
        assert result.exit_code == 0
        assert "4" in result.output  # total rules
        # Should show severity breakdown
        assert "medium" in result.output.lower()
        assert "high" in result.output.lower()


class TestRulesUpdatePopular:
    """aigate rules update-popular command."""

    def test_rules_update_popular(self, runner: CliRunner, tmp_path: Path) -> None:
        cache_file = tmp_path / "popular_packages.json"

        async def mock_fetch_pypi(count: int = 1000) -> set[str]:
            return {"requests", "flask", "django", "numpy", "pandas"}

        async def mock_fetch_npm(count: int = 1000) -> set[str]:
            return {"express", "react", "lodash", "axios", "webpack"}

        with (
            patch("aigate.rules.popular_packages._fetch_pypi_top", mock_fetch_pypi),
            patch("aigate.rules.popular_packages._fetch_npm_top", mock_fetch_npm),
            patch("aigate.rules.popular_packages.CACHE_FILE", cache_file),
        ):
            result = runner.invoke(main, ["rules", "update-popular"])
        assert result.exit_code == 0
        assert "Updated" in result.output or "updated" in result.output
        # Cache file should exist
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert "pypi" in data
        assert "npm" in data
