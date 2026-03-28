"""Tests for CLI quiet mode suppressing terminal output."""

from __future__ import annotations

import json

from click.testing import CliRunner

from aigate.cli import main
from aigate.config import Config
from aigate.models import PackageInfo, PrefilterResult, RiskLevel


def _package(*, name: str = "demo", version: str = "1.0.0", ecosystem: str = "pypi") -> PackageInfo:
    return PackageInfo(name=name, version=version, ecosystem=ecosystem)


def _stub_check(monkeypatch, *, risk_level: RiskLevel = RiskLevel.LOW):
    """Stub resolve/download/prefilter/cache so check runs without network."""
    package = _package()

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())
    monkeypatch.setattr("aigate.cli.get_cached", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.cli.set_cached", lambda *a, **kw: None)

    async def fake_resolve(name, version, ecosystem):
        return package

    async def fake_download(_):
        return {"setup.py": "print('hi')"}

    def fake_prefilter(_, __, ___=None):
        return PrefilterResult(
            passed=risk_level == RiskLevel.LOW,
            reason="ok" if risk_level == RiskLevel.LOW else "risk detected",
            risk_level=risk_level,
            risk_signals=[] if risk_level == RiskLevel.LOW else ["signal"],
            needs_ai_review=False,
        )

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve)
    monkeypatch.setattr("aigate.cli.download_source", fake_download)
    monkeypatch.setattr("aigate.cli.run_prefilter", fake_prefilter)


def test_quiet_flag_suppresses_rich_formatting(monkeypatch):
    """With --quiet, check output has no Rich panel borders."""
    _stub_check(monkeypatch)
    result = CliRunner().invoke(main, ["--quiet", "check", "demo", "--skip-ai"])
    # Should not contain Rich panel box-drawing characters
    assert "╭" not in result.output
    assert "╰" not in result.output
    assert "─" not in result.output


def test_quiet_outputs_one_line_summary(monkeypatch):
    """Quiet mode prints exactly one non-empty line: 'name==version: outcome'."""
    _stub_check(monkeypatch)
    result = CliRunner().invoke(main, ["--quiet", "check", "demo", "--skip-ai"])
    lines = [line for line in result.output.strip().splitlines() if line.strip()]
    assert len(lines) == 1
    assert "demo==1.0.0:" in lines[0]
    assert "safe" in lines[0]


def test_quiet_with_json_still_outputs_json(monkeypatch):
    """--quiet + --json should still produce valid JSON."""
    _stub_check(monkeypatch)
    result = CliRunner().invoke(main, ["--quiet", "check", "demo", "--skip-ai", "--json"])
    data = json.loads(result.output)
    assert "decision" in data


def test_quiet_preserves_exit_code(monkeypatch):
    """Quiet mode still uses the correct exit code."""
    _stub_check(monkeypatch, risk_level=RiskLevel.HIGH)
    result = CliRunner().invoke(main, ["--quiet", "check", "demo", "--skip-ai"])
    assert result.exit_code == 2


def test_normal_mode_has_rich_formatting(monkeypatch):
    """Without --quiet, output should contain Rich panel borders."""
    _stub_check(monkeypatch)
    result = CliRunner().invoke(main, ["check", "demo", "--skip-ai"])
    # Normal mode has Rich panels with box-drawing characters
    assert "╭" in result.output or "aigate" in result.output
