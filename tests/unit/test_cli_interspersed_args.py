"""Tests for CLI interspersed args — global flags after subcommand (U1)."""

from __future__ import annotations

from click.testing import CliRunner

from aigate.cli import main
from aigate.config import Config
from aigate.models import PackageInfo, PrefilterResult, RiskLevel


def _stub(monkeypatch):
    package = PackageInfo(name="demo", version="1.0.0", ecosystem="pypi")
    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())
    monkeypatch.setattr("aigate.cli.get_cached", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.cli.set_cached", lambda *a, **kw: None)

    async def fake_resolve(name, version, ecosystem):
        return package

    async def fake_download(_, **kw):
        return {"setup.py": "print('hi')"}

    def fake_prefilter(_, __, ___=None):
        return PrefilterResult(
            passed=True, reason="ok", risk_level=RiskLevel.LOW, needs_ai_review=False
        )

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve)
    monkeypatch.setattr("aigate.cli.download_source", fake_download)
    monkeypatch.setattr("aigate.cli.run_prefilter", fake_prefilter)


def test_quiet_flag_after_subcommand(monkeypatch):
    """-q after 'check' should work: `aigate check demo -q --skip-ai`."""
    _stub(monkeypatch)
    result = CliRunner().invoke(main, ["check", "demo", "-q", "--skip-ai"])
    assert result.exit_code == 0
    # Quiet mode should not have Rich panel borders
    assert "╭" not in result.output


def test_verbose_flag_after_subcommand(monkeypatch):
    """-V after 'check' should work: `aigate check demo -V --skip-ai`."""
    _stub(monkeypatch)
    result = CliRunner().invoke(main, ["check", "demo", "-V", "--skip-ai"])
    assert result.exit_code == 0
