"""Tests for `aigate scan` CLI behavior."""

from __future__ import annotations

import json

from click.testing import CliRunner

from aigate.cli import main
from aigate.config import Config
from aigate.models import ConsensusResult, PackageInfo, PrefilterResult, RiskLevel, Verdict


def _package(*, name: str, version: str, ecosystem: str) -> PackageInfo:
    return PackageInfo(
        name=name,
        version=version,
        ecosystem=ecosystem,
        author="Test Author",
        description="Test package",
        repository="https://github.com/example/test",
    )


def test_scan_json_uses_full_prefilter_and_ai(monkeypatch, tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("demo==1.0.0\n")

    package = _package(name="demo", version="1.0.0", ecosystem="pypi")
    source_files = {"setup.py": "exec('boom')"}
    calls = {"download": 0, "ai": 0}

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve_package(
        name: str, version: str, ecosystem: str, **kw: object
    ) -> PackageInfo:
        assert (name, version, ecosystem) == ("demo", "1.0.0", "pypi")
        return package

    async def fake_download_source(_: PackageInfo, **kw: object) -> dict[str, str]:
        calls["download"] += 1
        return source_files

    def fake_run_prefilter(
        _: PackageInfo,
        __: Config,
        received_source_files: dict[str, str] | None = None,
    ) -> PrefilterResult:
        assert received_source_files == source_files
        return PrefilterResult(
            passed=False,
            reason="needs AI review",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["dangerous_pattern(MEDIUM): exec in setup.py"],
            needs_ai_review=True,
        )

    async def fake_run_consensus(**_: object) -> ConsensusResult:
        calls["ai"] += 1
        return ConsensusResult(
            final_verdict=Verdict.SUSPICIOUS,
            confidence=0.82,
            summary="Consensus: suspicious",
            recommendation="Manual review recommended.",
        )

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.cli.download_source", fake_download_source)
    monkeypatch.setattr("aigate.cli.run_prefilter", fake_run_prefilter)
    monkeypatch.setattr("aigate.cli.run_consensus", fake_run_consensus)

    result = CliRunner().invoke(main, ["scan", str(lockfile), "--json"])

    assert result.exit_code == 1
    assert calls == {"download": 1, "ai": 1}

    payload = json.loads(result.output)
    assert payload["ecosystem"] == "pypi"
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["suspicious"] == 1
    assert payload["packages"][0]["package"]["name"] == "demo"
    assert payload["packages"][0]["consensus"]["final_verdict"] == "suspicious"


def test_scan_skip_ai_uses_prefilter_exit_code(monkeypatch, tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("demo==1.0.0\n")

    package = _package(name="demo", version="1.0.0", ecosystem="pypi")

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve_package(_: str, __: str, ecosystem: str, **kw: object) -> PackageInfo:
        assert ecosystem == "pypi"
        return package

    async def fake_download_source(_: PackageInfo, **kw: object) -> dict[str, str]:
        return {"setup.py": "exec('boom')"}

    def fake_run_prefilter(
        _: PackageInfo,
        __: Config,
        ___: dict[str, str] | None = None,
    ) -> PrefilterResult:
        return PrefilterResult(
            passed=False,
            reason="high risk from prefilter",
            risk_level=RiskLevel.HIGH,
            risk_signals=["dangerous_pattern(HIGH): exec in setup.py"],
            needs_ai_review=True,
        )

    async def fail_run_consensus(**_: object) -> ConsensusResult:
        raise AssertionError("scan should not call AI when --skip-ai is set")

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.cli.download_source", fake_download_source)
    monkeypatch.setattr("aigate.cli.run_prefilter", fake_run_prefilter)
    monkeypatch.setattr("aigate.cli.run_consensus", fail_run_consensus)

    result = CliRunner().invoke(main, ["scan", str(lockfile), "--json", "--skip-ai"])

    assert result.exit_code == 2

    payload = json.loads(result.output)
    assert payload["summary"]["malicious"] == 1
    assert payload["packages"][0]["consensus"] is None
    assert payload["packages"][0]["prefilter"]["risk_level"] == "high"


def test_scan_uses_explicit_ecosystem_option(monkeypatch, tmp_path):
    lockfile = tmp_path / "deps.txt"
    lockfile.write_text("leftpad==1.0.0\n")

    seen: dict[str, str] = {}

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve_package(
        name: str, version: str, ecosystem: str, **kw: object
    ) -> PackageInfo:
        seen["ecosystem"] = ecosystem
        return _package(name=name, version=version, ecosystem=ecosystem)

    async def fake_download_source(_: PackageInfo, **kw: object) -> dict[str, str]:
        return {}

    def fake_run_prefilter(
        _: PackageInfo,
        __: Config,
        ___: dict[str, str] | None = None,
    ) -> PrefilterResult:
        return PrefilterResult(
            passed=True,
            reason="No risk signals detected",
            risk_level=RiskLevel.NONE,
        )

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.cli.download_source", fake_download_source)
    monkeypatch.setattr("aigate.cli.run_prefilter", fake_run_prefilter)

    result = CliRunner().invoke(main, ["scan", str(lockfile), "--json", "--ecosystem", "npm"])

    assert result.exit_code == 0
    assert seen["ecosystem"] == "npm"

    payload = json.loads(result.output)
    assert payload["ecosystem"] == "npm"
    assert payload["summary"]["safe"] == 1


def test_scan_empty_lockfile_has_top_level_decision(monkeypatch, tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("")

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    result = CliRunner().invoke(main, ["scan", str(lockfile), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["decision"] == "safe"
    assert payload["exit_code"] == 0
    assert payload["packages"] == []


def test_scan_enrichment_failure_does_not_become_error(monkeypatch, tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("demo==1.0.0\n")

    package = _package(name="demo", version="1.0.0", ecosystem="pypi")
    config = Config()
    config.enrichment.enabled = True

    monkeypatch.setattr("aigate.cli.Config.load", lambda: config)

    async def fake_resolve_package(_: str, __: str, ___: str, **kw: object) -> PackageInfo:
        return package

    async def fake_download_source(_: PackageInfo, **kw: object) -> dict[str, str]:
        return {"setup.py": "print('hi')"}

    def fake_run_prefilter(
        _: PackageInfo,
        __: Config,
        ___: dict[str, str] | None = None,
    ) -> PrefilterResult:
        return PrefilterResult(
            passed=False,
            reason="needs AI review",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["signal"],
            needs_ai_review=True,
        )

    async def fake_run_enrichment(*_: object) -> object:
        raise RuntimeError("upstream timeout")

    async def fake_run_consensus(**_: object) -> ConsensusResult:
        return ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.72,
            summary="AI found no malicious behavior",
        )

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.cli.download_source", fake_download_source)
    monkeypatch.setattr("aigate.cli.run_prefilter", fake_run_prefilter)
    monkeypatch.setattr("aigate.cli.run_consensus", fake_run_consensus)
    monkeypatch.setattr("aigate.enrichment.run_enrichment", fake_run_enrichment)

    result = CliRunner().invoke(main, ["scan", str(lockfile), "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["decision"] == "needs_review"
    assert payload["exit_code"] == 1
    assert payload["packages"][0]["error"] == ""
