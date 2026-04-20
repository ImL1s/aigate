"""Tests for `aigate check` CLI behavior."""

from __future__ import annotations

import json

from click.testing import CliRunner

from aigate.cli import main
from aigate.config import Config
from aigate.models import PackageInfo, PrefilterResult, RiskLevel


def _extract_json(output: str) -> dict:
    """Extract the JSON object from CLI output (warnings may precede it)."""
    start = output.find("{")
    if start < 0:
        raise AssertionError(f"no JSON object in output: {output!r}")
    return json.loads(output[start:])


def _package(*, name: str = "demo", version: str = "1.0.0", ecosystem: str = "pypi") -> PackageInfo:
    return PackageInfo(
        name=name,
        version=version,
        ecosystem=ecosystem,
        author="Test Author",
        description="Test package",
        repository="https://github.com/example/test",
    )


def test_check_skip_ai_medium_exits_needs_review(monkeypatch):
    package = _package()

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve_package(name: str, version: str | None, ecosystem: str) -> PackageInfo:
        assert (name, version, ecosystem) == ("demo", None, "pypi")
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
            reason="needs review",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["signal"],
            needs_ai_review=True,
        )

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.cli.download_source", fake_download_source)
    monkeypatch.setattr("aigate.cli.run_prefilter", fake_run_prefilter)

    result = CliRunner().invoke(main, ["check", "demo", "--json", "--skip-ai"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["decision"] == "needs_review"
    assert payload["exit_code"] == 1


def test_check_resolve_error_exits_error_json(monkeypatch):
    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        raise ValueError("resolver exploded")

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)

    result = CliRunner().invoke(main, ["check", "demo", "--json"])

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["decision"] == "error"
    assert payload["exit_code"] == 3
    assert "resolver exploded" in payload["error"]


def test_check_cached_skip_ai_preserves_cached_decision(monkeypatch):
    package = _package()

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr(
        "aigate.cli.get_cached",
        lambda *_, **__: {
            "package": {
                "name": "demo",
                "version": "1.0.0",
                "ecosystem": "pypi",
                "author": "Test Author",
                "description": "Test package",
                "download_count": 0,
                "publish_date": "",
                "homepage": "",
                "repository": "https://github.com/example/test",
                "has_install_scripts": False,
                "dependencies": [],
                "metadata": {},
            },
            "prefilter": {
                "passed": False,
                "reason": "cached malicious",
                "risk_signals": ["signal"],
                "risk_level": "high",
                "needs_ai_review": True,
            },
            "consensus": {
                "final_verdict": "malicious",
                "confidence": 0.98,
                "model_results": [],
                "has_disagreement": False,
                "summary": "cached malicious",
                "risk_signals": ["signal"],
                "recommendation": "Block install",
            },
            "cached": True,
            "total_latency_ms": 10,
        },
    )

    result = CliRunner().invoke(main, ["check", "demo", "--json", "--skip-ai"])

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["decision"] == "malicious"
    assert payload["exit_code"] == 2
    assert payload["consensus"]["final_verdict"] == "malicious"


def test_check_download_failure_returns_needs_review_not_safe(monkeypatch):
    """US-002 / Reviewer IMP-1: bare-except on download_source must set
    source_unavailable so the policy layer (US-001) blocks SAFE leakage.
    Reviewer found httpx.ConnectError, asyncio.TimeoutError, ExtractionError
    etc. all silently producing SAFE before this fix."""
    package = _package()

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())
    # Skip persistent cache so prior runs don't shadow the download branch.
    monkeypatch.setattr("aigate.cli.get_cached", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.cli.set_cached", lambda *a, **kw: None)

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    async def fake_download_source(_: PackageInfo, **kw: object) -> dict[str, str]:
        # Simulate the kind of error a bare-except would swallow:
        # ConnectError / Timeout / ExtractionError / TarError all hit this branch.
        raise RuntimeError("simulated httpx.ConnectError: tcp connection refused")

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.cli.download_source", fake_download_source)

    result = CliRunner().invoke(main, ["check", "demo", "--json", "--skip-ai"])

    payload = _extract_json(result.output)
    # Must be NEEDS_REVIEW (exit 1), not SAFE (exit 0)
    assert result.exit_code == 1, (
        f"download failure leaked to exit {result.exit_code}; payload: {payload}"
    )
    assert payload["decision"] == "needs_review"
    assert payload["exit_code"] == 1
    assert payload["prefilter"]["source_unavailable"] is True
    assert any(
        "source_unavailable" in str(s) and "download_failed" in str(s)
        for s in payload["prefilter"]["risk_signals"]
    )


def test_check_value_error_non_oversized_returns_needs_review_not_safe(monkeypatch):
    """US-002: a generic ValueError (not archive_oversized) on download must
    also degrade to NEEDS_REVIEW, not silent SAFE. E.g. a corrupt tarball
    raising ValueError from inside _extract_archive."""
    package = _package()

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())
    monkeypatch.setattr("aigate.cli.get_cached", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.cli.set_cached", lambda *a, **kw: None)

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    async def fake_download_source(_: PackageInfo, **kw: object) -> dict[str, str]:
        raise ValueError("malformed tarball: unexpected EOF in middle of stream")

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.cli.download_source", fake_download_source)

    result = CliRunner().invoke(main, ["check", "demo", "--json", "--skip-ai"])

    payload = _extract_json(result.output)
    assert result.exit_code == 1, f"non-oversized ValueError leaked exit {result.exit_code}"
    assert payload["decision"] == "needs_review"
    assert payload["prefilter"]["source_unavailable"] is True


def test_check_accepts_pub_ecosystem(monkeypatch):
    package = _package(name="http", version="1.2.1", ecosystem="pub")
    seen: dict[str, str] = {}

    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve_package(name: str, version: str | None, ecosystem: str) -> PackageInfo:
        seen["ecosystem"] = ecosystem
        assert (name, version) == ("http", None)
        return package

    async def fake_download_source(_: PackageInfo, **kw: object) -> dict[str, str]:
        return {"lib/http.dart": "void main() {}"}

    def fake_run_prefilter(
        _: PackageInfo,
        __: Config,
        ___: dict[str, str] | None = None,
    ) -> PrefilterResult:
        return PrefilterResult(
            passed=True,
            reason="clean",
            risk_level=RiskLevel.NONE,
        )

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.cli.download_source", fake_download_source)
    monkeypatch.setattr("aigate.cli.run_prefilter", fake_run_prefilter)

    result = CliRunner().invoke(
        main, ["check", "http", "--ecosystem", "pub", "--json", "--skip-ai"]
    )

    assert result.exit_code == 0
    assert seen["ecosystem"] == "pub"
