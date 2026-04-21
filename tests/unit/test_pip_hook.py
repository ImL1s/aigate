"""Tests for the pip install hook wrapper."""

from __future__ import annotations

import pytest

from aigate.cache import _cache_key, set_cached
from aigate.config import Config
from aigate.hooks import pip_hook
from aigate.models import (
    AnalysisReport,
    ConsensusResult,
    EnrichmentResult,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
    Verdict,
)


def test_pip_wrapper_bypasses_with_no_aigate(monkeypatch):
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        pip_hook.sys,
        "argv",
        ["aigate-pip", "install", "--no-aigate", "requests"],
    )
    monkeypatch.setattr(
        pip_hook,
        "_passthrough_pip",
        lambda args: seen.update({"args": args}),
    )
    monkeypatch.setattr(
        pip_hook.asyncio,
        "run",
        lambda _: pytest.fail("pip_wrapper should bypass without invoking aigate"),
    )

    pip_hook.pip_wrapper()

    assert seen == {"args": ["install", "requests"]}


@pytest.mark.asyncio
async def test_check_packages_passes_enrichment_into_consensus(monkeypatch, tmp_path):
    config = Config()
    config.enrichment.enabled = True
    config.cache_dir = str(tmp_path)  # isolate from user's real ~/.aigate/cache
    package = PackageInfo(name="requests", version="2.31.0", ecosystem="pypi")
    seen: dict[str, object] = {}

    monkeypatch.setattr("aigate.hooks.pip_hook.Config.load", lambda: config)

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    async def fake_download_source(_: PackageInfo) -> dict[str, str]:
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

    async def fake_run_enrichment(_: PackageInfo, __: object) -> EnrichmentResult:
        return EnrichmentResult(
            library_description="HTTP client",
            sources_queried=["osv"],
        )

    async def fake_run_consensus(**kwargs: object):
        seen["external_intelligence"] = kwargs["external_intelligence"]
        from aigate.models import ConsensusResult, Verdict

        return ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.9,
            summary="safe",
        )

    monkeypatch.setattr("aigate.hooks.pip_hook.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.hooks.pip_hook.download_source", fake_download_source)
    monkeypatch.setattr("aigate.hooks.pip_hook.run_prefilter", fake_run_prefilter)
    monkeypatch.setattr("aigate.hooks.pip_hook.run_enrichment", fake_run_enrichment)
    monkeypatch.setattr("aigate.hooks.pip_hook.run_consensus", fake_run_consensus)

    blocked = await pip_hook._check_packages([("requests", None)])

    assert blocked == []
    assert "External Intelligence" in str(seen["external_intelligence"])


@pytest.mark.asyncio
async def test_pip_hook_uses_cache_on_hit(monkeypatch, tmp_path):
    """On cache hit, skip download/prefilter/consensus entirely."""
    config = Config()
    config.cache_dir = str(tmp_path)
    monkeypatch.setattr("aigate.hooks.pip_hook.Config.load", lambda: config)

    package = PackageInfo(name="requests", version="2.31.0", ecosystem="pypi")

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    monkeypatch.setattr("aigate.hooks.pip_hook.resolve_package", fake_resolve_package)

    # Seed a safe-verdict cache entry so decision_from_report yields "allow"
    safe_report = AnalysisReport(
        package=package,
        prefilter=PrefilterResult(passed=True, reason="safe", risk_level=RiskLevel.NONE),
    )
    set_cached(package.name, package.version, "pypi", safe_report, str(tmp_path))

    # Heavy-path functions must not be called on a cache hit
    async def fail_download(*_args, **_kwargs):
        pytest.fail("download_source must not be called on cache hit")

    def fail_prefilter(*_args, **_kwargs):
        pytest.fail("run_prefilter must not be called on cache hit")

    async def fail_consensus(*_args, **_kwargs):
        pytest.fail("run_consensus must not be called on cache hit")

    monkeypatch.setattr("aigate.hooks.pip_hook.download_source", fail_download)
    monkeypatch.setattr("aigate.hooks.pip_hook.run_prefilter", fail_prefilter)
    monkeypatch.setattr("aigate.hooks.pip_hook.run_consensus", fail_consensus)

    blocked = await pip_hook._check_packages([("requests", None)])

    assert blocked == []


@pytest.mark.asyncio
async def test_pip_hook_does_not_cache_error_verdict(monkeypatch, tmp_path):
    """A transient AI ERROR must not get cached — otherwise one timeout
    silently suppresses retry for the full TTL window."""
    config = Config()
    config.cache_dir = str(tmp_path)
    config.enrichment.enabled = False
    monkeypatch.setattr("aigate.hooks.pip_hook.Config.load", lambda: config)

    package = PackageInfo(name="slow-pkg", version="1.0.0", ecosystem="pypi")

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    async def fake_download_source(_: PackageInfo) -> dict[str, str]:
        return {"setup.py": "print('hi')"}

    def fake_run_prefilter(*_args, **_kwargs) -> PrefilterResult:
        return PrefilterResult(
            passed=False,
            reason="needs review",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["s"],
            needs_ai_review=True,
        )

    async def fake_run_consensus(**_kwargs: object) -> ConsensusResult:
        return ConsensusResult(
            final_verdict=Verdict.ERROR, confidence=0.0, summary="backend failed"
        )

    monkeypatch.setattr("aigate.hooks.pip_hook.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.hooks.pip_hook.download_source", fake_download_source)
    monkeypatch.setattr("aigate.hooks.pip_hook.run_prefilter", fake_run_prefilter)
    monkeypatch.setattr("aigate.hooks.pip_hook.run_consensus", fake_run_consensus)

    blocked = await pip_hook._check_packages([("slow-pkg", None)])

    assert blocked == []
    # Cache file for this pkg must not exist — transient failures are not persistent verdicts
    key = _cache_key("slow-pkg", "1.0.0", "pypi")
    assert not (tmp_path / f"{key}.json").exists()
