"""Tests for the pip install hook wrapper."""

from __future__ import annotations

import pytest

from aigate.config import Config
from aigate.hooks import pip_hook
from aigate.models import EnrichmentResult, PackageInfo, PrefilterResult, RiskLevel


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
async def test_check_packages_passes_enrichment_into_consensus(monkeypatch):
    config = Config()
    config.enrichment.enabled = True
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
