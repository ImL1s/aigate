"""Tests for enrichment models, prompts, and reporting."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import pytest
from rich.console import Console

from aigate.backends.base import AIBackend
from aigate.enrichment import (
    DepsDevConfig,
    EnrichmentConfig,
    OsvConfig,
    ProvenanceConfig,
    ScorecardConfig,
    run_enrichment,
)
from aigate.models import (
    AnalysisLevel,
    AnalysisReport,
    EnrichmentResult,
    KnownVulnerability,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
    SecurityMention,
)
from aigate.reporters.json_reporter import JsonReporter
from aigate.reporters.terminal import TerminalReporter


class CaptureBackend(AIBackend):
    name = "capture"

    def __init__(self):
        self.prompt = ""

    async def analyze(self, prompt: str, level: AnalysisLevel = AnalysisLevel.L1_QUICK) -> str:
        self.prompt = prompt
        return json.dumps(
            {
                "verdict": "safe",
                "confidence": 0.95,
                "reasoning": "No issues found",
                "risk_signals": [],
            }
        )


def _report_with_enrichment() -> AnalysisReport:
    return AnalysisReport(
        package=PackageInfo(name="demo", version="1.0.0", ecosystem="pypi"),
        prefilter=PrefilterResult(
            passed=False,
            reason="needs enrichment",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["signal"],
            needs_ai_review=True,
        ),
        enrichment=EnrichmentResult(
            library_description="A HTTP client for Python.",
            expected_capabilities=["HTTP requests"],
            security_mentions=[
                SecurityMention(
                    title="Maintainer account compromise rumor",
                    url="https://example.com/security-post",
                    snippet="community report",
                    source="web_search",
                    relevance=0.9,
                )
            ],
            known_vulnerabilities=[
                KnownVulnerability(
                    id="GHSA-1234",
                    summary="Credential leak in older versions",
                    severity="HIGH",
                    fixed_version="1.2.0",
                )
            ],
            sources_queried=["osv", "web_search"],
        ),
    )


@pytest.mark.asyncio
async def test_backend_prompt_includes_external_intelligence():
    backend = CaptureBackend()
    enrichment = EnrichmentResult(
        library_description="A HTTP client for Python.",
        known_vulnerabilities=[
            KnownVulnerability(
                id="GHSA-1234",
                summary="Credential leak in older versions",
                severity="HIGH",
                fixed_version="1.2.0",
            )
        ],
    )

    await backend.analyze_package(
        name="demo",
        version="1.0.0",
        ecosystem="pypi",
        author="Test Author",
        description="Test package",
        has_install_scripts=False,
        risk_signals=["signal"],
        source_code="print('hi')",
        external_intelligence=enrichment.to_prompt_section(),
    )

    assert "External Intelligence" in backend.prompt
    assert "GHSA-1234" in backend.prompt


def test_json_reporter_serializes_enrichment():
    output = io.StringIO()
    report = _report_with_enrichment()

    with redirect_stdout(output):
        JsonReporter().print_report(report)

    payload = json.loads(output.getvalue())
    assert payload["enrichment"]["known_vulnerabilities"][0]["id"] == "GHSA-1234"
    assert (
        payload["enrichment"]["security_mentions"][0]["title"]
        == "Maintainer account compromise rumor"
    )


def test_terminal_reporter_prints_enrichment_summary():
    console = Console(record=True, width=120)
    report = _report_with_enrichment()

    TerminalReporter(console).print_report(report)
    output = console.export_text()

    assert "External intelligence" in output
    assert "GHSA-1234" in output


@pytest.mark.asyncio
async def test_run_enrichment_includes_trust_providers(monkeypatch):
    package = PackageInfo(name="demo", version="1.0.0", ecosystem="pypi")

    async def fake_query_osv_vulns(_: PackageInfo) -> dict:
        return {
            "known_vulnerabilities": [
                {
                    "id": "GHSA-1234",
                    "summary": "Credential leak in older versions",
                    "severity": "HIGH",
                    "fixed_version": "1.2.0",
                }
            ]
        }

    async def fake_fetch_deps_dev_metadata(_: PackageInfo, __: DepsDevConfig) -> dict:
        return {
            "repository_url": "https://github.com/example/demo",
            "project_status": "active",
            "advisory_ids": ["GHSA-1234"],
            "slsa_provenance_count": 1,
            "attestation_count": 1,
        }

    async def fake_fetch_scorecard(_: str, __: ScorecardConfig) -> dict:
        return {
            "repository_url": "https://github.com/example/demo",
            "score": 8.7,
            "date": "2026-03-28",
            "critical_findings": [],
        }

    async def fake_fetch_provenance(_: PackageInfo, deps_dev_metadata: dict | None = None) -> dict:
        assert deps_dev_metadata is not None
        return {
            "source": "pypi",
            "available": True,
            "verified": True,
            "status": "available",
            "details": "attestation published",
        }

    monkeypatch.setattr("aigate.enrichment.threat_intel.query_osv_vulns", fake_query_osv_vulns)
    monkeypatch.setattr(
        "aigate.enrichment.deps_dev.fetch_deps_dev_metadata",
        fake_fetch_deps_dev_metadata,
    )
    monkeypatch.setattr(
        "aigate.enrichment.scorecard.fetch_scorecard",
        fake_fetch_scorecard,
    )
    monkeypatch.setattr(
        "aigate.enrichment.provenance.fetch_provenance",
        fake_fetch_provenance,
    )

    result = await run_enrichment(
        package,
        EnrichmentConfig(
            enabled=True,
            osv=OsvConfig(enabled=True),
            deps_dev=DepsDevConfig(enabled=True),
            scorecard=ScorecardConfig(enabled=True),
            provenance=ProvenanceConfig(enabled=True),
        ),
    )

    assert result.repository_url == "https://github.com/example/demo"
    assert result.scorecard is not None
    assert result.scorecard.score == 8.7
    assert result.provenance is not None
    assert result.provenance.status == "available"
    assert result.known_vulnerabilities[0].id == "GHSA-1234"


class TestEnrichmentResult:
    def test_to_prompt_section_empty(self):
        """No sources queried → empty string."""
        r = EnrichmentResult()
        section = r.to_prompt_section()
        assert section == ""

    def test_to_prompt_section_with_docs(self):
        r = EnrichmentResult(
            library_description="HTTP library for Python",
            expected_capabilities=["http requests", "session management"],
            sources_queried=["context7"],
        )
        section = r.to_prompt_section()
        assert "HTTP library" in section
        assert "http requests" in section

    def test_to_prompt_section_with_threat(self):
        r = EnrichmentResult(
            known_vulnerabilities=[
                KnownVulnerability(
                    id="CVE-2024-1234",
                    summary="RCE in setup.py",
                    severity="CRITICAL",
                ),
            ],
            sources_queried=["osv"],
        )
        section = r.to_prompt_section()
        assert "CVE-2024-1234" in section
        assert "CRITICAL" in section

    def test_to_prompt_section_with_search(self):
        r = EnrichmentResult(
            security_mentions=[
                SecurityMention(
                    title="Users report malicious behavior",
                    url="https://reddit.com/r/test",
                    snippet="malicious code found in v2.0",
                    source="reddit",
                ),
            ],
            sources_queried=["web_search"],
        )
        section = r.to_prompt_section()
        assert "malicious" in section
        assert "reddit" in section

    def test_to_prompt_section_no_vulns_found(self):
        """When OSV was queried but found nothing, should say so."""
        r = EnrichmentResult(sources_queried=["osv"])
        section = r.to_prompt_section()
        assert "No known vulnerabilities" in section

    def test_to_prompt_section_no_search_hits(self):
        """When web search was queried but found nothing, should say so."""
        r = EnrichmentResult(sources_queried=["web_search"])
        section = r.to_prompt_section()
        assert "No recent security reports" in section

    def test_doc_snippets_limited(self):
        """Should only include first 3 doc snippets."""
        r = EnrichmentResult(
            doc_snippets=["a", "b", "c", "d", "e"],
            library_description="test lib",
            sources_queried=["context7"],
        )
        section = r.to_prompt_section()
        assert "- d" not in section
        assert "- e" not in section

    def test_author_info_included(self):
        r = EnrichmentResult(
            author_info="Maintained by Test Corp since 2020",
            sources_queried=["web_search"],
        )
        section = r.to_prompt_section()
        assert "Test Corp" in section
