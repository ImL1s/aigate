"""Tests for enrichment modules (context7, deps_dev, provenance, scorecard, threat_intel, web)."""

from __future__ import annotations

import httpx

from aigate.enrichment import (
    Context7Config,
    DepsDevConfig,
    ScorecardConfig,
    WebSearchConfig,
)
from aigate.enrichment.context7 import fetch_context7_docs
from aigate.enrichment.deps_dev import fetch_deps_dev_metadata
from aigate.enrichment.provenance import fetch_provenance
from aigate.enrichment.scorecard import fetch_scorecard
from aigate.enrichment.threat_intel import query_osv_vulns
from aigate.enrichment.web_search import search_security_intel
from aigate.models import PackageInfo

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PKG = PackageInfo(name="requests", version="2.31.0", ecosystem="pypi")
_NPM_PKG = PackageInfo(name="express", version="4.18.2", ecosystem="npm")


def _make_response(status_code: int = 200, json_data=None):
    """Build a fake httpx.Response."""
    resp = httpx.Response(
        status_code=status_code,
        json=json_data,
        request=httpx.Request("GET", "https://fake"),
    )
    return resp


# ===== context7.py =====


async def test_fetch_context7_success(monkeypatch):
    """Mock httpx, return docs, verify result has expected keys."""
    monkeypatch.setenv("CONTEXT7_API_KEY", "test-key")
    monkeypatch.setattr("aigate.enrichment.context7._read_cache", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.enrichment.context7._write_cache", lambda *a, **kw: None)

    search_resp = _make_response(200, [{"id": "/pallets/flask", "trustScore": 0.9}])
    docs_resp = _make_response(200, [{"content": "Flask is a micro web framework for Python."}])

    call_count = 0

    async def fake_get(self, url, **kwargs):
        nonlocal call_count
        call_count += 1
        if "search" in url:
            return search_resp
        return docs_resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await fetch_context7_docs(_PKG, Context7Config(enabled=True))
    assert result["library_description"]
    assert isinstance(result["doc_snippets"], list)
    assert call_count == 2


async def test_fetch_context7_api_error(monkeypatch):
    """Mock 500 server error, verify graceful failure."""
    monkeypatch.setenv("CONTEXT7_API_KEY", "test-key")
    monkeypatch.setattr("aigate.enrichment.context7._read_cache", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.enrichment.context7._write_cache", lambda *a, **kw: None)

    error_resp = _make_response(500, {"error": "server error"})

    async def fake_get(self, url, **kwargs):
        return error_resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await fetch_context7_docs(_PKG, Context7Config(enabled=True))
    assert result["library_description"] == ""
    assert result["expected_capabilities"] == []
    assert result["doc_snippets"] == []


async def test_fetch_context7_timeout(monkeypatch):
    """Mock timeout, verify graceful failure."""
    monkeypatch.setenv("CONTEXT7_API_KEY", "test-key")
    monkeypatch.setattr("aigate.enrichment.context7._read_cache", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.enrichment.context7._write_cache", lambda *a, **kw: None)

    async def fake_get(self, url, **kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await fetch_context7_docs(_PKG, Context7Config(enabled=True))
    assert result["library_description"] == ""
    assert result["doc_snippets"] == []


# ===== deps_dev.py =====


async def test_fetch_deps_dev_success(monkeypatch):
    """Mock response, verify fields extracted."""
    monkeypatch.setattr("aigate.enrichment.deps_dev._read_cache", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.enrichment.deps_dev._write_cache", lambda *a, **kw: None)

    api_data = {
        "links": [{"label": "SOURCE_REPO", "url": "https://github.com/psf/requests"}],
        "advisoryKeys": [{"id": "GHSA-1234"}],
        "attestations": [{"sig": "..."}],
        "slsaProvenances": [],
        "publishedAt": "2023-06-01",
        "licenses": ["Apache-2.0"],
        "projectStatus": {"status": "active"},
    }
    resp = _make_response(200, api_data)

    async def fake_get(self, url, **kwargs):
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await fetch_deps_dev_metadata(_PKG, DepsDevConfig(enabled=True))
    assert result["repository_url"] == "https://github.com/psf/requests"
    assert "GHSA-1234" in result["advisory_ids"]
    assert result["provenance"]["available"] is True


async def test_fetch_deps_dev_not_found(monkeypatch):
    """Mock 404, verify empty result."""
    monkeypatch.setattr("aigate.enrichment.deps_dev._read_cache", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.enrichment.deps_dev._write_cache", lambda *a, **kw: None)

    resp = _make_response(404, {"error": "not found"})

    async def fake_get(self, url, **kwargs):
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await fetch_deps_dev_metadata(_PKG, DepsDevConfig(enabled=True))
    assert result == {}


# ===== provenance.py =====


async def test_fetch_provenance_npm_with_attestation(monkeypatch):
    """Mock npm registry, verify available=True when attestation present."""
    npm_data = {
        "dist": {
            "signatures": [{"sig": "abc"}],
            "attestations": [],
            "provenance": "https://build.example.com/123",
        }
    }
    resp = _make_response(200, npm_data)

    async def fake_get(self, url, **kwargs):
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await fetch_provenance(_NPM_PKG)
    assert result["available"] is True
    assert result["status"] == "available"
    assert result["build_url"] == "https://build.example.com/123"


async def test_fetch_provenance_npm_no_attestation(monkeypatch):
    """Mock npm registry with empty dist, verify available=False."""
    npm_data = {"dist": {}}
    resp = _make_response(200, npm_data)

    async def fake_get(self, url, **kwargs):
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await fetch_provenance(_NPM_PKG)
    assert result["available"] is False
    assert result["status"] == "missing"


async def test_fetch_provenance_pypi():
    """Verify deps_dev metadata is used for PyPI packages (no npm call)."""
    deps_dev_meta = {
        "repository_url": "https://github.com/psf/requests",
        "attestation_count": 2,
        "slsa_provenance_count": 1,
    }
    result = await fetch_provenance(_PKG, deps_dev_metadata=deps_dev_meta)
    assert result["available"] is True
    assert result["attestation_count"] == 2
    assert result["slsa_provenance_count"] == 1
    assert result["source_repository"] == "https://github.com/psf/requests"


# ===== scorecard.py =====


async def test_fetch_scorecard_success(monkeypatch):
    """Mock API, verify score + checks extracted."""
    api_data = {
        "date": "2024-01-15",
        "score": 7.5,
        "checks": [
            {"name": "Code-Review", "score": 8, "reason": "good"},
            {"name": "Vulnerabilities", "score": 2, "reason": "issues found"},
        ],
    }
    resp = _make_response(200, api_data)

    async def fake_get(self, url, **kwargs):
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await fetch_scorecard(
        "https://github.com/psf/requests",
        ScorecardConfig(enabled=True),
    )
    assert result["score"] == 7.5
    assert len(result["checks"]) == 2
    assert "Vulnerabilities" in result["critical_findings"]


async def test_fetch_scorecard_no_repo():
    """Verify graceful empty result for non-GitHub URL."""
    result = await fetch_scorecard(
        "https://gitlab.com/some/repo",
        ScorecardConfig(enabled=True),
    )
    assert result == {}


# ===== threat_intel.py =====


async def test_threat_intel_success(monkeypatch):
    """Mock OSV API, verify results parsed."""
    monkeypatch.setattr("aigate.enrichment.threat_intel._read_cache", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.enrichment.threat_intel._write_cache", lambda *a, **kw: None)

    osv_data = {
        "vulns": [
            {
                "id": "PYSEC-2023-001",
                "summary": "Critical vulnerability in requests",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "ranges": [
                            {"events": [{"introduced": "0"}, {"fixed": "2.32.0"}]},
                        ]
                    }
                ],
            },
        ]
    }
    resp = _make_response(200, osv_data)

    async def fake_post(self, url, **kwargs):
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    result = await query_osv_vulns(_PKG)
    assert len(result["known_vulnerabilities"]) == 1
    vuln = result["known_vulnerabilities"][0]
    assert vuln["id"] == "PYSEC-2023-001"
    assert vuln["severity"] == "HIGH"
    assert vuln["fixed_version"] == "2.32.0"


async def test_threat_intel_error(monkeypatch):
    """Mock failure, verify empty result."""
    monkeypatch.setattr("aigate.enrichment.threat_intel._read_cache", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.enrichment.threat_intel._write_cache", lambda *a, **kw: None)

    async def fake_post(self, url, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    result = await query_osv_vulns(_PKG)
    assert result["known_vulnerabilities"] == []


# ===== web_search.py =====


async def test_web_search_success(monkeypatch):
    """Mock Bright Data SERP API, verify results."""
    monkeypatch.setenv("BRIGHT_DATA_API_KEY", "test-key")
    monkeypatch.setattr("aigate.enrichment.web_search._read_cache", lambda *a, **kw: None)
    monkeypatch.setattr("aigate.enrichment.web_search._write_cache", lambda *a, **kw: None)

    serp_data = {
        "organic": [
            {
                "title": "requests malicious supply chain attack",
                "link": "https://example.com/alert",
                "description": "A malicious version of requests was found...",
            },
        ]
    }
    resp = _make_response(200, serp_data)

    async def fake_post(self, url, **kwargs):
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    result = await search_security_intel(
        _PKG,
        WebSearchConfig(enabled=True, provider="brightdata", zone="test_zone"),
    )
    assert len(result["security_mentions"]) >= 1
    assert result["security_mentions"][0]["source"] == "google"


async def test_web_search_disabled():
    """Verify skip when provider is 'none'."""
    result = await search_security_intel(
        _PKG,
        WebSearchConfig(enabled=True, provider="none"),
    )
    assert result["security_mentions"] == []
    assert result["author_info"] == ""
