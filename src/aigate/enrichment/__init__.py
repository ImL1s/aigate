"""Enrichment module — optional intelligence gathering layer for AI analysis.

Fetches external context (documentation, security intel, known vulnerabilities)
to enhance AI prompt quality. Runs between pre-filter and AI consensus.

Usage:
    from aigate.enrichment import run_enrichment, EnrichmentResult
    result = await run_enrichment(package, config.enrichment)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import (
    EnrichmentResult,
    KnownVulnerability,
    PackageInfo,
    ProvenanceInfo,
    ScorecardCheck,
    ScorecardResult,
    SecurityMention,
)
from ..rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

# Module-level rate limiter for external API calls (5 calls/second)
_api_limiter = RateLimiter(max_calls=5, period_seconds=1.0)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class Context7Config:
    enabled: bool = False
    api_key_env: str = "CONTEXT7_API_KEY"


@dataclass
class WebSearchConfig:
    enabled: bool = False
    provider: str = "brightdata"  # "brightdata" | "none"
    api_key_env: str = "BRIGHT_DATA_API_KEY"
    zone: str = ""


@dataclass
class OsvConfig:
    enabled: bool = True  # Free, no API key needed


@dataclass
class DepsDevConfig:
    enabled: bool = False
    api_base_url: str = "https://api.deps.dev/v3"


@dataclass
class ScorecardConfig:
    enabled: bool = False
    api_base_url: str = "https://api.securityscorecards.dev"


@dataclass
class ProvenanceConfig:
    enabled: bool = False


@dataclass
class EnrichmentConfig:
    enabled: bool = False
    context7: Context7Config = field(default_factory=Context7Config)
    web_search: WebSearchConfig = field(default_factory=WebSearchConfig)
    osv: OsvConfig = field(default_factory=OsvConfig)
    deps_dev: DepsDevConfig = field(default_factory=DepsDevConfig)
    scorecard: ScorecardConfig = field(default_factory=ScorecardConfig)
    provenance: ProvenanceConfig = field(default_factory=ProvenanceConfig)
    timeout_seconds: int = 10
    cache_ttl_hours: dict[str, int] = field(
        default_factory=lambda: {
            "context7": 168,  # 7 days
            "web_search": 24,  # 1 day
            "osv": 6,  # 6 hours
            "deps_dev": 24,
            "scorecard": 24,
            "provenance": 24,
        }
    )


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _cache_key(package: PackageInfo, source: str) -> str:
    raw = f"{package.ecosystem}:{package.name}:{package.version}:{source}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _cache_dir() -> Path:
    d = Path.home() / ".aigate" / "cache" / "enrichment"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read_cache(package: PackageInfo, source: str, ttl_hours: int) -> dict[str, Any] | None:
    """Read from file cache. Returns None on miss or expiry."""
    path = _cache_dir() / f"{_cache_key(package, source)}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > ttl_hours * 3600:
            return None
        return data
    except (json.JSONDecodeError, KeyError):
        return None


def _write_cache(package: PackageInfo, source: str, data: dict[str, Any]) -> None:
    """Write to file cache."""
    data["_cached_at"] = time.time()
    path = _cache_dir() / f"{_cache_key(package, source)}.json"
    try:
        path.write_text(json.dumps(data, ensure_ascii=False))
    except OSError as e:
        logger.warning("Failed to write enrichment cache: %s", e)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_enrichment(
    package: PackageInfo,
    config: EnrichmentConfig,
) -> EnrichmentResult:
    """Run all enabled enrichment sources in parallel.

    Returns partial results on timeout or individual source failures.
    """
    if not config.enabled:
        return EnrichmentResult()

    from .context7 import fetch_context7_docs
    from .deps_dev import fetch_deps_dev_metadata
    from .provenance import fetch_provenance
    from .scorecard import fetch_scorecard
    from .threat_intel import query_osv_vulns
    from .web_search import search_security_intel

    start = time.monotonic()
    tasks: list[tuple[str, Any]] = []

    if config.context7.enabled:
        tasks.append(("context7", fetch_context7_docs(package, config.context7)))
    if config.web_search.enabled:
        tasks.append(("web_search", search_security_intel(package, config.web_search)))
    if config.osv.enabled:
        tasks.append(("osv", query_osv_vulns(package)))
    if config.deps_dev.enabled:
        tasks.append(("deps_dev", fetch_deps_dev_metadata(package, config.deps_dev)))

    if not tasks and not config.scorecard.enabled and not config.provenance.enabled:
        return EnrichmentResult()

    sources = [name for name, _ in tasks]
    coros = [coro for _, coro in tasks]

    async def _limited_call(coro: Any) -> Any:
        """Wrap a coroutine with the module-level rate limiter."""
        async with _api_limiter:
            return await coro

    try:
        raw_results = await asyncio.wait_for(
            asyncio.gather(*[_limited_call(c) for c in coros], return_exceptions=True),
            timeout=config.timeout_seconds,
        )
    except TimeoutError:
        logger.warning("Enrichment timed out after %ds", config.timeout_seconds)
        raw_results = [TimeoutError("enrichment timeout")] * len(coros)

    result = _merge_results(
        sources=sources,
        raw_results=list(raw_results),
        latency_ms=int((time.monotonic() - start) * 1000),
    )

    if config.scorecard.enabled:
        repo_url = result.repository_url or package.repository
        result.sources_queried.append("scorecard")
        if repo_url:
            try:
                scorecard_raw = await fetch_scorecard(repo_url, config.scorecard)
                result.scorecard = _build_scorecard_result(scorecard_raw)
            except Exception as e:
                result.errors.append(f"scorecard: {e}")
                logger.warning("Enrichment source scorecard failed: %s", e)

    if config.provenance.enabled:
        result.sources_queried.append("provenance")
        try:
            provenance_raw = await fetch_provenance(
                package,
                deps_dev_metadata={
                    "repository_url": result.repository_url,
                    "attestation_count": (
                        result.provenance.attestation_count if result.provenance else 0
                    ),
                    "slsa_provenance_count": (
                        result.provenance.slsa_provenance_count if result.provenance else 0
                    ),
                },
            )
            result.provenance = ProvenanceInfo(**provenance_raw)
        except Exception as e:
            result.errors.append(f"provenance: {e}")
            logger.warning("Enrichment source provenance failed: %s", e)

    result.enrichment_latency_ms = int((time.monotonic() - start) * 1000)
    return result


def _merge_results(
    sources: list[str],
    raw_results: list[Any],
    latency_ms: int,
) -> EnrichmentResult:
    """Merge results from all enrichment sources into a single EnrichmentResult."""
    result = EnrichmentResult(
        sources_queried=sources,
        enrichment_latency_ms=latency_ms,
    )

    for source, raw in zip(sources, raw_results):
        if isinstance(raw, BaseException):
            result.errors.append(f"{source}: {raw}")
            logger.warning("Enrichment source %s failed: %s", source, raw)
            continue

        if not isinstance(raw, dict):
            continue

        if source == "context7":
            result.library_description = raw.get("library_description", "")
            result.expected_capabilities = raw.get("expected_capabilities", [])
            result.doc_snippets = raw.get("doc_snippets", [])
        elif source == "web_search":
            for m in raw.get("security_mentions", []):
                result.security_mentions.append(SecurityMention(**m))
            result.author_info = raw.get("author_info", "")
        elif source == "osv":
            for v in raw.get("known_vulnerabilities", []):
                result.known_vulnerabilities.append(KnownVulnerability(**v))
        elif source == "deps_dev":
            result.repository_url = raw.get("repository_url", "")
            result.project_status = raw.get("project_status", "")
            result.advisory_ids = raw.get("advisory_ids", [])
            if raw.get("provenance"):
                result.provenance = ProvenanceInfo(**raw["provenance"])

    return result


def _build_scorecard_result(raw: dict[str, Any]) -> ScorecardResult:
    checks = []
    for check in raw.get("checks", []):
        documentation = check.get("documentation", {}) or {}
        checks.append(
            ScorecardCheck(
                name=check.get("name", ""),
                score=float(check.get("score", 0)),
                reason=check.get("reason", ""),
                documentation_url=documentation.get("url", ""),
            )
        )
    return ScorecardResult(
        repository_url=raw.get("repository_url", ""),
        date=raw.get("date", ""),
        score=float(raw.get("score", 0.0)),
        critical_findings=raw.get("critical_findings", []),
        checks=checks,
    )
