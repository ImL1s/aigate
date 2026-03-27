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

from ..models import PackageInfo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SecurityMention:
    """A security-related mention found via web search."""

    title: str
    url: str
    snippet: str
    source: str = ""  # "google", "bing", "reddit", etc.
    relevance: float = 0.0


@dataclass
class KnownVuln:
    """A known vulnerability from OSV.dev or similar databases."""

    id: str  # "GHSA-xxx" or "CVE-xxx"
    summary: str
    severity: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL
    fixed_version: str = ""


@dataclass
class EnrichmentResult:
    """Aggregated intelligence from all enrichment sources."""

    # Context7 — official documentation context
    library_description: str = ""
    expected_capabilities: list[str] = field(default_factory=list)
    doc_snippets: list[str] = field(default_factory=list)

    # Web search — security intelligence
    security_mentions: list[SecurityMention] = field(default_factory=list)
    author_info: str = ""

    # OSV — known vulnerabilities
    known_vulnerabilities: list[KnownVuln] = field(default_factory=list)

    # Meta
    sources_queried: list[str] = field(default_factory=list)
    cache_hit: bool = False
    enrichment_latency_ms: int = 0
    errors: list[str] = field(default_factory=list)

    def to_prompt_section(self) -> str:
        """Format enrichment data as a prompt section for AI analysis."""
        if not self.sources_queried:
            return ""

        sections: list[str] = []
        sections.append("## External Intelligence (enrichment)")

        # Context7 docs
        if self.library_description or self.doc_snippets:
            sections.append("\n### Official Documentation Context (via Context7)")
            if self.library_description:
                sections.append(f'This package is described as: "{self.library_description}"')
            if self.expected_capabilities:
                sections.append("Expected capabilities: " + ", ".join(self.expected_capabilities))
            for snippet in self.doc_snippets[:3]:  # Limit to 3 snippets
                sections.append(f"- {snippet[:500]}")

        # Web search security intel
        if self.security_mentions:
            sections.append("\n### Security Intelligence (web search) [unverified]")
            for mention in self.security_mentions[:5]:  # Top 5
                sections.append(f'- [{mention.source}] "{mention.title}"')
                if mention.snippet:
                    sections.append(f"  {mention.snippet[:200]}")
        elif "web_search" in self.sources_queried:
            sections.append("\n### Security Intelligence (web search)")
            sections.append("- No recent security reports found for this package.")

        # Known vulns
        if self.known_vulnerabilities:
            sections.append("\n### Known Vulnerabilities (OSV.dev)")
            for vuln in self.known_vulnerabilities:
                line = f'- {vuln.id}: "{vuln.summary}" (severity: {vuln.severity})'
                if vuln.fixed_version:
                    line += f" — fixed in {vuln.fixed_version}"
                sections.append(line)
        elif "osv" in self.sources_queried:
            sections.append("\n### Known Vulnerabilities (OSV.dev)")
            sections.append("- No known vulnerabilities for this version.")

        if self.author_info:
            sections.append(f"\n### Author Info\n{self.author_info[:300]}")

        return "\n".join(sections)


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
class EnrichmentConfig:
    enabled: bool = False
    context7: Context7Config = field(default_factory=Context7Config)
    web_search: WebSearchConfig = field(default_factory=WebSearchConfig)
    osv: OsvConfig = field(default_factory=OsvConfig)
    timeout_seconds: int = 10
    cache_ttl_hours: dict[str, int] = field(
        default_factory=lambda: {
            "context7": 168,  # 7 days
            "web_search": 24,  # 1 day
            "osv": 6,  # 6 hours
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

    if not tasks:
        return EnrichmentResult()

    sources = [name for name, _ in tasks]
    coros = [coro for _, coro in tasks]

    try:
        raw_results = await asyncio.wait_for(
            asyncio.gather(*coros, return_exceptions=True),
            timeout=config.timeout_seconds,
        )
    except TimeoutError:
        logger.warning("Enrichment timed out after %ds", config.timeout_seconds)
        raw_results = [TimeoutError("enrichment timeout")] * len(coros)

    return _merge_results(
        sources=sources,
        raw_results=list(raw_results),
        latency_ms=int((time.monotonic() - start) * 1000),
    )


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
                result.known_vulnerabilities.append(KnownVuln(**v))

    return result
