"""Web search integration — search for package security intelligence.

Uses Bright Data SERP API to find security-related mentions of a package
that may not yet be in formal CVE databases (zero-day community reports,
maintainer account compromises, controversy, etc.).

Bright Data SERP API: https://docs.brightdata.com/scraping-automation/serp-api/introduction
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from ..models import PackageInfo
from . import WebSearchConfig, _read_cache, _write_cache

logger = logging.getLogger(__name__)

BRIGHTDATA_ENDPOINT = "https://api.brightdata.com/request"

# Search query templates — each package gets up to 3 queries
SEARCH_QUERIES: list[str] = [
    '"{name}" {ecosystem} malicious OR vulnerability OR "supply chain attack"',
    '"{name}" {ecosystem} deprecated OR abandoned OR "account compromised" OR hijacked',
    '"{name}" {ecosystem} author "{author}" github reputation',
]


async def search_security_intel(
    package: PackageInfo,
    config: WebSearchConfig,
) -> dict[str, Any]:
    """Search for security intelligence about a package.

    Returns a dict with keys:
        - security_mentions: list[dict] with {title, url, snippet, source, relevance}
        - author_info: str
    """
    # Check cache first
    cached = _read_cache(package, "web_search", ttl_hours=24)
    if cached and "_cached_at" in cached:
        cached.pop("_cached_at", None)
        return cached

    if config.provider == "none":
        return {"security_mentions": [], "author_info": ""}

    api_key = os.environ.get(config.api_key_env, "")
    if not api_key:
        logger.debug("Bright Data API key not set (%s), skipping", config.api_key_env)
        return {"security_mentions": [], "author_info": ""}

    result = await _search_brightdata(package, config, api_key)

    # Cache the result
    _write_cache(package, "web_search", result)
    return result


async def _search_brightdata(
    package: PackageInfo,
    config: WebSearchConfig,
    api_key: str,
) -> dict[str, Any]:
    """Execute searches via Bright Data SERP API."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    mentions: list[dict[str, Any]] = []
    author_info = ""

    async with httpx.AsyncClient(timeout=15.0) as client:
        for i, template in enumerate(SEARCH_QUERIES):
            query = template.format(
                name=package.name,
                ecosystem=package.ecosystem,
                author=package.author or "unknown",
            )

            # Skip author query if no author info
            if i == 2 and not package.author:
                continue

            try:
                results = await _execute_serp_query(client, headers, config.zone, query)
            except Exception as e:
                logger.warning("SERP query %d failed for %s: %s", i, package.name, e)
                continue

            for r in results:
                mention = {
                    "title": r.get("title", ""),
                    "url": r.get("link", ""),
                    "snippet": r.get("description", ""),
                    "source": "google",
                    "relevance": _score_relevance(r, package),
                }

                # Last query is author-related
                if i == 2:
                    author_info = _extract_author_info(results, package)
                else:
                    mentions.append(mention)

    # Sort by relevance, keep top results
    mentions.sort(key=lambda m: m["relevance"], reverse=True)
    mentions = mentions[:10]

    # Filter out low-relevance noise
    mentions = [m for m in mentions if m["relevance"] > 0.1]

    return {
        "security_mentions": mentions,
        "author_info": author_info,
    }


async def _execute_serp_query(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    zone: str,
    query: str,
) -> list[dict[str, Any]]:
    """Execute a single SERP API query and return organic results."""
    from urllib.parse import quote

    search_url = f"https://www.google.com/search?q={quote(query)}&brd_json=1"

    payload = {
        "zone": zone,
        "url": search_url,
        "format": "raw",
    }

    resp = await client.post(
        BRIGHTDATA_ENDPOINT,
        headers=headers,
        json=payload,
    )
    resp.raise_for_status()
    data = resp.json()

    # Bright Data SERP API returns organic results under "organic" key
    if isinstance(data, dict):
        return data.get("organic", [])
    if isinstance(data, list):
        return data
    return []


def _score_relevance(result: dict[str, Any], package: PackageInfo) -> float:
    """Score how relevant a search result is to security analysis.

    Returns 0.0-1.0 based on keyword matching in title and description.
    """
    text = f"{result.get('title', '')} {result.get('description', '')}".lower()
    score = 0.0

    # High-signal security keywords
    high_signal = [
        "malicious",
        "malware",
        "supply chain attack",
        "backdoor",
        "compromised",
        "hijacked",
        "trojan",
        "credential theft",
        "data exfiltration",
        "cryptominer",
    ]
    medium_signal = [
        "vulnerability",
        "cve-",
        "ghsa-",
        "security advisory",
        "deprecated",
        "abandoned",
        "unmaintained",
    ]
    low_signal = [
        "security",
        "risk",
        "warning",
        "caution",
    ]

    for kw in high_signal:
        if kw in text:
            score += 0.4

    for kw in medium_signal:
        if kw in text:
            score += 0.2

    for kw in low_signal:
        if kw in text:
            score += 0.1

    # Boost if package name appears prominently
    if package.name.lower() in result.get("title", "").lower():
        score += 0.15

    return min(score, 1.0)


def _extract_author_info(
    results: list[dict[str, Any]],
    package: PackageInfo,
) -> str:
    """Extract author reputation info from search results."""
    if not results:
        return ""

    snippets: list[str] = []
    for r in results[:3]:
        title = r.get("title", "")
        desc = r.get("description", "")
        if package.author and package.author.lower() in f"{title} {desc}".lower():
            snippets.append(f"- {title}: {desc[:150]}")

    if not snippets:
        return ""

    return f'Author "{package.author}":\n' + "\n".join(snippets)
