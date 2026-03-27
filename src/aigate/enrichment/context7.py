"""Context7 integration — fetch official library documentation.

Uses Context7 REST API (not MCP) to retrieve up-to-date documentation
for a given package, providing AI with context about what the package
*should* do vs. what the code actually does.

API docs: https://context7.mintlify.dev/docs/api-guide
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from ..models import PackageInfo
from . import Context7Config, _read_cache, _write_cache

logger = logging.getLogger(__name__)

BASE_URL = "https://context7.com/api/v2"

# Map aigate ecosystem names to Context7 search terms
ECOSYSTEM_HINTS: dict[str, str] = {
    "pypi": "python",
    "npm": "node javascript",
    "pub": "dart flutter",
}


async def fetch_context7_docs(
    package: PackageInfo,
    config: Context7Config,
) -> dict[str, Any]:
    """Fetch official documentation context for a package.

    Returns a dict with keys:
        - library_description: str
        - expected_capabilities: list[str]
        - doc_snippets: list[str]
    """
    # Check cache first
    cached = _read_cache(package, "context7", ttl_hours=168)
    if cached and "_cached_at" in cached:
        cached.pop("_cached_at", None)
        return cached

    api_key = os.environ.get(config.api_key_env, "")
    if not api_key:
        logger.debug("Context7 API key not set (%s), skipping", config.api_key_env)
        return {"library_description": "", "expected_capabilities": [], "doc_snippets": []}

    headers = {"Authorization": f"Bearer {api_key}"}

    async with httpx.AsyncClient(timeout=15.0) as client:
        # Step 1: Resolve library ID
        library_id = await _resolve_library_id(client, headers, package)
        if not library_id:
            return {"library_description": "", "expected_capabilities": [], "doc_snippets": []}

        # Step 2: Fetch documentation
        result = await _fetch_docs(client, headers, library_id, package)

    # Cache the result
    _write_cache(package, "context7", result)
    return result


async def _resolve_library_id(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    package: PackageInfo,
) -> str:
    """Resolve package name to Context7 library ID.

    Returns library ID string (e.g., "/expressjs/express") or empty string.
    """
    hint = ECOSYSTEM_HINTS.get(package.ecosystem, "")
    search_name = f"{package.name} {hint}".strip()

    try:
        resp = await client.get(
            f"{BASE_URL}/libs/search",
            headers=headers,
            params={
                "libraryName": search_name,
                "query": f"what does {package.name} do",
            },
        )
        resp.raise_for_status()
        libraries = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.warning("Context7 library search failed for %s: %s", package.name, e)
        return ""

    if not libraries or not isinstance(libraries, list):
        logger.debug("Context7: no libraries found for %s", package.name)
        return ""

    # Return the best match (first result, ranked by relevance)
    best = libraries[0]
    library_id = best.get("id", "")
    logger.debug(
        "Context7: resolved %s -> %s (trust=%s)",
        package.name,
        library_id,
        best.get("trustScore", "?"),
    )
    return library_id


async def _fetch_docs(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    library_id: str,
    package: PackageInfo,
) -> dict[str, Any]:
    """Fetch documentation snippets for a resolved library ID."""
    result: dict[str, Any] = {
        "library_description": "",
        "expected_capabilities": [],
        "doc_snippets": [],
    }

    # Query 1: General "what is this" for description + capabilities
    try:
        resp = await client.get(
            f"{BASE_URL}/context",
            headers=headers,
            params={
                "libraryId": library_id,
                "query": f"what is {package.name} and what does it do, main features",
                "type": "json",
            },
        )
        resp.raise_for_status()
        docs = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.warning("Context7 doc fetch failed for %s: %s", library_id, e)
        return result

    if not docs or not isinstance(docs, list):
        return result

    # Extract description from first doc snippet
    if docs:
        first = docs[0]
        result["library_description"] = first.get("content", "")[:500]

    # Collect all snippets
    result["doc_snippets"] = [d.get("content", "")[:500] for d in docs[:5] if d.get("content")]

    # Try to infer expected capabilities from docs
    result["expected_capabilities"] = _infer_capabilities(docs)

    return result


def _infer_capabilities(docs: list[dict[str, Any]]) -> list[str]:
    """Infer expected package capabilities from documentation snippets.

    Simple heuristic: look for common capability-indicating patterns.
    """
    capabilities: list[str] = []
    all_text = " ".join(d.get("content", "") for d in docs).lower()

    capability_keywords = {
        "http": "HTTP requests",
        "websocket": "WebSocket connections",
        "database": "database operations",
        "file system": "file system access",
        "authentication": "authentication",
        "encryption": "encryption/cryptography",
        "parsing": "data parsing",
        "cli": "command-line interface",
        "testing": "testing utilities",
        "logging": "logging",
        "caching": "caching",
        "orm": "ORM / database mapping",
        "template": "templating",
        "routing": "URL routing",
        "middleware": "middleware",
        "serialization": "data serialization",
    }

    for keyword, capability in capability_keywords.items():
        if keyword in all_text:
            capabilities.append(capability)

    return capabilities[:8]  # Cap at 8
