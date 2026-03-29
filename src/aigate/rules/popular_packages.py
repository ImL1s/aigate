"""Auto-updating popular package lists from PyPI/npm APIs with local caching."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

CACHE_FILE = Path.home() / ".aigate" / "cache" / "popular_packages.json"
CACHE_TTL_DAYS = 7

# PyPI top-packages dataset (free, no auth)
_PYPI_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

# npm registry search (public, no auth)
_NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"


async def get_popular_packages(ecosystem: str) -> set[str]:
    """Get popular package names, from cache or API.

    Falls back to hardcoded lists when the API is unreachable.
    """
    cached = _read_cache(ecosystem)
    if cached is not None:
        return cached

    try:
        if ecosystem == "pypi":
            packages = await _fetch_pypi_top()
        elif ecosystem == "npm":
            packages = await _fetch_npm_top()
        else:
            return _get_builtin_fallback(ecosystem)
    except Exception:
        logger.warning(
            "Failed to fetch popular %s packages, using fallback", ecosystem, exc_info=True
        )
        return _get_builtin_fallback(ecosystem)

    _write_cache(ecosystem, packages)
    return packages


async def _fetch_pypi_top(count: int = 1000) -> set[str]:
    """Fetch top PyPI packages from hugovk's dataset."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(_PYPI_TOP_URL)
        resp.raise_for_status()
        data = resp.json()
        return {row["project"] for row in data["rows"][:count]}


async def _fetch_npm_top(count: int = 1000) -> set[str]:
    """Fetch top npm packages from the registry search API.

    npm search returns max 250 per request, so we paginate.
    """
    packages: set[str] = set()
    async with httpx.AsyncClient(timeout=30) as client:
        offset = 0
        page_size = 250
        while len(packages) < count:
            resp = await client.get(
                _NPM_SEARCH_URL,
                params={"text": "boost-exact:true", "size": page_size, "from": offset},
            )
            resp.raise_for_status()
            data = resp.json()
            objects = data.get("objects", [])
            if not objects:
                break
            for obj in objects:
                packages.add(obj["package"]["name"])
            offset += page_size
            if len(objects) < page_size:
                break
    return packages


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _read_cache(ecosystem: str) -> set[str] | None:
    """Read cached package list. Returns None if missing or stale."""
    if not CACHE_FILE.exists():
        return None
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        entry = data.get(ecosystem)
        if entry is None:
            return None
        updated_at = entry.get("updated_at", 0)
        age_days = (time.time() - updated_at) / 86400
        if age_days > CACHE_TTL_DAYS:
            return None
        return set(entry.get("packages", []))
    except (json.JSONDecodeError, KeyError, TypeError):
        logger.warning("Corrupt cache file %s, ignoring", CACHE_FILE)
        return None


def _write_cache(ecosystem: str, packages: set[str]) -> None:
    """Write package list to cache file, preserving other ecosystems."""
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Load existing cache to preserve other ecosystems
    data: dict = {}
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, TypeError):
            data = {}

    data[ecosystem] = {
        "packages": sorted(packages),
        "updated_at": time.time(),
    }
    CACHE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Builtin fallback lists (imported from prefilter.py hardcoded sets)
# ---------------------------------------------------------------------------


def _get_builtin_fallback(ecosystem: str) -> set[str]:
    """Return hardcoded popular package names as a fallback."""
    from aigate.prefilter import (
        POPULAR_CARGO,
        POPULAR_COMPOSER,
        POPULAR_GEM,
        POPULAR_GO,
        POPULAR_NPM,
        POPULAR_NUGET,
        POPULAR_PYPI,
    )

    fallbacks: dict[str, set[str]] = {
        "pypi": POPULAR_PYPI,
        "npm": POPULAR_NPM,
        "cargo": POPULAR_CARGO,
        "gem": POPULAR_GEM,
        "composer": POPULAR_COMPOSER,
        "go": POPULAR_GO,
        "nuget": POPULAR_NUGET,
    }
    return fallbacks.get(ecosystem, set())
