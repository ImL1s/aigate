"""OpenSSF Scorecard integration."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from . import ScorecardConfig

logger = logging.getLogger(__name__)


async def fetch_scorecard(repo_url: str, config: ScorecardConfig) -> dict[str, Any]:
    owner_repo = _github_owner_repo(repo_url)
    if not owner_repo:
        return {}

    url = f"{config.api_base_url}/projects/github.com/{owner_repo}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("Scorecard lookup failed for %s: %s", repo_url, e)
            return {}

    checks = data.get("checks", [])
    critical_findings = [
        check.get("name", "") for check in checks if float(check.get("score", 0) or 0) <= 3
    ]
    return {
        "repository_url": repo_url,
        "date": data.get("date", ""),
        "score": float(data.get("score", 0.0) or 0.0),
        "critical_findings": [name for name in critical_findings if name],
        "checks": checks,
    }


def _github_owner_repo(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    if parsed.netloc != "github.com":
        return ""
    path = parsed.path.strip("/").split("/")
    if len(path) < 2:
        return ""
    return f"{path[0]}/{path[1]}"
