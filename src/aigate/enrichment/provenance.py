"""Best-effort provenance normalization for npm and PyPI packages."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import httpx

from ..models import PackageInfo

logger = logging.getLogger(__name__)

NPM_REGISTRY_URL = "https://registry.npmjs.org"


async def fetch_provenance(
    package: PackageInfo,
    deps_dev_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    deps_dev_metadata = deps_dev_metadata or {}
    provenance = {
        "source": package.ecosystem,
        "available": False,
        "verified": None,
        "status": "missing",
        "details": "No provenance metadata found.",
        "source_repository": deps_dev_metadata.get("repository_url", package.repository),
        "source_commit": "",
        "build_url": "",
        "attestation_count": int(deps_dev_metadata.get("attestation_count", 0) or 0),
        "slsa_provenance_count": int(deps_dev_metadata.get("slsa_provenance_count", 0) or 0),
    }

    if provenance["attestation_count"] or provenance["slsa_provenance_count"]:
        provenance["available"] = True
        provenance["status"] = "available"
        provenance["details"] = (
            f"Registry metadata reported {provenance['attestation_count']} attestations and "
            f"{provenance['slsa_provenance_count']} SLSA provenance record(s)."
        )

    if package.ecosystem == "npm":
        npm_metadata = await _fetch_npm_version_metadata(package)
        dist = npm_metadata.get("dist", {})
        signatures = dist.get("signatures") or []
        attestations = dist.get("attestations") or []
        provenance_url = dist.get("provenance")

        if signatures or attestations or provenance_url:
            provenance["available"] = True
            provenance["status"] = "available"
            provenance["details"] = "npm registry exposes provenance/signature metadata."
            provenance["attestation_count"] = max(
                provenance["attestation_count"], len(attestations)
            )
            if isinstance(provenance_url, str) and provenance_url:
                provenance["build_url"] = provenance_url

    return provenance


async def _fetch_npm_version_metadata(package: PackageInfo) -> dict[str, Any]:
    if not package.version:
        return {}

    encoded_name = quote(package.name, safe="@")
    encoded_version = quote(package.version, safe="")
    url = f"{NPM_REGISTRY_URL}/{encoded_name}/{encoded_version}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("npm provenance lookup failed for %s: %s", package.name, e)
            return {}
