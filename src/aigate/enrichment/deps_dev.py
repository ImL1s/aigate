"""deps.dev integration for package metadata and repository trust signals."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import httpx

from ..models import PackageInfo
from . import DepsDevConfig, _read_cache, _write_cache

logger = logging.getLogger(__name__)

SYSTEM_MAP = {
    "pypi": "pypi",
    "npm": "npm",
    "pub": "pub",
}


async def fetch_deps_dev_metadata(
    package: PackageInfo,
    config: DepsDevConfig,
) -> dict[str, Any]:
    cached = _read_cache(package, "deps_dev", ttl_hours=24)
    if cached and "_cached_at" in cached:
        cached.pop("_cached_at", None)
        return cached

    system = SYSTEM_MAP.get(package.ecosystem)
    if not system or not package.version:
        return {}

    package_name = quote(package.name, safe="")
    package_version = quote(package.version, safe="")
    url = (
        f"{config.api_base_url}/systems/{system}/packages/{package_name}/versions/{package_version}"
    )

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("deps.dev lookup failed for %s: %s", package.name, e)
            return {}

    result = _parse_deps_dev_response(package, data)
    _write_cache(package, "deps_dev", result)
    return result


def _parse_deps_dev_response(package: PackageInfo, data: dict[str, Any]) -> dict[str, Any]:
    repo_url = _extract_repository_url(data)
    advisory_ids = [
        entry.get("id", "") for entry in data.get("advisoryKeys", []) if entry.get("id")
    ]
    attestation_count = len(data.get("attestations", []))
    slsa_provenance_count = len(data.get("slsaProvenances", []))

    return {
        "repository_url": repo_url,
        "project_status": data.get("projectStatus", {}).get("status", ""),
        "advisory_ids": advisory_ids,
        "published_at": data.get("publishedAt", ""),
        "licenses": data.get("licenses", []),
        "provenance": {
            "source": package.ecosystem,
            "available": bool(attestation_count or slsa_provenance_count),
            "verified": None,
            "status": "available" if (attestation_count or slsa_provenance_count) else "missing",
            "details": (
                f"deps.dev reported {attestation_count} attestations and "
                f"{slsa_provenance_count} SLSA provenance record(s)"
            ),
            "source_repository": repo_url,
            "attestation_count": attestation_count,
            "slsa_provenance_count": slsa_provenance_count,
        },
    }


def _extract_repository_url(data: dict[str, Any]) -> str:
    for link in data.get("links", []):
        if link.get("label") == "SOURCE_REPO" and link.get("url"):
            return link["url"]

    for project in data.get("relatedProjects", []):
        project_id = project.get("projectKey", {}).get("id", "")
        if project_id.startswith("github.com/"):
            return f"https://{project_id}"

    return ""
