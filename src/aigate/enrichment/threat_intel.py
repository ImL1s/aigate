"""Threat intelligence — query vulnerability databases for known issues.

Primary source: OSV.dev (free, no API key required).
Future: Socket.dev, Snyk, GitHub Advisory Database, deps.dev.

OSV API docs: https://google.github.io/osv.dev/api/
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ..models import PackageInfo
from . import _read_cache, _write_cache

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"

# Map aigate ecosystem names to OSV ecosystem names (case-sensitive!)
ECOSYSTEM_MAP: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "pub": "Pub",
}


async def query_osv_vulns(package: PackageInfo) -> dict[str, Any]:
    """Query OSV.dev for known vulnerabilities.

    Returns a dict with key:
        - known_vulnerabilities: list[dict] with {id, summary, severity, fixed_version}
    """
    # Check cache first
    cached = _read_cache(package, "osv", ttl_hours=6)
    if cached and "_cached_at" in cached:
        cached.pop("_cached_at", None)
        return cached

    osv_ecosystem = ECOSYSTEM_MAP.get(package.ecosystem)
    if not osv_ecosystem:
        logger.debug("OSV: unsupported ecosystem %s", package.ecosystem)
        return {"known_vulnerabilities": []}

    result = await _query_osv(package, osv_ecosystem)

    # Cache the result
    _write_cache(package, "osv", result)
    return result


async def _query_osv(
    package: PackageInfo,
    osv_ecosystem: str,
) -> dict[str, Any]:
    """Execute OSV.dev API query."""
    payload: dict[str, Any] = {
        "package": {
            "name": package.name,
            "ecosystem": osv_ecosystem,
        },
    }
    if package.version:
        payload["version"] = package.version

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(OSV_API_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            logger.warning("OSV query failed for %s: HTTP %s", package.name, e.response.status_code)
            return {"known_vulnerabilities": []}
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("OSV query failed for %s: %s", package.name, e)
            return {"known_vulnerabilities": []}

    vulns = data.get("vulns", [])
    if not vulns:
        return {"known_vulnerabilities": []}

    return {
        "known_vulnerabilities": [_parse_vuln(v) for v in vulns[:20]],  # Cap at 20
    }


def _parse_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    """Parse an OSV vulnerability entry into our format."""
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary", vuln.get("details", "")[:200])

    # Extract severity
    severity = _extract_severity(vuln)

    # Extract fixed version (first fix from affected ranges)
    fixed_version = _extract_fixed_version(vuln)

    return {
        "id": vuln_id,
        "summary": summary,
        "severity": severity,
        "fixed_version": fixed_version,
    }


def _extract_severity(vuln: dict[str, Any]) -> str:
    """Extract severity from OSV vulnerability data.

    OSV uses CVSS in database_specific or severity field.
    """
    # Try database_specific.severity
    db_specific = vuln.get("database_specific", {})
    severity = db_specific.get("severity")
    if severity and isinstance(severity, str):
        return severity.upper()

    # Try ecosystem_specific
    eco_specific = vuln.get("ecosystem_specific", {})
    severity = eco_specific.get("severity")
    if severity and isinstance(severity, str):
        return severity.upper()

    # Fallback: try to infer from CVSS score in severity array
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        if isinstance(score, str) and "CVSS" in score:
            # Parse CVSS base score from vector string
            cvss_score = _parse_cvss_score(score)
            if cvss_score is not None:
                return _cvss_to_severity(cvss_score)

    return "UNKNOWN"


def _extract_fixed_version(vuln: dict[str, Any]) -> str:
    """Extract the earliest fixed version from affected ranges."""
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return ""


def _parse_cvss_score(vector: str) -> float | None:
    """Try to extract numeric CVSS score from a CVSS vector string.

    This is a best-effort parser. CVSS vectors don't always contain
    the numeric score directly.
    """
    # Some OSV entries include score as "CVSS:3.1/AV:N/AC:L/..."
    # We can't calculate the exact score without a full CVSS library,
    # but we can use heuristics based on attack vector components.
    vector_lower = vector.lower()

    # Rough heuristic based on common CVSS components
    score = 5.0  # default medium
    if "av:n" in vector_lower:  # Network attack vector
        score += 2.0
    if "ac:l" in vector_lower:  # Low complexity
        score += 1.0
    if "pr:n" in vector_lower:  # No privileges required
        score += 1.0
    if "ui:n" in vector_lower:  # No user interaction
        score += 0.5

    return min(score, 10.0)


def _cvss_to_severity(score: float) -> str:
    """Convert CVSS numeric score to severity string."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"
