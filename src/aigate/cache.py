"""File-based analysis cache for aigate."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from .models import (
    AnalysisLevel,
    AnalysisReport,
    ConsensusResult,
    EnrichmentResult,
    KnownVulnerability,
    ModelResult,
    PackageInfo,
    PrefilterResult,
    ProvenanceInfo,
    RiskLevel,
    ScorecardCheck,
    ScorecardResult,
    SecurityMention,
    Verdict,
)

logger = logging.getLogger(__name__)


def _cache_disabled() -> bool:
    """AIGATE_NO_CACHE escape hatch. Truthy values: 1/true/yes/on (case-insensitive)."""
    val = os.environ.get("AIGATE_NO_CACHE", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _from_dict(cls, data: dict):
    """Construct a dataclass, silently dropping unknown keys.

    Tolerates two-way schema drift: older cache entries may contain fields the
    current class dropped (filtered via ``__dataclass_fields__``), or may lack
    fields the current class now requires (caught as TypeError and downgraded
    to None). Either way the caller treats the result as "not in cache" rather
    than letting the hook's broad except swallow a TypeError and fail-open.
    """
    fields = cls.__dataclass_fields__
    filtered = {k: v for k, v in data.items() if k in fields}
    try:
        return cls(**filtered)
    except TypeError:
        logger.debug("Skipping cached %s — incompatible with current schema", cls.__name__)
        return None


def _cache_dir(config_cache_dir: str) -> Path:
    p = Path(config_cache_dir).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cache_key(name: str, version: str, ecosystem: str, provenance: str = "registry") -> str:
    raw = f"{ecosystem}:{name}:{version}:{provenance}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_cached(
    name: str,
    version: str,
    ecosystem: str,
    cache_dir: str,
    ttl_hours: int,
    provenance: str = "registry",
) -> dict | None:
    """Return cached analysis dict or None if missing/expired/disabled."""
    if _cache_disabled():
        logger.debug("Cache disabled via AIGATE_NO_CACHE — skipping read")
        return None
    d = _cache_dir(cache_dir)
    key = _cache_key(name, version, ecosystem, provenance)
    path = d / f"{key}.json"
    if not path.exists():
        logger.debug("Cache miss: %s/%s/%s", ecosystem, name, version)
        return None
    try:
        data = json.loads(path.read_text())
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > ttl_hours * 3600:
            logger.debug("Cache expired: %s/%s/%s", ecosystem, name, version)
            path.unlink(missing_ok=True)
            return None
        logger.debug("Cache hit: %s/%s/%s", ecosystem, name, version)
        return data
    except (json.JSONDecodeError, OSError):
        return None


def set_cached(
    name: str,
    version: str,
    ecosystem: str,
    report: AnalysisReport,
    cache_dir: str,
    provenance: str = "registry",
) -> None:
    """Write analysis result to cache using atomic write.

    Writes to a temporary file first, then atomically replaces the target.
    This prevents concurrent readers from seeing partial/corrupt JSON.
    No-op when AIGATE_NO_CACHE is set.
    """
    if _cache_disabled():
        logger.debug("Cache disabled via AIGATE_NO_CACHE — skipping write")
        return
    d = _cache_dir(cache_dir)
    key = _cache_key(name, version, ecosystem, provenance)
    path = d / f"{key}.json"
    data = asdict(report)
    data["_cached_at"] = time.time()
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=d, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            fd = None  # os.fdopen takes ownership of fd
            json.dump(data, f, default=str)
        os.replace(tmp_path, path)  # Atomic on POSIX
        tmp_path = None  # Successfully replaced, no cleanup needed
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def report_from_cached(
    cached: dict,
    *,
    fallback_package: PackageInfo,
    total_latency_ms: int,
) -> AnalysisReport:
    """Reconstruct an AnalysisReport from a cached dict (produced by set_cached).

    ``fallback_package`` supplies defaults when the cached payload is missing
    package metadata fields (older cache entries may omit newly added fields).
    """
    package_data = cached.get("package") or {}
    package = PackageInfo(
        name=package_data.get("name", fallback_package.name),
        version=package_data.get("version", fallback_package.version),
        ecosystem=package_data.get("ecosystem", fallback_package.ecosystem),
        author=package_data.get("author", fallback_package.author),
        description=package_data.get("description", fallback_package.description),
        download_count=package_data.get("download_count", fallback_package.download_count),
        publish_date=package_data.get("publish_date", fallback_package.publish_date),
        homepage=package_data.get("homepage", fallback_package.homepage),
        repository=package_data.get("repository", fallback_package.repository),
        has_install_scripts=package_data.get(
            "has_install_scripts",
            fallback_package.has_install_scripts,
        ),
        dependencies=package_data.get("dependencies", fallback_package.dependencies),
        metadata=package_data.get("metadata", fallback_package.metadata),
    )

    prefilter_data = cached.get("prefilter") or {}
    prefilter = PrefilterResult(
        passed=prefilter_data.get("passed", True),
        reason=prefilter_data.get("reason", "cached"),
        risk_signals=prefilter_data.get("risk_signals", []),
        risk_level=RiskLevel(prefilter_data.get("risk_level", "none")),
        needs_ai_review=prefilter_data.get("needs_ai_review", False),
        source_unavailable=prefilter_data.get("source_unavailable", False),
    )

    consensus = None
    consensus_data = cached.get("consensus")
    if consensus_data:
        consensus = ConsensusResult(
            final_verdict=Verdict(consensus_data.get("final_verdict", "error")),
            confidence=float(consensus_data.get("confidence", 0.0)),
            model_results=[
                ModelResult(
                    model_name=model.get("model_name", ""),
                    verdict=Verdict(model.get("verdict", "error")),
                    confidence=float(model.get("confidence", 0.0)),
                    reasoning=model.get("reasoning", ""),
                    risk_signals=model.get("risk_signals", []),
                    analysis_level=AnalysisLevel(model.get("analysis_level", "l1_quick")),
                    token_usage=int(model.get("token_usage", 0)),
                    latency_ms=int(model.get("latency_ms", 0)),
                    raw_response=model.get("raw_response", ""),
                )
                for model in consensus_data.get("model_results", [])
            ],
            has_disagreement=consensus_data.get("has_disagreement", False),
            summary=consensus_data.get("summary", ""),
            risk_signals=consensus_data.get("risk_signals", []),
            recommendation=consensus_data.get("recommendation", ""),
        )

    enrichment = None
    enrichment_data = cached.get("enrichment")
    if enrichment_data:
        scorecard = None
        if enrichment_data.get("scorecard"):
            scorecard_data = enrichment_data["scorecard"]
            scorecard = ScorecardResult(
                repository_url=scorecard_data.get("repository_url", ""),
                date=scorecard_data.get("date", ""),
                score=float(scorecard_data.get("score", 0.0)),
                critical_findings=scorecard_data.get("critical_findings", []),
                checks=[
                    ScorecardCheck(
                        name=check.get("name", ""),
                        score=float(check.get("score", 0.0)),
                        reason=check.get("reason", ""),
                        documentation_url=check.get("documentation_url", ""),
                    )
                    for check in scorecard_data.get("checks", [])
                ],
            )

        provenance = None
        if enrichment_data.get("provenance"):
            provenance = _from_dict(ProvenanceInfo, enrichment_data["provenance"])

        enrichment = EnrichmentResult(
            repository_url=enrichment_data.get("repository_url", ""),
            project_status=enrichment_data.get("project_status", ""),
            advisory_ids=enrichment_data.get("advisory_ids", []),
            library_description=enrichment_data.get("library_description", ""),
            expected_capabilities=enrichment_data.get("expected_capabilities", []),
            doc_snippets=enrichment_data.get("doc_snippets", []),
            security_mentions=[
                m_obj
                for mention in enrichment_data.get("security_mentions", [])
                if (m_obj := _from_dict(SecurityMention, mention)) is not None
            ],
            author_info=enrichment_data.get("author_info", ""),
            known_vulnerabilities=[
                v_obj
                for vuln in enrichment_data.get("known_vulnerabilities", [])
                if (v_obj := _from_dict(KnownVulnerability, vuln)) is not None
            ],
            scorecard=scorecard,
            provenance=provenance,
            sources_queried=enrichment_data.get("sources_queried", []),
            cache_hit=enrichment_data.get("cache_hit", False),
            enrichment_latency_ms=int(enrichment_data.get("enrichment_latency_ms", 0)),
            errors=enrichment_data.get("errors", []),
        )

    return AnalysisReport(
        package=package,
        prefilter=prefilter,
        consensus=consensus,
        enrichment=enrichment,
        cached=True,
        total_latency_ms=int(cached.get("total_latency_ms", total_latency_ms)),
    )
