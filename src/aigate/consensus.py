"""Multi-model consensus engine."""

from __future__ import annotations

import asyncio
import logging
import statistics

from .backends.base import AIBackend
from .backends.claude import ClaudeBackend
from .backends.gemini import GeminiBackend
from .backends.ollama import OllamaBackend
from .config import Config, ModelConfig
from .models import (
    AnalysisLevel,
    ConsensusResult,
    ModelResult,
    PackageInfo,
    Verdict,
    VersionDiff,
)

logger = logging.getLogger(__name__)

BACKEND_MAP = {
    "claude": ClaudeBackend,
    "gemini": GeminiBackend,
    "ollama": OllamaBackend,
}


def create_backend(model_config: ModelConfig) -> AIBackend:
    cls = BACKEND_MAP.get(model_config.backend)
    if cls is None:
        raise ValueError(f"Unknown backend: {model_config.backend}")
    kwargs = {"timeout": model_config.timeout_seconds}
    if model_config.model_id:
        kwargs["model_id"] = model_config.model_id
    kwargs.update(model_config.options)
    return cls(**kwargs)


async def run_consensus(
    package: PackageInfo,
    risk_signals: list[str],
    source_code: str,
    config: Config,
    level: AnalysisLevel = AnalysisLevel.L1_QUICK,
    version_diff: VersionDiff | None = None,
    external_intelligence: str = "",
) -> ConsensusResult:
    """Run multi-model analysis and aggregate votes."""
    enabled_models = [m for m in config.models if m.enabled]
    if not enabled_models:
        return ConsensusResult(
            final_verdict=Verdict.ERROR,
            confidence=0.0,
            summary="No AI models configured or enabled",
        )

    backends = []
    for mc in enabled_models:
        try:
            backends.append((mc, create_backend(mc)))
            logger.debug("Initialized backend: %s (%s)", mc.name, mc.backend)
        except ValueError:
            logger.debug("Skipping unavailable backend: %s", mc.backend)
            pass

    if not backends:
        return ConsensusResult(
            final_verdict=Verdict.ERROR,
            confidence=0.0,
            summary="No AI backends available",
        )

    # Run all models in parallel
    tasks = []
    for mc, backend in backends:
        if version_diff:
            task = backend.analyze_diff(
                name=package.name,
                old_version=version_diff.old_version,
                new_version=version_diff.new_version,
                ecosystem=package.ecosystem,
                new_imports=version_diff.new_imports,
                new_network_calls=version_diff.new_network_calls,
                new_exec_calls=version_diff.new_exec_calls,
                new_file_access=version_diff.new_file_access,
                install_script_changes="\n".join(
                    f.path for f in version_diff.install_script_changes
                ),
                diff_content=source_code,
                level=level,
            )
        else:
            task = backend.analyze_package(
                name=package.name,
                version=package.version,
                ecosystem=package.ecosystem,
                author=package.author,
                description=package.description,
                has_install_scripts=package.has_install_scripts,
                risk_signals=risk_signals,
                source_code=source_code,
                external_intelligence=external_intelligence,
                level=level,
            )
        tasks.append(task)

    logger.debug("Running %d AI models in parallel", len(tasks))
    results: list[ModelResult] = []
    for coro in asyncio.as_completed(tasks):
        try:
            result = await coro
            logger.debug(
                "Model %s returned verdict=%s confidence=%.2f",
                result.model_name,
                result.verdict.value,
                result.confidence,
            )
            results.append(result)
        except Exception as e:
            results.append(
                ModelResult(
                    model_name="unknown",
                    verdict=Verdict.ERROR,
                    confidence=0.0,
                    reasoning=f"Backend error: {e}",
                    analysis_level=level,
                )
            )

    return _aggregate_votes(results, config, enabled_models)


def _aggregate_votes(
    results: list[ModelResult],
    config: Config,
    model_configs: list[ModelConfig],
) -> ConsensusResult:
    """Aggregate model votes using weighted consensus."""
    # Filter out errors
    valid = [r for r in results if r.verdict != Verdict.ERROR]
    if not valid:
        return ConsensusResult(
            final_verdict=Verdict.ERROR,
            confidence=0.0,
            model_results=results,
            summary="All models returned errors",
        )

    # Build weight map
    weight_map = {mc.name: mc.weight for mc in model_configs}

    # Calculate weighted scores for each verdict
    scores: dict[Verdict, float] = {
        Verdict.SAFE: 0.0,
        Verdict.SUSPICIOUS: 0.0,
        Verdict.MALICIOUS: 0.0,
    }
    total_weight = 0.0

    for r in valid:
        w = weight_map.get(r.model_name, 1.0) * r.confidence
        scores[r.verdict] = scores.get(r.verdict, 0.0) + w
        total_weight += w

    # Normalize
    if total_weight > 0:
        for v in scores:
            scores[v] /= total_weight

    # Check disagreement
    confidences = [r.confidence for r in valid]
    has_disagreement = False
    if len(confidences) >= 2:
        verdicts_set = {r.verdict for r in valid}
        if Verdict.MALICIOUS in verdicts_set and Verdict.SAFE in verdicts_set:
            has_disagreement = True

    # Decision
    thresholds = config.thresholds

    if has_disagreement:
        final = Verdict.NEEDS_HUMAN_REVIEW
        confidence = statistics.mean(confidences)
    elif scores[Verdict.MALICIOUS] > thresholds.malicious:
        final = Verdict.MALICIOUS
        confidence = scores[Verdict.MALICIOUS]
    elif scores[Verdict.SUSPICIOUS] > thresholds.suspicious:
        final = Verdict.SUSPICIOUS
        confidence = scores[Verdict.SUSPICIOUS]
    else:
        final = Verdict.SAFE
        confidence = scores[Verdict.SAFE]

    # Collect all risk signals
    all_signals = []
    for r in valid:
        all_signals.extend(r.risk_signals)
    unique_signals = list(dict.fromkeys(all_signals))

    # Build summary
    model_verdicts = ", ".join(
        f"{r.model_name}={r.verdict.value}({r.confidence:.0%})" for r in valid
    )
    summary = f"Consensus: {final.value} | Models: [{model_verdicts}]"

    # Recommendation
    recommendations = {
        Verdict.SAFE: "Package appears safe to install.",
        Verdict.SUSPICIOUS: "Proceed with caution. Review the flagged risk signals manually.",
        Verdict.MALICIOUS: "DO NOT INSTALL. This package shows signs of malicious behavior.",
        Verdict.NEEDS_HUMAN_REVIEW: "Models disagree. Manual review required before installation.",
    }

    return ConsensusResult(
        final_verdict=final,
        confidence=confidence,
        model_results=results,
        has_disagreement=has_disagreement,
        summary=summary,
        risk_signals=unique_signals,
        recommendation=recommendations.get(final, ""),
    )
