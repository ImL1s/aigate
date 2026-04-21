"""Shared decision policy for scan, hooks, and other enforcement surfaces."""

from __future__ import annotations

import platform
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from .models import (
    AnalysisReport,
    ConsensusResult,
    EnrichmentResult,
    PrefilterResult,
    RiskLevel,
    RiskSignal,
    Verdict,
)
from .sandbox import evasion as _evasion_mod

if TYPE_CHECKING:
    # Runtime import lives inside ``decision_from_dynamic_trace`` to avoid
    # pulling the sandbox package on every CLI invocation that never uses it.
    from .sandbox.types import DynamicTrace


class PolicyOutcome(StrEnum):
    SAFE = "safe"
    NEEDS_REVIEW = "needs_review"
    MALICIOUS = "malicious"
    ERROR = "error"


@dataclass(frozen=True)
class PolicyDecision:
    outcome: PolicyOutcome
    exit_code: int
    reason: str
    should_block_install: bool = False


# ---------------------------------------------------------------------------
# Multi-evasion gate helpers (Phase 3 T14)
# ---------------------------------------------------------------------------

_OUTCOME_ORDER: dict[PolicyOutcome, int] = {
    PolicyOutcome.SAFE: 0,
    PolicyOutcome.NEEDS_REVIEW: 1,
    PolicyOutcome.MALICIOUS: 2,
    PolicyOutcome.ERROR: 3,
}

_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def max_verdict(a: PolicyOutcome, b: PolicyOutcome) -> PolicyOutcome:
    """Return the higher-severity verdict in the ordering SAFE < NEEDS_REVIEW < MALICIOUS."""
    return a if _OUTCOME_ORDER.get(a, 0) >= _OUTCOME_ORDER.get(b, 0) else b


def _apply_multi_evasion_gate(
    verdict: PolicyOutcome,
    categories_dict: dict[str, RiskLevel],
    dynamic_confirmed_categories: set[str],
) -> PolicyOutcome:
    """Apply the 5-step multi-evasion gate (Phase 3 T14).

    Step 1: categories_dict is already built by the caller via MAX join.
    Step 2: Darwin-XPC belt-and-braces — FIRST, before any count gate.
    Step 3: MALICIOUS gate — ≥2 HIGH categories with ≥1 dynamic confirmation.
    Step 4: NEEDS_REVIEW monotone-lift — ≥2 MEDIUM-or-above categories.
    Step 5: unchanged.
    """
    # Step 2: Darwin-XPC standalone belt-and-braces — evaluated FIRST (REV-BS3).
    # Fires when direct_xpc is the *only* evasion category on Darwin, even at
    # MEDIUM severity, escalating a SAFE verdict to NEEDS_REVIEW.
    if platform.system() == "Darwin" and set(categories_dict.keys()) == {"direct_xpc"}:
        return max_verdict(verdict, PolicyOutcome.NEEDS_REVIEW)

    # Step 3: MALICIOUS gate — ≥2 distinct HIGH categories + ≥1 dynamic confirmation.
    # Deliberate tightening (REV-NI2 option a): 1 HIGH + N MEDIUM does NOT
    # escalate to MALICIOUS; two orthogonal HIGH tactics are required.
    high_cats = {
        c
        for c, sev in categories_dict.items()
        if _RISK_ORDER.get(sev, 0) >= _RISK_ORDER[RiskLevel.HIGH]
    }
    if len(high_cats) >= 2 and len(high_cats & dynamic_confirmed_categories) >= 1:
        return PolicyOutcome.MALICIOUS  # short-circuit; Step 4 never runs

    # Step 4: NEEDS_REVIEW monotone-lift — ≥2 MEDIUM-or-above categories.
    # Monotone: NEVER downgrades an already-MALICIOUS verdict (REV-NI1).
    medium_or_above = {
        c
        for c, sev in categories_dict.items()
        if _RISK_ORDER.get(sev, 0) >= _RISK_ORDER[RiskLevel.MEDIUM]
    }
    if len(medium_or_above) >= 2:
        return max_verdict(verdict, PolicyOutcome.NEEDS_REVIEW)

    # Step 5: unchanged.
    return verdict


def decision_from_prefilter(prefilter: PrefilterResult) -> PolicyDecision:
    if prefilter.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        base_outcome = PolicyOutcome.MALICIOUS
    elif prefilter.risk_level == RiskLevel.MEDIUM:
        base_outcome = PolicyOutcome.NEEDS_REVIEW
    else:
        base_outcome = PolicyOutcome.SAFE

    # Phase 3 T14: multi-evasion gate over structured RiskSignal attributes.
    static_signals = [s for s in (prefilter.risk_signals or []) if isinstance(s, RiskSignal)]
    categories_dict = _evasion_mod.categories_from_signals(static_signals, [])
    outcome = _apply_multi_evasion_gate(base_outcome, categories_dict, set())

    if outcome == PolicyOutcome.MALICIOUS:
        return PolicyDecision(
            outcome=PolicyOutcome.MALICIOUS,
            exit_code=2,
            reason=prefilter.reason,
            should_block_install=True,
        )
    if outcome == PolicyOutcome.NEEDS_REVIEW:
        return PolicyDecision(
            outcome=PolicyOutcome.NEEDS_REVIEW,
            exit_code=1,
            reason=prefilter.reason,
        )
    return PolicyDecision(
        outcome=PolicyOutcome.SAFE,
        exit_code=0,
        reason=prefilter.reason,
    )


def decision_from_consensus(consensus: ConsensusResult) -> PolicyDecision:
    verdict_map = {
        Verdict.SAFE: PolicyDecision(
            outcome=PolicyOutcome.SAFE,
            exit_code=0,
            reason=consensus.summary,
        ),
        Verdict.SUSPICIOUS: PolicyDecision(
            outcome=PolicyOutcome.NEEDS_REVIEW,
            exit_code=1,
            reason=consensus.summary,
        ),
        Verdict.NEEDS_HUMAN_REVIEW: PolicyDecision(
            outcome=PolicyOutcome.NEEDS_REVIEW,
            exit_code=1,
            reason=consensus.summary,
        ),
        Verdict.MALICIOUS: PolicyDecision(
            outcome=PolicyOutcome.MALICIOUS,
            exit_code=2,
            reason=consensus.summary,
            should_block_install=True,
        ),
        Verdict.ERROR: PolicyDecision(
            outcome=PolicyOutcome.ERROR,
            exit_code=3,
            reason=consensus.summary or "AI analysis returned an error",
        ),
    }
    return verdict_map[consensus.final_verdict]


def decision_from_error(message: str) -> PolicyDecision:
    return PolicyDecision(
        outcome=PolicyOutcome.ERROR,
        exit_code=3,
        reason=message,
    )


def decision_from_report(report: AnalysisReport) -> PolicyDecision:
    # Data-layer guarantee: uninspected bytes can never resolve to SAFE.
    # Lives here (not just in CLI) so cached reports rehydrated from disk
    # and any external constructor of AnalysisReport cannot bypass it.
    if report.prefilter.source_unavailable:
        decisions = [
            PolicyDecision(
                outcome=PolicyOutcome.NEEDS_REVIEW,
                exit_code=1,
                reason=report.prefilter.reason
                or "Source bytes unavailable; manual review required",
            )
        ]
    else:
        decisions = (
            [decision_from_consensus(report.consensus)]
            if report.consensus
            else [decision_from_prefilter(report.prefilter)]
        )
    enrichment_decision = decision_from_enrichment(report.enrichment)
    if enrichment_decision:
        decisions.append(enrichment_decision)
    dynamic_trace_decision = decision_from_dynamic_trace(report.dynamic_trace)
    if dynamic_trace_decision:
        decisions.append(dynamic_trace_decision)
    return aggregate_decisions(decisions)


def decision_from_enrichment(enrichment: EnrichmentResult | None) -> PolicyDecision | None:
    if enrichment is None:
        return None

    decisions: list[PolicyDecision] = []

    high_severity_vulns = [
        vuln
        for vuln in enrichment.known_vulnerabilities
        if vuln.severity.upper() in {"HIGH", "CRITICAL"}
    ]
    if high_severity_vulns:
        decisions.append(
            PolicyDecision(
                outcome=PolicyOutcome.NEEDS_REVIEW,
                exit_code=1,
                reason=(
                    "Known vulnerabilities detected: "
                    + ", ".join(vuln.id for vuln in high_severity_vulns[:5])
                ),
            )
        )

    if enrichment.scorecard and enrichment.scorecard.score < 5.0:
        decisions.append(
            PolicyDecision(
                outcome=PolicyOutcome.NEEDS_REVIEW,
                exit_code=1,
                reason=f"OpenSSF Scorecard is low ({enrichment.scorecard.score:.1f}/10)",
            )
        )

    if enrichment.provenance and (
        enrichment.provenance.status == "invalid" or enrichment.provenance.verified is False
    ):
        decisions.append(
            PolicyDecision(
                outcome=PolicyOutcome.NEEDS_REVIEW,
                exit_code=1,
                reason=enrichment.provenance.details or "Invalid provenance metadata",
            )
        )

    if enrichment.errors:
        decisions.append(
            PolicyDecision(
                outcome=PolicyOutcome.NEEDS_REVIEW,
                exit_code=1,
                reason=enrichment.errors[0],
            )
        )

    if not decisions:
        return None
    return aggregate_decisions(decisions)


def decision_from_dynamic_trace(
    trace: DynamicTrace | None,
) -> PolicyDecision | None:
    """Mirror of :func:`decision_from_enrichment` for sandbox output.

    PRD v3.1 §3.2 contract:

    - Returns ``None`` when the trace is absent or ran cleanly with no
      signatures / canary touches. Callers fold ``None`` into the existing
      consensus/prefilter decision unchanged.
    - Returns ``NEEDS_REVIEW`` when ``trace.has_observation_failure()`` is
      True (PRD P0-2 floor + ``skipped_unexpected`` + backend error).
      Fail-closed parallel to ``prefilter.source_unavailable`` — uninspected
      or under-observed runs never resolve to SAFE.
    - Returns ``MALICIOUS`` + ``should_block_install=True`` when any event
      or signature is HIGH / CRITICAL severity (e.g. ``canary_touched``,
      ``canary_exfil``, ``persist_write``). Reviewer guidance: a single
      canary read is unambiguous malicious intent.
    - Returns ``NEEDS_REVIEW`` when MEDIUM severity signals fire OR the
      quiet-run heuristic trips (``is_suspiciously_quiet()``).

    Kept runtime-tolerant of missing methods / fields so this works even
    against ``DynamicTrace``-shaped stand-ins in tests; anything that
    cannot be reasoned about falls through to ``None`` rather than SAFE.
    """
    if trace is None:
        return None

    # Fail-closed: observation failure dominates any SAFE signal.
    try:
        observation_failed = trace.has_observation_failure()
    except AttributeError:
        observation_failed = False
    if observation_failed:
        reason = trace.error or "Sandbox observation incomplete; manual review required"
        return PolicyDecision(
            outcome=PolicyOutcome.NEEDS_REVIEW,
            exit_code=1,
            reason=reason,
        )

    # Phase 3 T14: multi-evasion gate (evaluated before severity scan).
    # Build policy-local copy of signatures — never mutate trace.signatures.
    _trace_static_signals = [
        s for s in (getattr(trace, "risk_signals", []) or []) if isinstance(s, RiskSignal)
    ]
    _dynamic_cats: list[str] = list(getattr(trace, "dynamic_categories", []) or [])
    _categories_dict = _evasion_mod.categories_from_signals(_trace_static_signals, _dynamic_cats)
    _dynamic_confirmed: set[str] = set(_dynamic_cats)
    _gate_outcome = _apply_multi_evasion_gate(
        PolicyOutcome.SAFE, _categories_dict, _dynamic_confirmed
    )
    if _gate_outcome == PolicyOutcome.MALICIOUS:
        return PolicyDecision(
            outcome=PolicyOutcome.MALICIOUS,
            exit_code=2,
            reason="Multi-evasion gate: ≥2 HIGH evasion tactics with dynamic confirmation",
            should_block_install=True,
        )
    if _gate_outcome == PolicyOutcome.NEEDS_REVIEW:
        return PolicyDecision(
            outcome=PolicyOutcome.NEEDS_REVIEW,
            exit_code=1,
            reason="Multi-evasion gate: ≥2 evasion tactics detected",
        )

    # Scan events + signatures for HIGH/CRITICAL signals.
    highest_severity = RiskLevel.NONE
    severity_reason = ""
    severity_order = {
        RiskLevel.NONE: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    for event in getattr(trace, "events", []) or []:
        sev = getattr(event, "severity", RiskLevel.NONE)
        if severity_order.get(sev, 0) > severity_order.get(highest_severity, 0):
            highest_severity = sev
            severity_reason = (
                f"Sandbox observed {event.kind} event with severity {sev.value}"
                if hasattr(event, "kind") and hasattr(sev, "value")
                else "Sandbox observed high-severity event"
            )

    # Canary touches are unambiguous MALICIOUS even without per-event severity,
    # because each canary has a unique random token and no legitimate package
    # reads these paths during install.
    canary_touches = list(getattr(trace, "canary_touches", []) or [])
    if canary_touches:
        return PolicyDecision(
            outcome=PolicyOutcome.MALICIOUS,
            exit_code=2,
            reason=("Sandbox canary file(s) read during install: " + ", ".join(canary_touches[:3])),
            should_block_install=True,
        )

    if highest_severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        return PolicyDecision(
            outcome=PolicyOutcome.MALICIOUS,
            exit_code=2,
            reason=severity_reason or "Sandbox observed high-severity event",
            should_block_install=True,
        )

    # Signature-based signals without severity metadata get folded in as
    # MEDIUM-equivalents by default — signature names (Tracee/Falco-style)
    # are already curated.
    signatures = list(getattr(trace, "signatures", []) or [])

    if highest_severity == RiskLevel.MEDIUM or signatures:
        reason = severity_reason or (
            "Sandbox surfaced signatures: " + ", ".join(signatures[:3])
            if signatures
            else "Sandbox surfaced medium-severity events"
        )
        return PolicyDecision(
            outcome=PolicyOutcome.NEEDS_REVIEW,
            exit_code=1,
            reason=reason,
        )

    # Quiet-run heuristic — last so loud-but-clean traces don't trip it.
    try:
        quiet = trace.is_suspiciously_quiet()
    except AttributeError:
        quiet = False
    if quiet:
        return PolicyDecision(
            outcome=PolicyOutcome.NEEDS_REVIEW,
            exit_code=1,
            reason="Sandbox run was suspiciously quiet (no network, no external writes, no exec)",
        )

    return None


def aggregate_decisions(decisions: Iterable[PolicyDecision]) -> PolicyDecision:
    decisions = list(decisions)
    if not decisions:
        return PolicyDecision(
            outcome=PolicyOutcome.SAFE,
            exit_code=0,
            reason="No packages scanned",
        )

    priority = {
        PolicyOutcome.ERROR: 3,
        PolicyOutcome.MALICIOUS: 2,
        PolicyOutcome.NEEDS_REVIEW: 1,
        PolicyOutcome.SAFE: 0,
    }
    return max(decisions, key=lambda decision: priority[decision.outcome])
