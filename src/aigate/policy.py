"""Shared decision policy for scan, hooks, and other enforcement surfaces."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from .models import (
    AnalysisReport,
    ConsensusResult,
    EnrichmentResult,
    PrefilterResult,
    RiskLevel,
    Verdict,
)


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


def decision_from_prefilter(prefilter: PrefilterResult) -> PolicyDecision:
    if prefilter.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        return PolicyDecision(
            outcome=PolicyOutcome.MALICIOUS,
            exit_code=2,
            reason=prefilter.reason,
            should_block_install=True,
        )
    if prefilter.risk_level == RiskLevel.MEDIUM:
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
    decisions = (
        [decision_from_consensus(report.consensus)]
        if report.consensus
        else [decision_from_prefilter(report.prefilter)]
    )
    enrichment_decision = decision_from_enrichment(report.enrichment)
    if enrichment_decision:
        decisions.append(enrichment_decision)
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
