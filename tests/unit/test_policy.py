"""Tests for shared policy decisions."""

import io
import json
from contextlib import redirect_stdout

from aigate.models import (
    AnalysisReport,
    ConsensusResult,
    EnrichmentResult,
    PackageInfo,
    PrefilterResult,
    ProvenanceInfo,
    RiskLevel,
    Verdict,
)
from aigate.policy import (
    PolicyOutcome,
    aggregate_decisions,
    decision_from_error,
    decision_from_prefilter,
    decision_from_report,
)
from aigate.reporters.json_reporter import JsonReporter


def _package() -> PackageInfo:
    return PackageInfo(name="demo", version="1.0.0", ecosystem="pypi")


def test_prefilter_medium_maps_to_review_without_blocking():
    decision = decision_from_prefilter(
        PrefilterResult(
            passed=False,
            reason="needs review",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["signal"],
            needs_ai_review=True,
        )
    )

    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1
    assert not decision.should_block_install


def test_prefilter_high_maps_to_malicious_and_blocks():
    decision = decision_from_prefilter(
        PrefilterResult(
            passed=False,
            reason="high risk",
            risk_level=RiskLevel.HIGH,
            risk_signals=["signal"],
            needs_ai_review=True,
        )
    )

    assert decision.outcome == PolicyOutcome.MALICIOUS
    assert decision.exit_code == 2
    assert decision.should_block_install


def test_consensus_review_maps_to_shared_review_decision():
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=False,
            reason="needs AI review",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["signal"],
            needs_ai_review=True,
        ),
        consensus=ConsensusResult(
            final_verdict=Verdict.NEEDS_HUMAN_REVIEW,
            confidence=0.71,
            summary="models disagree",
        ),
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1
    assert not decision.should_block_install


def test_aggregate_decisions_prioritizes_errors():
    aggregated = aggregate_decisions(
        [
            decision_from_prefilter(
                PrefilterResult(
                    passed=True,
                    reason="clean",
                    risk_level=RiskLevel.NONE,
                )
            ),
            decision_from_prefilter(
                PrefilterResult(
                    passed=False,
                    reason="high risk",
                    risk_level=RiskLevel.HIGH,
                    risk_signals=["signal"],
                    needs_ai_review=True,
                )
            ),
            decision_from_error("download failed"),
        ]
    )

    assert aggregated.outcome == PolicyOutcome.ERROR
    assert aggregated.exit_code == 3


def test_invalid_provenance_promotes_safe_report_to_review():
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=True,
            reason="clean",
            risk_level=RiskLevel.NONE,
        ),
        enrichment=EnrichmentResult(
            provenance=ProvenanceInfo(
                source="pypi",
                available=True,
                verified=False,
                status="invalid",
                details="attestation mismatch",
            )
        ),
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1
    assert not decision.should_block_install


def test_missing_provenance_stays_informational_under_balanced_policy():
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=True,
            reason="clean",
            risk_level=RiskLevel.NONE,
        ),
        enrichment=EnrichmentResult(
            provenance=ProvenanceInfo(
                source="npm",
                available=False,
                verified=None,
                status="missing",
                details="no provenance published",
            )
        ),
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.SAFE
    assert decision.exit_code == 0


def test_json_reporter_includes_shared_policy_fields():
    output = io.StringIO()
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=False,
            reason="high risk",
            risk_level=RiskLevel.HIGH,
            risk_signals=["signal"],
            needs_ai_review=True,
        ),
    )

    with redirect_stdout(output):
        JsonReporter().print_report(report)

    payload = json.loads(output.getvalue())
    assert payload["decision"] == "malicious"
    assert payload["exit_code"] == 2
