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
    decision_from_dynamic_trace,
    decision_from_error,
    decision_from_prefilter,
    decision_from_report,
)
from aigate.reporters.json_reporter import JsonReporter
from aigate.sandbox.types import (
    DynamicTrace,
    DynamicTraceEvent,
    SandboxCoverage,
)


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


# ---------------------------------------------------------------------------
# Source-unavailable data-layer invariant — US-001 / Reviewer CRITICAL-2
# ---------------------------------------------------------------------------


def test_decision_from_report_source_unavailable_overrides_safe_consensus():
    """source_unavailable=True must short-circuit to NEEDS_REVIEW even when
    a consensus says SAFE. Reviewer probe showed exit 0 leakage; this is the
    data-layer guard that prevents bypass via cached/external reports."""
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=False,
            reason="rate-limit on github tarball; bytes not inspected",
            risk_level=RiskLevel.NONE,
            source_unavailable=True,
        ),
        consensus=ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.9,
            summary="(should be ignored)",
        ),
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1
    assert "rate-limit" in decision.reason or "Source bytes unavailable" in decision.reason


def test_decision_from_report_source_unavailable_no_consensus():
    """source_unavailable=True with no consensus (e.g. cached pre-AI scan)
    still resolves to NEEDS_REVIEW, never SAFE."""
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=True,
            reason="",
            risk_level=RiskLevel.NONE,
            source_unavailable=True,
        ),
        consensus=None,
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1


def test_decision_from_report_source_unavailable_with_malicious_stays_review():
    """Even when consensus would have escalated to MALICIOUS, an unavailable
    source means we have no real bytes to indict — surface as NEEDS_REVIEW
    with the prefilter reason (caller can still inspect risk_signals)."""
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=False,
            reason="github 403 — bytes not fetched",
            risk_level=RiskLevel.NONE,
            source_unavailable=True,
        ),
        consensus=ConsensusResult(
            final_verdict=Verdict.MALICIOUS,
            confidence=0.99,
            summary="(should be ignored — we never inspected bytes)",
        ),
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1


def test_decision_from_report_source_available_unchanged():
    """source_unavailable=False must not change the existing dispatch behaviour."""
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=True,
            reason="clean",
            risk_level=RiskLevel.NONE,
            source_unavailable=False,
        ),
        consensus=ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.95,
            summary="all safe",
        ),
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.SAFE
    assert decision.exit_code == 0


# ---------------------------------------------------------------------------
# Sandbox dynamic-trace policy — PRD v3.1 §3.2 / §3.5 — Phase 1 scaffold
# ---------------------------------------------------------------------------


def _noisy_events(
    *,
    severity: RiskLevel = RiskLevel.NONE,
    kinds: tuple[str, ...] = ("exec", "open", "connect"),
) -> list[DynamicTraceEvent]:
    """Trace-event list that clears the PRD P0-2 floor (≥3 distinct kinds)."""
    return [
        DynamicTraceEvent(
            kind=kind,
            ts_ms=i * 10,
            pid=1000 + i,
            process="npm",
            argv=["npm", "install"],
            target=f"/tmp/evidence-{i}",
            severity=severity,
        )
        for i, kind in enumerate(kinds)
    ]


def test_decision_from_dynamic_trace_none_returns_none():
    assert decision_from_dynamic_trace(None) is None


def test_decision_from_dynamic_trace_clean_run_returns_none():
    """A noisy, clean, non-quiet trace should NOT downgrade a consensus SAFE."""
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=3000,
        events=_noisy_events(),
    )
    assert decision_from_dynamic_trace(trace) is None


def test_decision_from_dynamic_trace_canary_touch_is_malicious():
    """PRD §3.2 P0-1: one canary read = unambiguous MALICIOUS."""
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=2500,
        events=_noisy_events(),
        canary_touches=["<CANARY_REF_0>"],
    )
    decision = decision_from_dynamic_trace(trace)
    assert decision is not None
    assert decision.outcome == PolicyOutcome.MALICIOUS
    assert decision.exit_code == 2
    assert decision.should_block_install is True


def test_decision_from_dynamic_trace_high_severity_event_is_malicious():
    trace = DynamicTrace(
        ran=True,
        runtime="docker",
        duration_ms=2500,
        events=_noisy_events(severity=RiskLevel.HIGH),
    )
    decision = decision_from_dynamic_trace(trace)
    assert decision is not None
    assert decision.outcome == PolicyOutcome.MALICIOUS
    assert decision.exit_code == 2
    assert decision.should_block_install is True


def test_decision_from_dynamic_trace_medium_severity_event_needs_review():
    trace = DynamicTrace(
        ran=True,
        runtime="docker",
        duration_ms=2500,
        events=_noisy_events(severity=RiskLevel.MEDIUM),
    )
    decision = decision_from_dynamic_trace(trace)
    assert decision is not None
    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1
    assert decision.should_block_install is False


def test_decision_from_dynamic_trace_observation_failure_needs_review():
    """``skipped_unexpected`` is the fail-closed parallel of source_unavailable."""
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=2500,
        events=_noisy_events(),
        skipped_unexpected={SandboxCoverage.NETWORK_CAPTURE},
    )
    decision = decision_from_dynamic_trace(trace)
    assert decision is not None
    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1


def test_decision_from_dynamic_trace_backend_error_needs_review():
    trace = DynamicTrace(
        ran=False,
        runtime="none",
        error="sandbox_unavailable: docker not installed",
        skipped_unexpected={
            SandboxCoverage.SYSCALL_TRACE,
            SandboxCoverage.NETWORK_CAPTURE,
        },
    )
    decision = decision_from_dynamic_trace(trace)
    assert decision is not None
    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert "docker not installed" in decision.reason


def test_decision_from_dynamic_trace_floor_violation_needs_review():
    """PRD P0-2: ≥2s run + <3 distinct kinds AND <10 events → floor trip."""
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=3000,
        events=[
            DynamicTraceEvent(kind="open", ts_ms=0, pid=1, process="sh", argv=["sh"]),
        ],
    )
    decision = decision_from_dynamic_trace(trace)
    assert decision is not None
    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW


def test_decision_from_dynamic_trace_quiet_run_needs_review():
    """PRD P0-2 heuristic: 0 net + 0 ext-write + ≤1 exec → suspicious_quiet_run."""
    # duration < 2s so floor rule does NOT apply; only quiet-run fires.
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=500,
        events=[
            DynamicTraceEvent(kind="open", ts_ms=0, pid=1, process="node", argv=["node"]),
        ],
    )
    decision = decision_from_dynamic_trace(trace)
    assert decision is not None
    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert "quiet" in decision.reason.lower()


def test_decision_from_report_sandbox_canary_overrides_safe_consensus():
    """Structured sandbox field must escalate past a SAFE consensus.

    Mirrors the ``source_unavailable`` invariant: actively-malicious bytes
    can never resolve to SAFE even with a high-confidence AI SAFE vote.
    """
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=2500,
        events=_noisy_events(),
        canary_touches=["<CANARY_REF_0>"],
    )
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=True,
            reason="clean",
            risk_level=RiskLevel.NONE,
        ),
        consensus=ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.95,
            summary="(should be overridden by canary signal)",
        ),
        dynamic_trace=trace,
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.MALICIOUS
    assert decision.exit_code == 2
    assert decision.should_block_install is True


def test_decision_from_report_sandbox_observation_failure_promotes_to_review():
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=2500,
        events=_noisy_events(),
        skipped_unexpected={SandboxCoverage.NETWORK_CAPTURE},
    )
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=True,
            reason="clean",
            risk_level=RiskLevel.NONE,
        ),
        consensus=ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.9,
            summary="(should be promoted to review)",
        ),
        dynamic_trace=trace,
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW
    assert decision.exit_code == 1


def test_decision_from_report_sandbox_clean_trace_preserves_safe():
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=3000,
        events=_noisy_events(),
    )
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=True,
            reason="clean",
            risk_level=RiskLevel.NONE,
        ),
        consensus=ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.95,
            summary="all safe",
        ),
        dynamic_trace=trace,
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.SAFE
    assert decision.exit_code == 0


def test_decision_from_report_no_dynamic_trace_unchanged_behaviour():
    """AnalysisReport.dynamic_trace=None must not affect the existing verdict."""
    report = AnalysisReport(
        package=_package(),
        prefilter=PrefilterResult(
            passed=False,
            reason="high risk",
            risk_level=RiskLevel.HIGH,
            risk_signals=["signal"],
            needs_ai_review=True,
        ),
        dynamic_trace=None,
    )

    decision = decision_from_report(report)

    assert decision.outcome == PolicyOutcome.MALICIOUS
    assert decision.exit_code == 2
