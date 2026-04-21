"""Integration: policy wires run_dynamic into decision_from_dynamic_trace (Phase 3 T10).

Verifies that a DynamicTrace with events triggering ≥2 evasion categories
escalates a SAFE-consensus report to NEEDS_REVIEW via the T14 gate.
"""

from __future__ import annotations

from aigate.models import RiskLevel, RiskSignal
from aigate.policy import PolicyOutcome, decision_from_dynamic_trace
from aigate.sandbox.types import (
    DynamicTrace,
    DynamicTraceEvent,
    SandboxCoverage,
)


def _make_clean_trace(**kwargs) -> DynamicTrace:
    """Return a DynamicTrace that passes observation failure check."""
    defaults = dict(
        ran=True,
        runtime="birdcage",
        image_digest="",
        duration_ms=500,
        timeout=False,
        events=[],
        signatures=[],
        canary_touches=[],
        observed=set(),
        skipped_expected=set(),
        skipped_unexpected=set(),
        error=None,
    )
    defaults.update(kwargs)
    return DynamicTrace(**defaults)


def _make_event(
    kind: str, target: str = "", severity: RiskLevel = RiskLevel.MEDIUM
) -> DynamicTraceEvent:
    return DynamicTraceEvent(
        kind=kind,
        ts_ms=100,
        pid=1234,
        process="node",
        target=target,
        severity=severity,
    )


def test_env_mutation_static_plus_build_hooks_dynamic_escalates() -> None:
    """env_mutation static + build_hooks dynamic (exec+connect) → NEEDS_REVIEW.

    Provides ≥2 distinct MEDIUM+ evasion categories to trip the T14
    monotone-lift gate: one static via `risk_signals`, one dynamic via
    detector emission on the exec+connect event pair.
    """
    env_signal = RiskSignal(
        category="env_mutation",
        severity=RiskLevel.MEDIUM,
        description="os.environ['LD_PRELOAD'] = ...",
        filepath="install.py",
    )

    exec_event = _make_event("exec", "/usr/bin/node")
    connect_event = _make_event("connect", "93.184.216.34:443")

    # DynamicTrace dataclass has no risk_signals field; use a namespace
    # object exposing the same attributes policy.py reads via getattr.
    class _FakeTrace:
        ran = True
        runtime = "birdcage"
        image_digest = ""
        duration_ms = 500
        timeout = False
        events = [exec_event, connect_event]
        signatures: list = []
        canary_touches: list = []
        observed: set = set()
        skipped_expected: set = set()
        skipped_unexpected: set = set()
        error = None
        risk_signals = [env_signal]
        dynamic_categories: list = []

        def has_observation_failure(self) -> bool:
            return False

        def is_suspiciously_quiet(self) -> bool:
            return False

    decision = decision_from_dynamic_trace(_FakeTrace())  # type: ignore[arg-type]
    assert decision is not None
    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW, (
        f"Expected NEEDS_REVIEW from 2 evasion categories "
        f"(env_mutation static + build_hooks dynamic), "
        f"got: {decision.outcome} ({decision.reason})"
    )


def test_parser_partial_drift_skipped_unexpected_escalates_via_fail_closed() -> None:
    """PARSER_PARTIAL_DRIFT in skipped_unexpected → has_observation_failure → NEEDS_REVIEW.

    When parser_partial_drift is in skipped_unexpected, has_observation_failure()
    returns True. The fail-closed path in decision_from_dynamic_trace returns
    NEEDS_REVIEW before the T14 gate even runs.
    """
    trace = _make_clean_trace(
        skipped_unexpected={SandboxCoverage.PARSER_PARTIAL_DRIFT},
    )

    decision = decision_from_dynamic_trace(trace)
    assert decision is not None
    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW, (
        f"Expected NEEDS_REVIEW (fail-closed observation failure), got: {decision.outcome}"
    )


def test_two_dynamic_categories_from_detectors_trigger_gate() -> None:
    """run_dynamic firing ≥2 categories triggers NEEDS_REVIEW via T14.

    We inject dynamic_categories directly to simulate ≥2 detector emissions,
    validating that the T10 merge path feeds the T14 gate.
    """

    # DynamicTrace has no dynamic_categories field natively; the policy reads
    # it via getattr(trace, "dynamic_categories", []).
    # We use a simple namespace to simulate this.
    class _FakeTrace:
        ran = True
        runtime = "birdcage"
        image_digest = ""
        duration_ms = 500
        timeout = False
        events: list = []
        signatures: list = []
        canary_touches: list = []
        observed: set = set()
        skipped_expected: set = set()
        skipped_unexpected: set = set()
        error = None
        risk_signals: list = []
        # Pre-populated dynamic categories (simulates trace-level detection)
        dynamic_categories = ["env_mutation", "time_bomb"]

        def has_observation_failure(self) -> bool:
            return False

        def is_suspiciously_quiet(self) -> bool:
            return False

    decision = decision_from_dynamic_trace(_FakeTrace())  # type: ignore[arg-type]
    assert decision is not None
    assert decision.outcome == PolicyOutcome.NEEDS_REVIEW, (
        f"Expected NEEDS_REVIEW from 2 dynamic categories, "
        f"got: {decision.outcome} ({decision.reason})"
    )


def test_t14_needs_review_plus_canary_escalates_to_malicious() -> None:
    """Regression: T14 NEEDS_REVIEW must not short-circuit canary escalation (P1 PR #7).

    A trace that trips T14 (≥2 evasion categories) AND also has canary_touches
    must return MALICIOUS — the monotone-lift contract means canary wins.
    """

    class _FakeTrace:
        ran = True
        runtime = "birdcage"
        image_digest = ""
        duration_ms = 500
        timeout = False
        events: list = []
        signatures: list = []
        canary_touches = ["/tmp/aigate-canary-abc123"]
        observed: set = set()
        skipped_expected: set = set()
        skipped_unexpected: set = set()
        error = None
        risk_signals: list = []
        dynamic_categories = ["env_mutation", "time_bomb"]

        def has_observation_failure(self) -> bool:
            return False

        def is_suspiciously_quiet(self) -> bool:
            return False

    decision = decision_from_dynamic_trace(_FakeTrace())  # type: ignore[arg-type]
    assert decision is not None
    assert decision.outcome == PolicyOutcome.MALICIOUS, (
        f"Expected MALICIOUS (canary must escalate over T14 NEEDS_REVIEW), "
        f"got: {decision.outcome} ({decision.reason})"
    )
    assert "canary" in decision.reason.lower()
