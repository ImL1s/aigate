"""Unit tests for aigate.sandbox.types — DynamicTrace + backend ABC.

Covers PRD v3.1 §3.2:
- Tier-floor publication (BIRDCAGE / DOCKER_PLAIN / DOCKER_PARANOID).
- ``has_observation_failure()`` trips on unexpected skips, explicit
  errors, and floor violations (≥2s run with <3 kinds AND <10 events).
- ``is_suspiciously_quiet()`` flags a zero-network / zero-external-write
  / zero-real-exec run per P0-2.
- ``SandboxBackend.classify_skips()`` splits attempted-but-not-observed
  surfaces into expected vs unexpected correctly.
"""

from __future__ import annotations

import pytest

from aigate.sandbox import (
    BIRDCAGE_EXPECTED_SKIPS,
    DOCKER_PARANOID_EXPECTED_SKIPS,
    DOCKER_PLAIN_EXPECTED_SKIPS,
    DynamicTrace,
    DynamicTraceEvent,
    SandboxBackend,
    SandboxCoverage,
    SandboxMode,
)

# ---------------------------------------------------------------------------
# Tier floors
# ---------------------------------------------------------------------------


def test_birdcage_tier_floor_matches_prd():
    # PRD §3.2: Birdcage is Landlock-only → no syscall trace, no
    # PID-namespace PROCESS_TREE walk, no uprobes ENV_READS.
    assert BIRDCAGE_EXPECTED_SKIPS == frozenset(
        {
            SandboxCoverage.SYSCALL_TRACE,
            SandboxCoverage.PROCESS_TREE,
            SandboxCoverage.ENV_READS,
        }
    )


def test_docker_plain_and_paranoid_floors_are_empty():
    assert DOCKER_PLAIN_EXPECTED_SKIPS == frozenset()
    assert DOCKER_PARANOID_EXPECTED_SKIPS == frozenset()


def test_expected_skips_for_mode_lookup():
    assert SandboxBackend.expected_skips_for(SandboxMode.LIGHT) == BIRDCAGE_EXPECTED_SKIPS
    assert SandboxBackend.expected_skips_for(SandboxMode.STRICT) == DOCKER_PARANOID_EXPECTED_SKIPS
    assert (
        SandboxBackend.expected_skips_for(SandboxMode.DOCKER_RUNSC)
        == DOCKER_PARANOID_EXPECTED_SKIPS
    )


# ---------------------------------------------------------------------------
# DynamicTrace.has_observation_failure
# ---------------------------------------------------------------------------


def _trace(
    *,
    ran: bool = True,
    duration_ms: int = 3000,
    events: list[DynamicTraceEvent] | None = None,
    skipped_expected: set[SandboxCoverage] | None = None,
    skipped_unexpected: set[SandboxCoverage] | None = None,
    error: str | None = None,
) -> DynamicTrace:
    return DynamicTrace(
        ran=ran,
        runtime="birdcage",
        duration_ms=duration_ms,
        events=events or [],
        skipped_expected=skipped_expected or set(),
        skipped_unexpected=skipped_unexpected or set(),
        error=error,
    )


def _event(kind: str, pid: int = 1, target: str = "") -> DynamicTraceEvent:
    return DynamicTraceEvent(
        kind=kind,
        ts_ms=1,
        pid=pid,
        process="npm",
        target=target,
    )


def test_observation_failure_on_unexpected_skip():
    trace = _trace(skipped_unexpected={SandboxCoverage.NETWORK_CAPTURE})
    assert trace.has_observation_failure() is True


def test_observation_failure_on_error():
    trace = _trace(error="mitmproxy crashed")
    assert trace.has_observation_failure() is True


def test_expected_skip_alone_is_not_failure():
    # Landlock-only Birdcage run SHOULD skip syscall trace without
    # tripping observation failure — that's the tier floor.
    trace = _trace(
        skipped_expected={SandboxCoverage.SYSCALL_TRACE},
        events=[
            _event("open"),
            _event("exec"),
            _event("connect"),
            _event("write"),
        ],
    )
    assert trace.has_observation_failure() is False


def test_floor_violation_trips_on_long_silent_run():
    # ≥2s run with <3 kinds AND <10 events → floor violation.
    trace = _trace(
        duration_ms=3000,
        events=[_event("open"), _event("open")],  # 1 kind, 2 events
    )
    assert trace.has_observation_failure() is True


def test_short_run_below_floor_threshold_is_ok():
    # <2s run: floor does not apply even if events are sparse.
    trace = _trace(duration_ms=500, events=[_event("open")])
    assert trace.has_observation_failure() is False


def test_floor_satisfied_by_many_events_of_one_kind():
    # PRD spec: ≥3 distinct kinds OR ≥10 total events → floor met.
    many = [_event("open") for _ in range(12)]
    trace = _trace(duration_ms=5000, events=many)
    assert trace.has_observation_failure() is False


def test_floor_satisfied_by_three_distinct_kinds():
    trace = _trace(
        duration_ms=5000,
        events=[_event("open"), _event("exec"), _event("connect")],
    )
    assert trace.has_observation_failure() is False


# ---------------------------------------------------------------------------
# DynamicTrace.is_suspiciously_quiet
# ---------------------------------------------------------------------------


def test_quiet_run_with_only_opens_is_suspicious():
    trace = _trace(events=[_event("open"), _event("open"), _event("exec")])
    # Single exec (manifest read) + no network + no writes → quiet.
    assert trace.is_suspiciously_quiet() is True


def test_run_with_network_is_not_quiet():
    trace = _trace(events=[_event("open"), _event("connect")])
    assert trace.is_suspiciously_quiet() is False


def test_run_with_persist_write_is_not_quiet():
    trace = _trace(events=[_event("open"), _event("persist_write")])
    assert trace.is_suspiciously_quiet() is False


def test_multiple_execs_are_not_quiet():
    # More than one exec (beyond manifest read) → actually doing something.
    trace = _trace(events=[_event("exec"), _event("exec"), _event("exec")])
    assert trace.is_suspiciously_quiet() is False


def test_run_that_did_not_run_is_not_quiet():
    # A trace that never executed cannot be "suspiciously quiet" —
    # the quiet-run heuristic only applies to completed runs.
    trace = _trace(ran=False, events=[])
    assert trace.is_suspiciously_quiet() is False


# ---------------------------------------------------------------------------
# SandboxBackend ABC + classify_skips
# ---------------------------------------------------------------------------


def test_sandbox_backend_is_abstract():
    # Direct instantiation is disallowed — subclasses must implement
    # run() + check_available().
    with pytest.raises(TypeError):
        SandboxBackend()  # type: ignore[abstract]


def test_classify_skips_light_mode_splits_expected_vs_unexpected():
    attempted = {
        SandboxCoverage.SYSCALL_TRACE,  # expected skip for Birdcage
        SandboxCoverage.NETWORK_CAPTURE,  # NOT in floor → unexpected
        SandboxCoverage.FS_WRITES,  # observed
    }
    observed = {SandboxCoverage.FS_WRITES}
    expected, unexpected = SandboxBackend.classify_skips(SandboxMode.LIGHT, observed, attempted)
    assert expected == {SandboxCoverage.SYSCALL_TRACE}
    assert unexpected == {SandboxCoverage.NETWORK_CAPTURE}


def test_classify_skips_strict_mode_treats_all_missing_as_unexpected():
    # Strict mode has an EMPTY floor → anything attempted-but-missing
    # is unexpected and trips observation failure.
    attempted = {SandboxCoverage.SYSCALL_TRACE, SandboxCoverage.DNS}
    observed: set[SandboxCoverage] = set()
    expected, unexpected = SandboxBackend.classify_skips(SandboxMode.STRICT, observed, attempted)
    assert expected == set()
    assert unexpected == {SandboxCoverage.SYSCALL_TRACE, SandboxCoverage.DNS}


# ---------------------------------------------------------------------------
# Codex P1 fix: timeout must trip has_observation_failure (never SAFE on
# truncated observation)
# ---------------------------------------------------------------------------


def test_timeout_run_with_many_events_still_trips_observation_failure():
    """Codex P1: a timed-out run that happens to exceed the floor must
    STILL escalate to NEEDS_REVIEW. Otherwise malicious behavior deferred
    beyond the timeout window rides on the clean observed prefix."""
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=30000,
        timeout=True,  # wall-clock budget exceeded
        events=[
            DynamicTraceEvent(kind=k, ts_ms=i * 100, pid=1, process="sh")
            for i, k in enumerate(("exec", "open", "write", "dns") * 5)
        ],  # 20 events, 4 distinct kinds — normally clears the floor
    )
    assert trace.has_observation_failure() is True


def test_clean_non_timeout_run_with_many_events_does_not_fail():
    """Control: same shape as above but timeout=False → no failure."""
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        duration_ms=30000,
        timeout=False,
        events=[
            DynamicTraceEvent(kind=k, ts_ms=i * 100, pid=1, process="sh")
            for i, k in enumerate(("exec", "open", "write", "dns") * 5)
        ],
    )
    assert trace.has_observation_failure() is False
