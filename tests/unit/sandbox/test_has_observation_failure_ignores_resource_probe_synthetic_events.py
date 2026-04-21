"""Tests: resource_probe synthetic events are excluded from floor + quiet heuristics.

REV-5: DynamicTraceEvent.source == "resource_probe" must NOT contribute to
has_observation_failure() floor counts or is_suspiciously_quiet() signals.
"""

from __future__ import annotations

from aigate.sandbox import DynamicTrace, DynamicTraceEvent


def _real(kind: str) -> DynamicTraceEvent:
    return DynamicTraceEvent(kind=kind, ts_ms=1, pid=1, process="npm")


def _synthetic(kind: str) -> DynamicTraceEvent:
    return DynamicTraceEvent(kind=kind, ts_ms=1, pid=1, process="probe", source="resource_probe")


def _trace(events: list[DynamicTraceEvent], duration_ms: int = 3000) -> DynamicTrace:
    return DynamicTrace(ran=True, runtime="birdcage", duration_ms=duration_ms, events=events)


# ---------------------------------------------------------------------------
# has_observation_failure — resource_probe exclusion
# ---------------------------------------------------------------------------


def test_only_synthetic_events_floor_unmet():
    # 1 synthetic exec, no real events → real_events=[] → floor unmet → True
    trace = _trace([_synthetic("exec")])
    assert trace.has_observation_failure() is True


def test_one_real_plus_many_synthetics_below_floor():
    # 1 real (1 kind) + 10 synthetics → real=1 event, 1 kind → below floor → True
    events = [_real("open")] + [_synthetic("exec") for _ in range(10)]
    trace = _trace(events)
    assert trace.has_observation_failure() is True


def test_three_real_distinct_kinds_meets_floor():
    # 3 real distinct kinds (exec/open/connect) → floor met → False
    trace = _trace([_real("exec"), _real("open"), _real("connect")])
    assert trace.has_observation_failure() is False


def test_three_real_kinds_plus_many_synthetics_still_meets_floor():
    # Synthetics must not pollute count; 3 distinct real kinds still meets floor
    events = [_real("exec"), _real("open"), _real("connect")] + [
        _synthetic("exec") for _ in range(20)
    ]
    trace = _trace(events)
    assert trace.has_observation_failure() is False


def test_short_run_skips_floor_check():
    # duration_ms < 2000 → floor does not apply regardless of events
    trace = _trace([_synthetic("exec")], duration_ms=500)
    assert trace.has_observation_failure() is False


def test_ten_real_events_one_kind_meets_total_floor():
    # ≥10 total real events satisfies the floor even with 1 kind
    events = [_real("open") for _ in range(10)]
    trace = _trace(events)
    assert trace.has_observation_failure() is False


# ---------------------------------------------------------------------------
# is_suspiciously_quiet — resource_probe exclusion
# ---------------------------------------------------------------------------


def test_quiet_with_only_synthetic_execs():
    # 0 real connects + 10 synthetic execs → synthetics ignored → quiet=True
    events = [_synthetic("exec") for _ in range(10)]
    trace = _trace(events)
    assert trace.is_suspiciously_quiet() is True


def test_real_connect_makes_not_quiet():
    # 1 real connect → has_net=True → not quiet
    events = [_synthetic("exec") for _ in range(10)] + [_real("connect")]
    trace = _trace(events)
    assert trace.is_suspiciously_quiet() is False


def test_real_persist_write_makes_not_quiet():
    events = [_synthetic("exec") for _ in range(5)] + [_real("persist_write")]
    trace = _trace(events)
    assert trace.is_suspiciously_quiet() is False


def test_multiple_real_execs_makes_not_quiet():
    # >1 real exec → has_real_exec=True → not quiet
    events = [_real("exec"), _real("exec")] + [_synthetic("exec") for _ in range(10)]
    trace = _trace(events)
    assert trace.is_suspiciously_quiet() is False


def test_not_ran_is_never_quiet():
    trace = DynamicTrace(ran=False, runtime="birdcage", events=[_synthetic("exec")])
    assert trace.is_suspiciously_quiet() is False
