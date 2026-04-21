"""Tests: is_real_event excludes both resource_probe AND observer_canary (REV-B).

REV-B: observer_canary events must be excluded from floor checks, quiet-run
heuristics, and coverage decisions — same as resource_probe (REV-5).

Covers:
- is_real_event() returns False for "resource_probe" and "observer_canary"
- is_real_event() returns True for real events (no source, other source)
- has_observation_failure() floor excludes observer_canary events
- is_suspiciously_quiet() excludes observer_canary events
- No regression on existing resource_probe exclusion behaviour
"""

from __future__ import annotations

from aigate.sandbox.types import DynamicTrace, DynamicTraceEvent, is_real_event

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(kind: str = "open", source: str | None = None) -> DynamicTraceEvent:
    return DynamicTraceEvent(kind=kind, ts_ms=1, pid=1, process="npm", source=source)


def _trace(events: list[DynamicTraceEvent], duration_ms: int = 3000) -> DynamicTrace:
    return DynamicTrace(ran=True, runtime="birdcage", duration_ms=duration_ms, events=events)


# ---------------------------------------------------------------------------
# is_real_event — unit tests
# ---------------------------------------------------------------------------


def test_is_real_event_excludes_resource_probe() -> None:
    assert is_real_event(_event(source="resource_probe")) is False


def test_is_real_event_excludes_observer_canary() -> None:
    assert is_real_event(_event(source="observer_canary")) is False


def test_is_real_event_passes_no_source() -> None:
    assert is_real_event(_event(source=None)) is True


def test_is_real_event_passes_other_source() -> None:
    # An event tagged with an unrecognised source (future extensibility)
    # must not be silently excluded.
    assert is_real_event(_event(source="strace")) is True


def test_is_real_event_passes_empty_string_source() -> None:
    # Empty string is not in the exclusion set — treat as real.
    assert is_real_event(_event(source="")) is True


# ---------------------------------------------------------------------------
# has_observation_failure — observer_canary events excluded from floor
# ---------------------------------------------------------------------------


def test_only_canary_events_floor_unmet() -> None:
    """1 observer_canary event, no real events → floor unmet → failure."""
    trace = _trace([_event(kind="open", source="observer_canary")])
    assert trace.has_observation_failure() is True


def test_canary_plus_resource_probe_floor_unmet() -> None:
    """Mix of synthetic events only → real_events=[] → floor unmet."""
    events = [
        _event(source="observer_canary"),
        _event(source="resource_probe"),
        _event(source="resource_probe"),
    ]
    trace = _trace(events)
    assert trace.has_observation_failure() is True


def test_three_real_kinds_with_canary_meets_floor() -> None:
    """3 real distinct kinds + canary → floor met → no failure."""
    events = [
        _event(kind="exec"),
        _event(kind="open"),
        _event(kind="connect"),
        _event(kind="open", source="observer_canary"),  # canary excluded
    ]
    trace = _trace(events)
    assert trace.has_observation_failure() is False


def test_canary_does_not_pad_event_count_to_floor() -> None:
    """9 canary events + 1 real event = 1 real total, 1 kind → floor unmet."""
    events = [_event(kind="open", source="observer_canary") for _ in range(9)]
    events.append(_event(kind="open"))  # 1 real, 1 kind
    trace = _trace(events)
    assert trace.has_observation_failure() is True


def test_ten_real_events_with_canary_meets_total_floor() -> None:
    """≥10 real events meets total-event floor regardless of kind count."""
    events = [_event(kind="open") for _ in range(10)]
    events.append(_event(kind="open", source="observer_canary"))
    trace = _trace(events)
    assert trace.has_observation_failure() is False


# ---------------------------------------------------------------------------
# is_suspiciously_quiet — observer_canary events excluded
# ---------------------------------------------------------------------------


def test_only_canary_execs_is_quiet() -> None:
    """Canary exec events don't count as real exec → run is quiet."""
    events = [_event(kind="exec", source="observer_canary") for _ in range(5)]
    trace = _trace(events)
    assert trace.is_suspiciously_quiet() is True


def test_real_connect_alongside_canary_is_not_quiet() -> None:
    """1 real connect + canary events → not quiet."""
    events = [
        _event(kind="exec", source="observer_canary"),
        _event(kind="connect"),  # real
    ]
    trace = _trace(events)
    assert trace.is_suspiciously_quiet() is False


# ---------------------------------------------------------------------------
# Regression: resource_probe exclusion still works (REV-5 must not regress)
# ---------------------------------------------------------------------------


def test_resource_probe_still_excluded_from_floor() -> None:
    """Ensure REV-5 resource_probe exclusion is not broken by REV-B changes."""
    events = [_event(kind="exec", source="resource_probe") for _ in range(15)]
    trace = _trace(events)
    # 15 resource_probe events, zero real → floor unmet → failure
    assert trace.has_observation_failure() is True


def test_resource_probe_still_excluded_from_quiet_check() -> None:
    """resource_probe exec events must not make a run appear non-quiet."""
    events = [_event(kind="exec", source="resource_probe") for _ in range(10)]
    trace = _trace(events)
    assert trace.is_suspiciously_quiet() is True
