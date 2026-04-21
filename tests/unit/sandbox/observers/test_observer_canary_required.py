"""Tests: observer canary + classify_network_capture_coverage (Phase 2, REV-B).

REV-B invariant: NETWORK_CAPTURE is only declared ``observed`` when at least
1 real event (non-synthetic, per is_real_event()) appears in the trace.
A canary-only trace (observer alive, package generated zero events) must
still move NETWORK_CAPTURE to skipped_unexpected — fail-closed posture.

Covers:
- zero real events + 1 observer_canary → skipped_unexpected has NETWORK_CAPTURE
- ≥1 real event + canary → observed has NETWORK_CAPTURE
- all-synthetic events (resource_probe + canary) → skipped_unexpected
- emit_canary_syscall: calls subprocess.run with the canary argv (mocked)
- CANARY_PATH matches strace.OBSERVER_CANARY_MARKER (contract check)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aigate.sandbox.observers.canary import (
    CANARY_PATH,
    classify_network_capture_coverage,
    emit_canary_syscall,
)
from aigate.sandbox.types import DynamicTraceEvent, SandboxCoverage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(kind: str = "open", source: str | None = None) -> DynamicTraceEvent:
    return DynamicTraceEvent(kind=kind, ts_ms=1, pid=1, process="npm", source=source)


def _canary_event() -> DynamicTraceEvent:
    return _event(kind="observer_canary", source="observer_canary")


def _real_event(kind: str = "connect") -> DynamicTraceEvent:
    return _event(kind=kind, source=None)


def _probe_event() -> DynamicTraceEvent:
    return _event(kind="exec", source="resource_probe")


# ---------------------------------------------------------------------------
# classify_network_capture_coverage — coverage decision
# ---------------------------------------------------------------------------


def test_zero_real_plus_canary_gives_skipped_unexpected() -> None:
    """REV-B: observer alive (canary present) but zero real events → fail-closed."""
    observed, skipped = classify_network_capture_coverage([_canary_event()])
    assert SandboxCoverage.NETWORK_CAPTURE in skipped
    assert SandboxCoverage.NETWORK_CAPTURE not in observed


def test_one_real_plus_canary_gives_observed() -> None:
    """≥1 real event + canary → observer confirmed live and capturing."""
    observed, skipped = classify_network_capture_coverage([_canary_event(), _real_event()])
    assert SandboxCoverage.NETWORK_CAPTURE in observed
    assert SandboxCoverage.NETWORK_CAPTURE not in skipped


def test_multiple_real_events_plus_canary_gives_observed() -> None:
    """Multiple real events → still observed (additive real evidence)."""
    events = [
        _canary_event(),
        _real_event("exec"),
        _real_event("connect"),
        _real_event("write"),
    ]
    observed, skipped = classify_network_capture_coverage(events)
    assert SandboxCoverage.NETWORK_CAPTURE in observed
    assert SandboxCoverage.NETWORK_CAPTURE not in skipped


def test_zero_real_no_canary_gives_skipped_unexpected() -> None:
    """Empty trace → no evidence observer ran → skipped_unexpected."""
    observed, skipped = classify_network_capture_coverage([])
    assert SandboxCoverage.NETWORK_CAPTURE in skipped
    assert SandboxCoverage.NETWORK_CAPTURE not in observed


def test_all_synthetic_events_gives_skipped_unexpected() -> None:
    """resource_probe + observer_canary only → real_count=0 → fail-closed."""
    events = [_probe_event(), _probe_event(), _canary_event()]
    observed, skipped = classify_network_capture_coverage(events)
    assert SandboxCoverage.NETWORK_CAPTURE in skipped
    assert SandboxCoverage.NETWORK_CAPTURE not in observed


def test_real_events_without_canary_gives_observed() -> None:
    """If real events exist, canary is not required for observed decision."""
    observed, skipped = classify_network_capture_coverage(
        [_real_event("exec"), _real_event("open")]
    )
    assert SandboxCoverage.NETWORK_CAPTURE in observed
    assert SandboxCoverage.NETWORK_CAPTURE not in skipped


def test_coverage_sets_are_disjoint() -> None:
    """observed and skipped_unexpected must never both contain NETWORK_CAPTURE."""
    for events in [
        [],
        [_canary_event()],
        [_real_event()],
        [_canary_event(), _real_event()],
    ]:
        obs, skip = classify_network_capture_coverage(events)
        assert not (
            SandboxCoverage.NETWORK_CAPTURE in obs and SandboxCoverage.NETWORK_CAPTURE in skip
        ), f"Both sets contain NETWORK_CAPTURE for events={events}"


# ---------------------------------------------------------------------------
# emit_canary_syscall — subprocess call (mocked)
# ---------------------------------------------------------------------------


def test_emit_canary_syscall_calls_subprocess_run() -> None:
    """emit_canary_syscall must call subprocess.run with the canary argv."""
    mock_sink = MagicMock()
    with patch("aigate.sandbox.observers.canary.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)  # ENOENT is normal
        emit_canary_syscall(mock_sink)
    mock_run.assert_called_once()
    argv = mock_run.call_args[0][0]
    assert CANARY_PATH in " ".join(argv)


def test_emit_canary_syscall_uses_check_false() -> None:
    """ENOENT is expected — subprocess.run must not raise on non-zero exit."""
    mock_sink = MagicMock()
    with patch("aigate.sandbox.observers.canary.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        emit_canary_syscall(mock_sink)
    _, kwargs = mock_run.call_args
    assert kwargs.get("check") is False


# ---------------------------------------------------------------------------
# Contract: CANARY_PATH must match strace.OBSERVER_CANARY_MARKER
# ---------------------------------------------------------------------------


def test_canary_path_matches_strace_observer_canary_marker() -> None:
    """CANARY_PATH and OBSERVER_CANARY_MARKER must be the same string.

    If they diverge, the canary subprocess opens a path the parser does
    not recognise — the canary silently stops working.  This test fails
    immediately when either constant is changed, forcing a conscious
    co-update.
    """
    try:
        from aigate.sandbox.observers.strace import OBSERVER_CANARY_MARKER
    except ImportError:
        pytest.skip("strace module not yet available (Task 2.2)")
    assert CANARY_PATH == OBSERVER_CANARY_MARKER, (
        f"canary.CANARY_PATH={CANARY_PATH!r} != "
        f"strace.OBSERVER_CANARY_MARKER={OBSERVER_CANARY_MARKER!r}"
    )
