"""Tests: fork-race detector — orphan clone without execve → floor_violation.

Plan §1.4 Scenario 3 (belt-and-braces descendant case):
  A clone(...) = child_pid event with no matching execve(pid=child_pid)
  in the event stream indicates the strace -f tracking may have dropped
  the child.  The post-run detector emits kind="floor_violation" with
  severity=MEDIUM for each orphan.

These tests cover:
- StraceObserver parses clone() → kind="clone" with child_pid in target.
- clone() = -1 (failed) does not produce an event.
- clone3 syscall is also parsed.
- Reference orphan-detector logic: orphan clone → floor_violation MEDIUM.
- Matched clone+execve pair → no violation.
- Mixed: one matched, one orphan → exactly one violation.
- Empty event list → no violations.
"""

from __future__ import annotations

import time

from aigate.sandbox.observers.strace import StraceObserver, parse_strace_logical_event
from aigate.sandbox.types import DynamicTraceEvent, RiskLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line(s: str) -> bytes:
    if not s.endswith("\n"):
        s += "\n"
    return s.encode()


def _ev(line: str):
    ev, _ = parse_strace_logical_event(_line(line), [])
    return ev


def _clone_event(parent_pid: int = 100, child_pid: int = 200, ts_ms: int = 0) -> DynamicTraceEvent:
    return DynamicTraceEvent(
        kind="clone",
        ts_ms=ts_ms or int(time.monotonic() * 1000),
        pid=parent_pid,
        process="",
        target=f"child_pid={child_pid}",
    )


def _exec_event(pid: int, target: str = "/bin/sh") -> DynamicTraceEvent:
    return DynamicTraceEvent(
        kind="exec",
        ts_ms=int(time.monotonic() * 1000),
        pid=pid,
        process="",
        target=target,
    )


def _detect_orphan_clones(
    events: list[DynamicTraceEvent],
) -> list[DynamicTraceEvent]:
    """Reference implementation: orphan clone → floor_violation(MEDIUM).

    Walks the event list; any clone event whose child_pid has no matching
    exec/execve event (by pid) emits a synthetic floor_violation.

    This mirrors the logic that Task 2.6's watchdog/fork-race detector
    implements post-run.
    """
    child_pids_with_exec: set[int] = {e.pid for e in events if e.kind in ("exec", "execve")}
    violations: list[DynamicTraceEvent] = []
    for ev in events:
        if ev.kind != "clone":
            continue
        child_pid: int | None = None
        for part in ev.target.split():
            if part.startswith("child_pid="):
                try:
                    child_pid = int(part.split("=", 1)[1])
                except ValueError:
                    pass
        if child_pid is None:
            continue
        if child_pid not in child_pids_with_exec:
            violations.append(
                DynamicTraceEvent(
                    kind="floor_violation",
                    ts_ms=int(time.monotonic() * 1000),
                    pid=child_pid,
                    process="",
                    target=f"orphan_clone child_pid={child_pid}",
                    severity=RiskLevel.MEDIUM,
                )
            )
    return violations


# ---------------------------------------------------------------------------
# Parser: clone() → kind="clone"
# ---------------------------------------------------------------------------


class TestCloneParsing:
    def test_clone_event_has_kind_clone(self):
        ev = _ev("1234 clone(child_stack=NULL, flags=CLONE_VM|SIGCHLD, ...) = 5678")
        assert ev is not None
        assert ev.kind == "clone"

    def test_clone_event_encodes_child_pid_in_target(self):
        ev = _ev("1234 clone(child_stack=NULL, flags=CLONE_VM, ...) = 5678")
        assert ev is not None
        assert "5678" in ev.target

    def test_clone_event_carries_parent_pid(self):
        ev = _ev("1234 clone(child_stack=NULL, flags=SIGCHLD, ...) = 9999")
        assert ev is not None
        assert ev.pid == 1234

    def test_failed_clone_returns_none(self):
        """clone() = -1 EPERM has no child PID — must not produce an event."""
        ev = _ev(
            "1234 clone(child_stack=NULL, flags=CLONE_VM) = -1 EPERM (Operation not permitted)"
        )
        assert ev is None

    def test_clone3_also_parsed_as_clone(self):
        """clone3 (Linux ≥5.3) uses the same parser path."""
        ev = _ev("1234 clone3({flags=CLONE_VM|SIGCHLD, exit_signal=SIGCHLD, ...}, 88) = 4242")
        assert ev is not None
        assert ev.kind == "clone"
        assert "4242" in ev.target

    def test_clone_child_pid_target_format(self):
        """target must be parseable as 'child_pid=N' by the fork-race detector."""
        ev = _ev("1234 clone(child_stack=NULL, flags=SIGCHLD) = 7777")
        assert ev is not None
        assert ev.target.startswith("child_pid="), (
            f"target must start with 'child_pid='; got: {ev.target!r}"
        )

    def test_instance_parse_event_also_yields_clone(self):
        """StraceObserver.parse_event() (stateful) produces clone events."""
        observer = StraceObserver()
        ev = observer.parse_event(b"1234 clone(child_stack=NULL, flags=SIGCHLD) = 8888\n", [])
        assert ev is not None
        assert ev.kind == "clone"
        assert "8888" in ev.target


# ---------------------------------------------------------------------------
# Fork-race detector
# ---------------------------------------------------------------------------


class TestForkRaceDetector:
    def test_orphan_clone_emits_floor_violation(self):
        """clone(child=42) with no exec(pid=42) → floor_violation."""
        events = [_clone_event(parent_pid=100, child_pid=42)]
        violations = _detect_orphan_clones(events)
        assert len(violations) == 1
        assert violations[0].kind == "floor_violation"
        assert "42" in violations[0].target

    def test_floor_violation_severity_is_medium(self):
        """floor_violation from orphan clone must carry severity=MEDIUM."""
        events = [_clone_event(parent_pid=100, child_pid=42)]
        violations = _detect_orphan_clones(events)
        assert violations[0].severity == RiskLevel.MEDIUM

    def test_clone_with_matching_exec_no_violation(self):
        """Normal fork-exec: clone(child=42) + exec(pid=42) → no violation."""
        events = [_clone_event(100, 42), _exec_event(42)]
        assert _detect_orphan_clones(events) == []

    def test_partial_match_one_violation(self):
        """Two clones; one exec covers child=111 but not child=222 → one violation."""
        events = [
            _clone_event(100, 111),
            _clone_event(100, 222),
            _exec_event(111),
        ]
        violations = _detect_orphan_clones(events)
        assert len(violations) == 1
        assert "222" in violations[0].target

    def test_two_orphan_clones_two_violations(self):
        """Two orphan clones → two floor_violation events."""
        events = [_clone_event(100, 11), _clone_event(100, 22)]
        violations = _detect_orphan_clones(events)
        assert len(violations) == 2

    def test_no_clones_no_violations(self):
        """Trace with no clone events → no violations."""
        events = [
            _exec_event(100),
            DynamicTraceEvent(kind="connect", ts_ms=1, pid=100, process="", target="1.2.3.4:80"),
        ]
        assert _detect_orphan_clones(events) == []

    def test_empty_event_list_no_violations(self):
        assert _detect_orphan_clones([]) == []

    def test_violation_pid_is_child_pid(self):
        """floor_violation.pid should encode the orphan child's PID."""
        events = [_clone_event(parent_pid=1, child_pid=999)]
        violations = _detect_orphan_clones(events)
        assert violations[0].pid == 999
