"""REV-G: Document and verify strace initial-attach semantics preclude
pre-PTRACE-stop syscalls in the traced child.

From strace(1) man page and strace.c::startup_child (strace ≥5.x):

  When invoked as ``strace -- cmd``, strace calls fork().  The child calls
  ptrace(PTRACE_TRACEME) BEFORE execve().  The kernel guarantees that once
  PTRACE_TRACEME is set, the next execve() itself generates a SIGTRAP (or
  PTRACE_EVENT_EXEC with PTRACE_O_TRACEEXEC), causing the child to stop
  *inside* the execve syscall, before the new program's first instruction
  runs.  strace receives the stop, then PTRACE_SYSCALL-resumes.

  Therefore: **no syscall in the new program can execute before strace
  observes it**.  The pre-stop-window concern is precluded by initial-attach
  semantics.

This module:
1. Asserts argv_prefix uses ``--`` exec mode (not ``-p PID`` attach mode).
2. Asserts -f is present for PTRACE_O_TRACECLONE descendant coverage.
3. Asserts execve tracing so the fork-race detector has exec events.
4. Documents the formal invariant in test_no_pre_stop_window_by_construction.

References:
  - strace(1) §DESCRIPTION — "If -p is given strace attaches to the running
    processes with PTRACE_ATTACH ... otherwise forks a traced child."
  - strace source: strace.c::startup_child(), ~line 680 (strace 6.8 tarball)
  - Linux kernel: arch/x86/kernel/ptrace.c ptrace_event(PTRACE_EVENT_EXEC)
"""

from __future__ import annotations

from aigate.sandbox.observers.base import FifoSink
from aigate.sandbox.observers.strace import StraceObserver

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _argv() -> list[str]:
    observer = StraceObserver()
    return observer.argv_prefix(FifoSink("/tmp/test.fifo"))


# ---------------------------------------------------------------------------
# Exec-mode assertion (no -p attach)
# ---------------------------------------------------------------------------


def test_argv_prefix_uses_exec_semantics_not_attach():
    """strace argv must use ``-- cmd`` exec mode, NOT ``-p PID`` attach mode.

    Exec mode: strace forks, child calls ptrace(PTRACE_TRACEME) then execve.
    The kernel stops the child inside execve before any instruction executes.

    Attach mode (-p PID): strace attaches after the target is already running.
    A window exists between process start and attach where syscalls run
    unobserved — exactly the pre-stop-window Scenario 3 identifies.

    Citation: strace(1) man page §DESCRIPTION; strace.c::startup_child.
    """
    argv = _argv()
    assert "-p" not in argv, (
        "argv must not contain '-p' (attach mode). Attach mode leaves a "
        "pre-stop window between process start and ptrace attachment. "
        "Use exec mode ('-- cmd') so PTRACE_TRACEME is called before execve."
    )
    assert argv[-1] == "--", (
        "argv_prefix must end with '--' to enforce strace exec-mode semantics. "
        "The child calls ptrace(PTRACE_TRACEME) before execve(), ensuring the "
        "kernel stops the child inside execve with no pre-stop window."
    )
    assert argv[0] == "strace"


def test_argv_prefix_has_minus_f_for_clone_tracing():
    """-f (follow forks) enables PTRACE_O_TRACECLONE for child coverage.

    Without -f, strace does not trace child processes created by birdcage.
    REV-C teardown also relies on -f: os.killpg(observer_pgid) cascades to
    all PTRACE_O_TRACECLONE-tracked children.
    """
    argv = _argv()
    assert "-f" in argv, "strace argv must include -f (follow forks / PTRACE_O_TRACECLONE)"


def test_argv_prefix_traces_execve_for_descendant_coverage():
    """execve must be in -e trace= so descendant exec chains are observable.

    The fork-race detector (Task 2.6) matches clone events against execve
    events by child PID.  Without execve tracing, every fork is an orphan
    and spurious floor_violation events are emitted.
    """
    argv = _argv()
    e_idx = argv.index("-e")
    trace_arg = argv[e_idx + 1]
    assert "execve" in trace_arg, (
        f"execve must be in -e trace= list; got: {trace_arg!r}"
    )


def test_argv_prefix_traces_clone_for_fork_race_detector():
    """clone must be in -e trace= so the fork-race detector has child PIDs."""
    argv = _argv()
    e_idx = argv.index("-e")
    trace_arg = argv[e_idx + 1]
    assert "clone" in trace_arg, (
        f"clone must be in -e trace= list; got: {trace_arg!r}"
    )


def test_argv_prefix_traces_connect_for_network_capture():
    """connect must be in -e trace= for NETWORK_CAPTURE coverage."""
    argv = _argv()
    e_idx = argv.index("-e")
    trace_arg = argv[e_idx + 1]
    assert "connect" in trace_arg


def test_argv_prefix_traces_openat_for_fs_writes():
    """openat must be in -e trace= for FS_WRITES coverage."""
    argv = _argv()
    e_idx = argv.index("-e")
    trace_arg = argv[e_idx + 1]
    assert "openat" in trace_arg


# ---------------------------------------------------------------------------
# Formal invariant: no pre-stop window by construction
# ---------------------------------------------------------------------------


def test_no_pre_stop_window_by_construction():
    """Formal assertion: initial-attach semantics preclude pre-stop syscalls.

    strace ``-- cmd`` exec flow per strace(1) + strace.c::startup_child():

      strace fork()
      ├── child: ptrace(PTRACE_TRACEME)    # BEFORE execve()
      │          execve("birdcage", ...)   # kernel emits SIGTRAP → child stops
      │                                   # INSIDE execve, before first instruction
      └── parent: receives SIGTRAP stop
                  ptrace(PTRACE_SYSCALL) → resumes child

    Consequence: the first instruction of the new program runs only AFTER
    strace has set PTRACE_SYSCALL delivery.  No syscall can execute before
    the first PTRACE_SYSCALL stop — there is no pre-stop window.

    This test asserts the observable preconditions (argv shape) that make
    the guarantee hold, and documents why each condition is necessary.
    """
    argv = _argv()

    # Precondition 1: exec mode, not attach mode
    has_exec_mode = argv[-1] == "--"
    # Precondition 2: follow-forks for descendant coverage
    has_follow_forks = "-f" in argv
    # Precondition 3: execve tracing for fork-race detector
    e_idx = argv.index("-e")
    trace_arg = argv[e_idx + 1]
    has_execve_tracing = "execve" in trace_arg

    assert has_exec_mode, (
        "exec mode ('--') required for ptrace(PTRACE_TRACEME)-before-execve guarantee"
    )
    assert has_follow_forks, "-f required for PTRACE_O_TRACECLONE child coverage"
    assert has_execve_tracing, "execve tracing required for descendant fork-race detection"
