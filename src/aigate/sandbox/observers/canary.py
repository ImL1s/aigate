"""Observer-canary helpers (Phase 2, REV-B).

The canary works as a parser-liveness proof:

1. BirdcageBackend calls ``emit_canary_syscall(sink)`` just before the
   observed child subprocess starts.
2. A tiny harness subprocess opens ``CANARY_PATH`` (a path that does NOT
   exist on disk → ENOENT).  strace captures the ``openat()`` syscall.
3. ``StraceObserver.parse_event()`` recognises the path and emits
   ``DynamicTraceEvent(kind="observer_canary", source="observer_canary")``.
4. ``classify_network_capture_coverage()`` uses ``is_real_event()`` to
   exclude the canary event from the real-event count, then decides
   whether NETWORK_CAPTURE belongs in ``observed`` or ``skipped_unexpected``.

REV-B invariant: ``real_event_count`` drives the coverage decision.  The
canary event itself is *not* counted as evidence of package activity —
it only demonstrates that the strace parser was alive before the install
started.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence

from ..types import DynamicTraceEvent, SandboxCoverage, is_real_event
from .base import ObserverSink

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Sentinel path opened by the canary harness subprocess.
#: MUST match ``strace.OBSERVER_CANARY_MARKER``.
#: Deliberately non-existent on disk — the open() returns ENOENT, but
#: strace captures the ``openat()`` syscall and the parser recognises it.
CANARY_PATH: str = "/aigate-observer-canary"

_CANARY_ARGV: tuple[str, ...] = (
    "python3",
    "-c",
    f"import os; os.open('{CANARY_PATH}', os.O_RDONLY)",
)


# ---------------------------------------------------------------------------
# Canary emission
# ---------------------------------------------------------------------------


def emit_canary_syscall(sink: ObserverSink) -> None:  # noqa: ARG001
    """Run the canary harness subprocess synchronously.

    The harness attempts ``open(CANARY_PATH, O_RDONLY)``.  The path does
    not exist on disk so the call returns ENOENT, but strace captures the
    ``openat()`` syscall.  ``StraceObserver.parse_event()`` recognises the
    path and tags the event ``source="observer_canary"``.

    **Must be called before the main observed child starts** so the parser
    can confirm liveness before any package-under-test events arrive.
    Runtime: ≈1ms (tiny Python startup + immediate exit on ENOENT).

    ``sink`` is accepted for API consistency with the ``Observer`` contract;
    this implementation does not write to it directly — strace captures the
    syscall through its normal PGID trace.

    Integration (Task 2.5): BirdcageBackend.run() calls this just before
    ``asyncio.create_subprocess_exec(birdcage_argv)``.
    """
    subprocess.run(  # noqa: S603
        _CANARY_ARGV,
        check=False,  # ENOENT from os.open is expected
        capture_output=True,
    )


# ---------------------------------------------------------------------------
# Coverage classification helper (preview for BirdcageBackend wiring)
# ---------------------------------------------------------------------------


def classify_network_capture_coverage(
    events: Sequence[DynamicTraceEvent],
) -> tuple[set[SandboxCoverage], set[SandboxCoverage]]:
    """Compute ``(observed, skipped_unexpected)`` for ``NETWORK_CAPTURE``.

    Uses ``is_real_event()`` to exclude synthetic events
    (``resource_probe``, ``observer_canary``) from the real-event count.

    REV-B rule:

    - ``real_event_count >= 1`` → observer was alive and captured real
      package events → return ``({NETWORK_CAPTURE}, set())``.
    - ``real_event_count == 0`` → observer may never have started, or the
      package generated zero observable events (both are fail-closed) →
      return ``(set(), {NETWORK_CAPTURE})``.

    BirdcageBackend.run() (Task 2.5) calls this after the run completes to
    populate ``trace.observed`` and ``trace.skipped_unexpected``.
    """
    real_count = sum(1 for e in events if is_real_event(e))
    if real_count >= 1:
        return {SandboxCoverage.NETWORK_CAPTURE}, set()
    return set(), {SandboxCoverage.NETWORK_CAPTURE}
