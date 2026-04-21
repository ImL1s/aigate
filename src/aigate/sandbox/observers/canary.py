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

from collections.abc import Sequence

from ..types import DynamicTraceEvent, SandboxCoverage, is_real_event

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Sentinel path opened by the canary harness.
#: MUST match ``strace.OBSERVER_CANARY_MARKER``.
#: Deliberately non-existent on disk — the open() returns ENOENT, but
#: strace captures the ``openat()`` syscall and the parser recognises it.
#:
#: The canary is emitted by BirdcageBackend via a ``sh -c`` wrapper that
#: runs as the first traced child of strace (see
#: ``_run_inside_scratch`` in birdcage_backend.py). The old
#: ``emit_canary_syscall`` sibling-subprocess approach is gone — it was
#: outside strace's ptrace tree and never reached the FIFO (PR #6 P1
#: comment 3117029517 + follow-up 3117386064).
CANARY_PATH: str = "/aigate-observer-canary"


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
