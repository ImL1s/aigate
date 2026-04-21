"""Drift-aware stuck observer watchdog (Phase 2, REV-A + REV-E).

Detects two distinct stuck conditions:

1. **Fully silent** — both ``events_delta == 0`` AND ``raw_lines_delta == 0``
   for ``timeout_s`` seconds (default 10, configurable via env).
   Indicates the observer subprocess died or never started.

2. **Drift-masked** — ``raw_lines_delta > 0`` AND ``events_delta == 0``
   for ``DRIFT_STUCK_THRESHOLD_S`` seconds (5s).
   Raw bytes are arriving but the parser matches nothing — the observer
   is alive but producing junk, which silently downgrades fail-closed
   posture. Shorter threshold because the signal is unambiguous.

REV-E: ``AIGATE_OBSERVER_STUCK_TIMEOUT_S`` env var overrides the
fully-silent timeout. Clamped to [2, 60] with a default of 10s.

Architecture note (architect non-blocking requirement): the watchdog
runs via ``asyncio.create_task`` in the BirdcageBackend's own event
loop. It is NOT a thread. All shared state (``events_ref``,
``raw_lines_ref``) is accessed from the same coroutine executor —
no locks needed.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_STUCK_TIMEOUT_S: int = 10
STUCK_CLAMP_MIN_S: int = 2
STUCK_CLAMP_MAX_S: int = 60

# Shorter trigger for the drift-masked case: raw bytes arriving but zero
# events parsed is an unambiguous signal, so we escalate faster.
DRIFT_STUCK_THRESHOLD_S: int = 5


# ---------------------------------------------------------------------------
# Env-driven timeout (REV-E)
# ---------------------------------------------------------------------------


def stuck_timeout_from_env() -> int:
    """Read ``AIGATE_OBSERVER_STUCK_TIMEOUT_S`` and return a clamped int.

    Returns ``DEFAULT_STUCK_TIMEOUT_S`` (10) when the variable is unset,
    empty, or non-integer. Clamps the parsed value to [``STUCK_CLAMP_MIN_S``,
    ``STUCK_CLAMP_MAX_S``] (i.e. [2, 60]).
    """
    raw = os.environ.get("AIGATE_OBSERVER_STUCK_TIMEOUT_S")
    if not raw:
        return DEFAULT_STUCK_TIMEOUT_S
    try:
        v = int(raw)
    except (ValueError, TypeError):
        return DEFAULT_STUCK_TIMEOUT_S
    return max(STUCK_CLAMP_MIN_S, min(v, STUCK_CLAMP_MAX_S))


# ---------------------------------------------------------------------------
# Snapshot + watchdog
# ---------------------------------------------------------------------------


@dataclass
class WatchdogSnapshot:
    """Point-in-time counter pair for drift detection."""

    events_count: int
    raw_lines_count: int


class ObserverWatchdog:
    """Drift-aware stuck detector for an async observer.

    Usage (inside BirdcageBackend.run)::

        stop_event = asyncio.Event()
        watchdog = ObserverWatchdog(events, raw_lines, stop_event)
        wdog_task = asyncio.create_task(watchdog.run())
        # ... run the install subprocess ...
        stop_event.set()
        await wdog_task
        if watchdog.stuck:
            trace.skipped_unexpected.add(SandboxCoverage.NETWORK_CAPTURE)

    Parameters
    ----------
    events_ref:
        The live list of ``DynamicTraceEvent`` objects accumulated by the
        parser. The watchdog reads ``len()`` each tick — it never mutates
        the list.
    raw_lines_ref:
        The live list of raw stdout lines emitted by the observer
        subprocess. Same read-only contract.
    stop_event:
        Set this when the install subprocess finishes so the watchdog
        coroutine exits cleanly.
    timeout_s:
        Override the fully-silent timeout.  ``None`` → read from env
        via ``stuck_timeout_from_env()``.
    """

    def __init__(
        self,
        events_ref: list,
        raw_lines_ref: list,
        stop_event: asyncio.Event,
        timeout_s: int | None = None,
    ) -> None:
        self.events_ref = events_ref
        self.raw_lines_ref = raw_lines_ref
        self.stop_event = stop_event
        self.timeout_s = timeout_s if timeout_s is not None else stuck_timeout_from_env()
        self.stuck: bool = False

    async def run(self) -> None:
        """Poll every second until stopped or a stuck condition fires.

        Sets ``self.stuck = True`` and returns early on either:
        - fully silent for ``self.timeout_s`` seconds, OR
        - drift-masked (raw>0 & events==0) for ``DRIFT_STUCK_THRESHOLD_S``.
        """
        last = WatchdogSnapshot(0, 0)
        silent_since: float | None = None
        drift_since: float | None = None

        while not self.stop_event.is_set():
            await asyncio.sleep(1)

            current = WatchdogSnapshot(
                events_count=len(self.events_ref),
                raw_lines_count=len(self.raw_lines_ref),
            )
            events_delta = current.events_count - last.events_count
            raw_delta = current.raw_lines_count - last.raw_lines_count
            now = asyncio.get_event_loop().time()

            # --- Fully silent check (both counters stuck) -----------------
            if events_delta == 0 and raw_delta == 0:
                if silent_since is None:
                    silent_since = now
                elif now - silent_since >= self.timeout_s:
                    self.stuck = True
                    return
            else:
                silent_since = None

            # --- Drift-masked check (raw arriving but parser matches 0) ---
            if raw_delta > 0 and events_delta == 0:
                if drift_since is None:
                    drift_since = now
                elif now - drift_since >= DRIFT_STUCK_THRESHOLD_S:
                    self.stuck = True
                    return
            else:
                drift_since = None

            last = current
