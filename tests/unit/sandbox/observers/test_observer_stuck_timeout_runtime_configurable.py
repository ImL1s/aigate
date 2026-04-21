"""Tests: ObserverWatchdog — drift-aware stuck detection + env timeout (REV-A + REV-E).

REV-E: 5 cases cover ``stuck_timeout_from_env()`` env-var parsing/clamping.
REV-A: behavioral tests cover both stuck conditions (fully silent and
       drift-masked) plus the happy path and REV-J monorepo quiet window.

All async watchdog tests mock ``asyncio.sleep`` (via the watchdog module's
own ``asyncio`` reference) so they run in microseconds rather than real
seconds. ``asyncio.get_event_loop().time()`` is similarly mocked to return
a controlled counter — this keeps time deterministic without touching the
real pytest-asyncio event loop.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aigate.sandbox.observers.watchdog import (
    DEFAULT_STUCK_TIMEOUT_S,
    DRIFT_STUCK_THRESHOLD_S,
    STUCK_CLAMP_MAX_S,
    STUCK_CLAMP_MIN_S,
    ObserverWatchdog,
    stuck_timeout_from_env,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_asyncio(tick: list[float]) -> Any:
    """Build a mock asyncio namespace with a time-advancing fake_sleep.

    ``tick`` is a single-element list so mutations are shared across closures.
    Returns (mock_asyncio, fake_sleep_coroutine_function).
    """
    mock_asyncio = MagicMock()

    async def fake_sleep(_: float) -> None:
        tick[0] += 1.0

    mock_asyncio.sleep = AsyncMock(side_effect=fake_sleep)
    mock_asyncio.get_running_loop.return_value.time.side_effect = lambda: tick[0]
    return mock_asyncio


# ---------------------------------------------------------------------------
# REV-E: stuck_timeout_from_env() — 5 parameterised cases
# ---------------------------------------------------------------------------


def test_default_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AIGATE_OBSERVER_STUCK_TIMEOUT_S", raising=False)
    assert stuck_timeout_from_env() == DEFAULT_STUCK_TIMEOUT_S


def test_env_30_returns_30(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIGATE_OBSERVER_STUCK_TIMEOUT_S", "30")
    assert stuck_timeout_from_env() == 30


def test_env_1_clamped_to_min(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIGATE_OBSERVER_STUCK_TIMEOUT_S", "1")
    assert stuck_timeout_from_env() == STUCK_CLAMP_MIN_S


def test_env_120_clamped_to_max(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIGATE_OBSERVER_STUCK_TIMEOUT_S", "120")
    assert stuck_timeout_from_env() == STUCK_CLAMP_MAX_S


def test_env_invalid_string_returns_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIGATE_OBSERVER_STUCK_TIMEOUT_S", "notanumber")
    assert stuck_timeout_from_env() == DEFAULT_STUCK_TIMEOUT_S


# ---------------------------------------------------------------------------
# REV-A: watchdog behavioral tests
# ---------------------------------------------------------------------------


async def test_watchdog_fires_on_fully_silent() -> None:
    """Both counters frozen for timeout_s → watchdog fires (fully-silent branch)."""
    events: list = []
    raw_lines: list = []
    stop = asyncio.Event()
    tick = [0.0]

    watchdog = ObserverWatchdog(events, raw_lines, stop, timeout_s=3)
    mock_asyncio = _make_fake_asyncio(tick)

    with patch("aigate.sandbox.observers.watchdog.asyncio", mock_asyncio):
        await watchdog.run()

    # Ticks: 1 (silent_since=1), 2 (delta=1, no fire), 3 (delta=2, no fire),
    # 4 (delta=3 >= timeout_s=3) → stuck
    assert watchdog.stuck is True


async def test_watchdog_fires_drift_masked() -> None:
    """raw_lines grows each tick but events never grow → drift-masked fire.

    DRIFT_STUCK_THRESHOLD_S = 5 so the watchdog fires after 5 ticks of
    raw>0 & events==0.
    """
    events: list = []
    raw_lines: list = []
    stop = asyncio.Event()
    tick = [0.0]
    call_count = [0]

    async def fake_sleep_raw(_: float) -> None:
        tick[0] += 1.0
        call_count[0] += 1
        raw_lines.append(f"unparsed line {call_count[0]}")

    mock_asyncio = MagicMock()
    mock_asyncio.sleep = AsyncMock(side_effect=fake_sleep_raw)
    mock_asyncio.get_running_loop.return_value.time.side_effect = lambda: tick[0]

    # timeout_s set high so fully-silent branch never fires first
    watchdog = ObserverWatchdog(events, raw_lines, stop, timeout_s=30)

    with patch("aigate.sandbox.observers.watchdog.asyncio", mock_asyncio):
        await watchdog.run()

    # After DRIFT_STUCK_THRESHOLD_S ticks of raw>0 & events==0: stuck
    assert watchdog.stuck is True
    assert call_count[0] == DRIFT_STUCK_THRESHOLD_S + 1  # fires on tick 6


async def test_watchdog_stays_quiet_when_events_flow() -> None:
    """Happy path: new event every tick → watchdog never fires."""
    events: list = []
    raw_lines: list = []
    stop = asyncio.Event()
    tick = [0.0]
    call_count = [0]

    async def fake_sleep_events(_: float) -> None:
        tick[0] += 1.0
        call_count[0] += 1
        events.append(object())  # 1 new event per tick
        if call_count[0] >= 15:
            stop.set()

    mock_asyncio = MagicMock()
    mock_asyncio.sleep = AsyncMock(side_effect=fake_sleep_events)
    mock_asyncio.get_running_loop.return_value.time.side_effect = lambda: tick[0]

    watchdog = ObserverWatchdog(events, raw_lines, stop, timeout_s=3)

    with patch("aigate.sandbox.observers.watchdog.asyncio", mock_asyncio):
        await watchdog.run()

    assert watchdog.stuck is False


async def test_watchdog_stays_quiet_for_monorepo_45s_quiet_window() -> None:
    """REV-J: events arrive every 8 virtual-seconds with a 10s timeout.

    A monorepo npm install can go 30–40s between write events during the
    npm dependency resolution phase. The watchdog must NOT fire as long as
    *some* progress appears within the timeout window. Here events arrive
    every 8 ticks < timeout_s=10 → watchdog stays quiet for the full 45-tick
    virtual run.
    """
    events: list = []
    raw_lines: list = []
    stop = asyncio.Event()
    tick = [0.0]
    call_count = [0]

    async def fake_sleep_intermittent(_: float) -> None:
        tick[0] += 1.0
        call_count[0] += 1
        # New event every 8 ticks — well within the 10s timeout
        if call_count[0] % 8 == 0:
            events.append(object())
        if call_count[0] >= 45:
            stop.set()

    mock_asyncio = MagicMock()
    mock_asyncio.sleep = AsyncMock(side_effect=fake_sleep_intermittent)
    mock_asyncio.get_running_loop.return_value.time.side_effect = lambda: tick[0]

    watchdog = ObserverWatchdog(events, raw_lines, stop, timeout_s=DEFAULT_STUCK_TIMEOUT_S)

    with patch("aigate.sandbox.observers.watchdog.asyncio", mock_asyncio):
        await watchdog.run()

    # 45 virtual seconds, events every 8s, timeout=10s → never stuck
    assert watchdog.stuck is False
    assert call_count[0] == 45
