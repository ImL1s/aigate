"""Tests for async rate limiter."""

from __future__ import annotations

import asyncio
import time

from aigate.rate_limiter import RateLimiter


async def test_rate_limiter_respects_limit():
    limiter = RateLimiter(max_calls=3, period_seconds=1.0)
    timestamps: list[float] = []

    async def call():
        async with limiter:
            timestamps.append(time.monotonic())

    tasks = [call() for _ in range(6)]
    await asyncio.gather(*tasks)

    # First 3 should be near-instant, next 3 should be ~1s later
    assert timestamps[3] - timestamps[0] >= 0.9


async def test_rate_limiter_allows_within_limit():
    limiter = RateLimiter(max_calls=10, period_seconds=1.0)
    start = time.monotonic()

    async def call():
        async with limiter:
            pass

    tasks = [call() for _ in range(5)]
    await asyncio.gather(*tasks)

    # All 5 should finish quickly (well within the 10/s limit)
    assert time.monotonic() - start < 0.5


async def test_rate_limiter_zero_period_no_limit():
    """With period=0, no rate limiting is applied."""
    limiter = RateLimiter(max_calls=1, period_seconds=0)
    start = time.monotonic()

    async def call():
        async with limiter:
            pass

    tasks = [call() for _ in range(10)]
    await asyncio.gather(*tasks)
    assert time.monotonic() - start < 0.5
