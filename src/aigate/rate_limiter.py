"""Simple async rate limiter using sliding window."""

from __future__ import annotations

import asyncio
import time
from types import TracebackType


class RateLimiter:
    """Async context manager that limits calls to max_calls per period_seconds."""

    def __init__(self, max_calls: int = 10, period_seconds: float = 1.0) -> None:
        self._max_calls = max_calls
        self._period = period_seconds
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> RateLimiter:
        if self._period <= 0:
            return self
        async with self._lock:
            now = time.monotonic()
            # Remove timestamps outside the current window
            self._timestamps = [t for t in self._timestamps if now - t < self._period]
            if len(self._timestamps) >= self._max_calls:
                sleep_time = self._period - (now - self._timestamps[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                self._timestamps = self._timestamps[1:]
            self._timestamps.append(time.monotonic())
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass
