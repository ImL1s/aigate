"""Evasion detector: time-bomb / temporal gate (Phase 3 T3).

Detects static patterns where code compares the current time against a
hard-coded future epoch or datetime literal, which is a classic technique
for deferring malicious payload execution past security scanning windows.

Dynamic detection watches for unusually long ``sleep()`` calls (>30 s) in
sandbox trace events as a heuristic for timing gates.
"""

from __future__ import annotations

import re
import time

from ...models import RiskLevel, RiskSignal
from ..types import DynamicTrace
from .base import Detector


class TimeBombDetector(Detector):
    """Detect time.time() > future_epoch and datetime.now() > datetime(year>2026)."""

    CATEGORY = "time_bomb"
    SEVERITY = RiskLevel.HIGH

    # Match: time.time() > 1800000000, time.time() >= 1900000000, etc.
    # Current epoch ~1790000000 (Apr 2026).  Only digits without separators are
    # matched; PEP 515 underscore-separated literals (1_850_000_000) are a
    # documented limitation — see test_time_bomb.py::test_pos_mutation_concat.
    _FUTURE_EPOCH = re.compile(
        r"""time\.time\(\)\s*[><]=?\s*(?P<epoch>\d{10,})""",
    )

    # Match: datetime.now() > datetime(2027, ...), datetime.utcnow() >= datetime(2028, ...)
    _FUTURE_DATETIME = re.compile(
        r"""datetime\.(?:now|utcnow)\(\)\s*[><]=?\s*datetime\(\s*(?P<year>\d{4})""",
    )

    # Hard-coded threshold year for predictability across test runs.
    _BOMB_YEAR_THRESHOLD = 2026

    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        """Scan source map for time-bomb patterns."""
        now_epoch = int(time.time())
        signals: list[RiskSignal] = []
        for path, content in source_files.items():
            for m in self._FUTURE_EPOCH.finditer(content):
                if int(m.group("epoch")) > now_epoch:
                    signals.append(
                        RiskSignal(
                            category=self.CATEGORY,
                            severity=self.SEVERITY,
                            description=(
                                f"time.time() gate in {path}: "
                                f"future epoch {m.group('epoch')}"
                            ),
                        )
                    )
            for m in self._FUTURE_DATETIME.finditer(content):
                year = int(m.group("year"))
                if year > self._BOMB_YEAR_THRESHOLD:
                    signals.append(
                        RiskSignal(
                            category=self.CATEGORY,
                            severity=self.SEVERITY,
                            description=(
                                f"datetime gate in {path}: future year {year}"
                            ),
                        )
                    )
        return signals

    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        """Return CATEGORY if any trace event is a sleep longer than 30 seconds."""
        long_sleeps = [
            e
            for e in trace.events
            if e.kind == "sleep" and int(e.target or "0") > 30
        ]
        return [self.CATEGORY] if long_sleeps else []
