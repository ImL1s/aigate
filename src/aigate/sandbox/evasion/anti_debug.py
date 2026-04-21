"""Evasion detector: anti-debugging techniques (Phase 3 T5).

Detects static patterns that indicate a package is checking whether it is
being debugged or traced (ptrace, PTRACE_TRACEME, debugger-detection APIs).
Dynamic detection watches for ptrace-related syscall events in strace output.

Anti-debug techniques are used by malicious packages to suppress their
payload when sandboxed or traced, making them appear benign under analysis.
"""

from __future__ import annotations

import re

from ...models import RiskLevel, RiskSignal
from ..types import DynamicTrace
from .base import Detector


class AntiDebugDetector(Detector):
    """Detect anti-debugging and anti-tracing patterns."""

    CATEGORY = "anti_debug"
    SEVERITY = RiskLevel.HIGH

    # ptrace / PTRACE_TRACEME / debugger-detection patterns
    _PTRACE = re.compile(
        r"""(ptrace\s*\(|PTRACE_TRACEME|PTRACE_ATTACH|ctypes.*ptrace|"""
        r"""IsDebuggerPresent|CheckRemoteDebuggerPresent|"""
        r"""/proc/self/status.*TracerPid|TracerPid\s*:\s*[^0])""",
    )

    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        """Scan source map for anti-debug patterns."""
        signals: list[RiskSignal] = []
        for path, content in source_files.items():
            if self._PTRACE.search(content):
                signals.append(
                    RiskSignal(
                        category=self.CATEGORY,
                        severity=self.SEVERITY,
                        description=f"anti-debug/anti-trace pattern in {path}",
                    )
                )
        return signals

    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        """Return CATEGORY if strace shows ptrace syscall events."""
        ptrace_events = [
            e
            for e in trace.events
            if e.kind == "exec" and "ptrace" in (e.target or "").lower()
        ]
        return [self.CATEGORY] if ptrace_events else []
