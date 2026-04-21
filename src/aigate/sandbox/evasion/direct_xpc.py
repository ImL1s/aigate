"""Evasion detector: direct XPC / system IPC bypass (Phase 3 T6).

Detects macOS XPC API calls (xpc_connection_create, NSXPCConnection, etc.)
and Linux D-Bus raw IPC patterns.  Both bypass the sandbox by communicating
directly with system services outside the monitored process tree.

Dynamic detection watches for /run/dbus connect events in strace output.
macOS SBPL does not observe XPC — this is a documented observation gap (D5 REV).
Standalone Darwin XPC static fires are escalated by T14 belt-and-braces rule.
"""

from __future__ import annotations

import re

from ...models import RiskLevel, RiskSignal
from ..types import DynamicTrace
from .base import Detector


class DirectXPCDetector(Detector):
    """Detect macOS XPC bypass and Linux D-Bus raw IPC patterns."""

    CATEGORY = "direct_xpc"
    # MEDIUM because macOS SBPL doesn't observe XPC; static hit with Darwin
    # runs should escalate via T14 belt-and-braces rule (REV-BS3).
    SEVERITY = RiskLevel.MEDIUM

    # macOS XPC bypass tokens
    _XPC_TOKENS = re.compile(
        r"""(xpc_connection_create|xpc_connection_create_mach_service|"""
        r"""NSXPCConnection|CFMessagePortCreateRemote|"""
        r"""mach_port_allocate|mach_port_insert_right)""",
    )

    # Linux D-Bus bypass (same category — system IPC)
    _DBUS_RAW = re.compile(
        r"""(dbus\.SessionBus\(\)|dbus\.SystemBus\(\)|org\.freedesktop\.|"""
        r"""GDBusConnection|Gio\.DBus)""",
    )

    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        """Scan source map for XPC and D-Bus bypass patterns."""
        signals: list[RiskSignal] = []
        for path, content in source_files.items():
            if self._XPC_TOKENS.search(content):
                signals.append(
                    RiskSignal(
                        category=self.CATEGORY,
                        severity=self.SEVERITY,
                        description=f"macOS XPC bypass tokens in {path}",
                    )
                )
            if self._DBUS_RAW.search(content):
                signals.append(
                    RiskSignal(
                        category=self.CATEGORY,
                        severity=self.SEVERITY,
                        description=f"Linux D-Bus bypass tokens in {path}",
                    )
                )
        return signals

    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        """Return CATEGORY if strace shows a connect to the D-Bus socket.

        macOS SBPL observes nothing for XPC — known gap (D5 REV).
        """
        dbus_events = [
            e for e in trace.events if e.kind == "connect" and "dbus" in (e.target or "").lower()
        ]
        return [self.CATEGORY] if dbus_events else []
