"""Evasion detector: build-time lifecycle hooks (Phase 3 T4).

Detects npm lifecycle scripts (postinstall etc.), Python setup.py subprocess
calls, and Rust build.rs presence. Dynamic detection correlates postinstall
exec events with connect syscalls.
"""

from __future__ import annotations

import json
import re

from ...models import RiskLevel, RiskSignal
from ..types import DynamicTrace
from .base import Detector


class BuildHooksDetector(Detector):
    """Detect lifecycle hooks that execute arbitrary code at install time."""

    CATEGORY = "build_hooks"
    # presence = MEDIUM; network activity during hook escalates via dynamic
    SEVERITY = RiskLevel.MEDIUM

    _LIFECYCLE_HOOK_KEYS = ("preinstall", "install", "postinstall", "prepublish", "prepare")
    _SETUP_PY_EXEC = re.compile(
        r"""(?:os\.system|subprocess\.(?:run|call|Popen|check_output))\s*\("""
    )
    _CARGO_BUILD_RS = "build.rs"  # Rust build script

    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        """Scan source map for lifecycle hook patterns."""
        signals: list[RiskSignal] = []
        for path, content in source_files.items():
            # npm package.json lifecycle scripts
            if path.endswith("package.json"):
                try:
                    pkg = json.loads(content)
                    scripts = pkg.get("scripts", {})
                    for hook in self._LIFECYCLE_HOOK_KEYS:
                        if hook in scripts:
                            signals.append(
                                RiskSignal(
                                    category=self.CATEGORY,
                                    severity=self.SEVERITY,
                                    description=(
                                        f"npm lifecycle hook in {path}: {hook}={scripts[hook][:60]}"
                                    ),
                                )
                            )
                except json.JSONDecodeError:
                    continue
            # Python setup.py with subprocess calls
            if path.endswith("setup.py") and self._SETUP_PY_EXEC.search(content):
                signals.append(
                    RiskSignal(
                        category=self.CATEGORY,
                        severity=self.SEVERITY,
                        description=f"setup.py invokes subprocess: {path}",
                    )
                )
            # Rust build.rs presence
            if path.endswith(self._CARGO_BUILD_RS):
                signals.append(
                    RiskSignal(
                        category=self.CATEGORY,
                        severity=self.SEVERITY,
                        description=f"Rust build script present: {path}",
                    )
                )
        return signals

    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        """Correlate postinstall exec events with connect syscalls.

        If a trace has an exec event whose target mentions 'postinstall' AND
        there is at least one connect event, the hook made a network call —
        escalate by returning the category.
        """
        has_exec = any(
            e.kind == "exec" and "postinstall" in (e.target or "").lower() for e in trace.events
        )
        has_connect = any(e.kind == "connect" for e in trace.events)
        return [self.CATEGORY] if (has_exec and has_connect) else []
