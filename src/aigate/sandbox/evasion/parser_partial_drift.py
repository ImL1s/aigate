"""Evasion detector: parser partial drift (Phase 3 T8).

A malicious package could emit strace-like bytes as part of its own
output (e.g., via printf) to confuse our parser.  The Phase 2 watchdog
already catches drift via ``raw_lines>0 AND events==0``, but treating
it as a first-class evasion category (not just a parser-health signal)
lets T14 gate count it toward multi-evasion escalation.

Reuses existing ``SandboxCoverage.PARSER_PARTIAL_DRIFT`` enum from
types.py:72 — no new constant needed.
"""

from __future__ import annotations

from ...models import RiskLevel, RiskSignal
from ..types import DynamicTrace, SandboxCoverage
from .base import Detector


class ParserPartialDriftDetector(Detector):
    """Evasion: strace output deliberately crafted to trip parser drift.

    Static detection is not reliable — parser drift is a runtime observation
    only.  If we find files that look like they print strace-ish output we
    might flag them at low confidence, but that is deferred to a future phase.

    Dynamic detection checks whether ``SandboxCoverage.PARSER_PARTIAL_DRIFT``
    landed in ``trace.skipped_unexpected``, which the Phase 2 observer already
    populates when it sees raw_lines > 0 but events == 0.
    """

    CATEGORY = "parser_partial_drift"
    # MEDIUM: parser drift isn't necessarily malicious, but correlated with
    # evasion — counts toward multi-evasion escalation via T14.
    SEVERITY = RiskLevel.MEDIUM

    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        """Static analysis cannot reliably identify parser drift injection.

        Parser drift is a runtime observation: the malicious package emits
        strace-ish bytes at install time.  No static pattern reliably captures
        this without unacceptable false positives.  Returns empty list always.
        """
        return []

    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        """Return CATEGORY if the observer flagged parser partial drift.

        The Phase 2 observer sets ``SandboxCoverage.PARSER_PARTIAL_DRIFT`` in
        ``trace.skipped_unexpected`` when it detects raw_lines > 0 but
        successfully parsed events == 0, indicating the parser was confused
        by injected strace-like output.
        """
        if SandboxCoverage.PARSER_PARTIAL_DRIFT in trace.skipped_unexpected:
            return [self.CATEGORY]
        return []
