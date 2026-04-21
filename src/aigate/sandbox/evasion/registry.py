"""Detector registry — explicit list of all 7 Phase 3 detectors."""

from __future__ import annotations

from ...models import RiskSignal
from ..types import DynamicTrace
from .anti_debug import AntiDebugDetector
from .base import Detector
from .build_hooks import BuildHooksDetector
from .derived_exfil import DerivedExfilDetector
from .direct_xpc import DirectXPCDetector
from .env_mutation import EnvMutationDetector
from .parser_partial_drift import ParserPartialDriftDetector
from .time_bomb import TimeBombDetector


def all_detectors() -> list[Detector]:
    """Return a fresh list of detector instances in fixed order."""
    return [
        EnvMutationDetector(),
        TimeBombDetector(),
        BuildHooksDetector(),
        DerivedExfilDetector(),
        DirectXPCDetector(),
        AntiDebugDetector(),
        ParserPartialDriftDetector(),
    ]


def run_static(source_files: dict[str, str]) -> list[RiskSignal]:
    """Run every detector's detect_static; concat results."""
    signals: list[RiskSignal] = []
    for det in all_detectors():
        signals.extend(det.detect_static(source_files))
    return signals


def run_dynamic(trace: DynamicTrace) -> list[str]:
    """Run every detector's detect_dynamic; concat category emissions."""
    cats: list[str] = []
    for det in all_detectors():
        cats.extend(det.detect_dynamic(trace))
    return cats
