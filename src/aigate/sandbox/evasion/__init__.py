"""aigate.sandbox.evasion — evasion-detector framework (Phase 3).

Re-exports the public API so callers can do::

    from aigate.sandbox.evasion import Detector, categories_from_signals, Severity
"""

from __future__ import annotations

from ...models import RiskLevel, RiskSignal  # noqa: F401
from ..types import DynamicTrace, DynamicTraceEvent  # noqa: F401
from .base import Detector, categories_from_signals
from .registry import all_detectors, run_dynamic, run_static

# Convenience alias matching the task spec re-export name.
Severity = RiskLevel

__all__ = [
    "Detector",
    "categories_from_signals",
    "Severity",
    "all_detectors",
    "run_static",
    "run_dynamic",
    # Re-exported for downstream detector modules
    "DynamicTrace",
    "DynamicTraceEvent",
    "RiskLevel",
    "RiskSignal",
]
