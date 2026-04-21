"""Detector ABC and categories_from_signals helper (Phase 3 T1).

All concrete evasion detectors inherit from ``Detector`` and register
themselves by implementing ``CATEGORY`` + the two abstract methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from ...models import RiskLevel, RiskSignal
from ..types import DynamicTrace


class Detector(ABC):
    """Abstract base for every evasion-category detector (Phase 3).

    Contract
    --------
    - ``CATEGORY`` is a snake_case string that MUST be unique across all
      registered detectors.  It is used as the ``category`` attribute on
      every ``RiskSignal`` this detector emits and as the key in the
      ``dict[str, RiskLevel]`` returned by ``categories_from_signals``.
    - ``SEVERITY`` is the default severity level; concrete detectors may
      override it.
    - ``detect_static`` scans source text; ``detect_dynamic`` inspects a
      completed ``DynamicTrace``.
    """

    CATEGORY: ClassVar[str]
    SEVERITY: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    def __init__(self) -> None:
        # Enforce CATEGORY at instantiation time.  We check the MRO for an
        # actual *value* (not just an annotation) so a subclass that inherits
        # only the bare ClassVar[str] annotation from Detector — which carries
        # no runtime value — still raises.
        for klass in type(self).__mro__:
            if klass is Detector:
                # Reached the base without finding a concrete value.
                raise AttributeError(f"{type(self).__name__} must define a CATEGORY class constant")
            if "CATEGORY" in klass.__dict__:
                break  # concrete value found — all good

    @abstractmethod
    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        """Scan source map ``{path: content}``; return RiskSignals tagged with self.CATEGORY."""
        ...

    @abstractmethod
    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        """Inspect DynamicTrace; return list of category strings.

        Each returned string MUST equal ``self.CATEGORY`` (or the list may be empty).
        """
        ...


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[RiskLevel, int] = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def _max_severity(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


def categories_from_signals(
    static_signals: list[RiskSignal],
    dynamic_signals: list[str] | None = None,
) -> dict[str, RiskLevel]:
    """Build ``{category: max_severity}`` from static + dynamic signals.

    Uses ``signal.category`` + ``signal.severity`` attributes (``RiskSignal``
    is structured — never parse ``str(signal)``).  Dynamic signals are plain
    strings (category names) and contribute at ``MEDIUM`` severity (dynamic
    presence = MEDIUM floor unless static already pairs it at ``HIGH`` or
    above).

    Returns ``{}`` for empty inputs — never raises.

    Semantics: for each category, ``result[cat] = max(result.get(cat, LOW),
    signal.severity)`` using the ordering
    ``CRITICAL > HIGH > MEDIUM > LOW > NONE``.
    """
    result: dict[str, RiskLevel] = {}

    for sig in static_signals or []:
        cat = sig.category
        result[cat] = _max_severity(result.get(cat, RiskLevel.LOW), sig.severity)

    for cat in dynamic_signals or []:
        # Dynamic presence contributes at MEDIUM; static MAX wins if higher.
        result[cat] = _max_severity(result.get(cat, RiskLevel.LOW), RiskLevel.MEDIUM)

    return result
