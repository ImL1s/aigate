"""Unit tests for Detector ABC and categories_from_signals helper (US-T1)."""

from __future__ import annotations

import pytest

from aigate.models import RiskLevel, RiskSignal
from aigate.sandbox.evasion import Detector, categories_from_signals
from aigate.sandbox.types import DynamicTrace

# ---------------------------------------------------------------------------
# Minimal concrete detector for subclass tests
# ---------------------------------------------------------------------------


class _MinimalDetector(Detector):
    CATEGORY = "test_category"
    SEVERITY = RiskLevel.MEDIUM

    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        return []

    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        return []


# ---------------------------------------------------------------------------
# ABC tests
# ---------------------------------------------------------------------------


def test_detector_abc_cannot_be_instantiated() -> None:
    """Detector ABC raises TypeError on direct instantiation."""
    with pytest.raises(TypeError):
        Detector()  # type: ignore[abstract]


def test_detector_subclass_requires_category_constant() -> None:
    """Subclass without CATEGORY raises (abstract ClassVar missing)."""

    # A subclass that omits CATEGORY but implements abstract methods
    # should still raise because CATEGORY is a required class constant.
    # We enforce this via __init_subclass__ or by checking at instantiation.
    class _NoCategory(Detector):
        # No CATEGORY defined
        def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
            return []

        def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
            return []

    # Instantiation must raise either TypeError (ABC) or AttributeError
    with pytest.raises((TypeError, AttributeError)):
        _NoCategory()


def test_detector_subclass_without_detect_methods_raises() -> None:
    """Subclass missing abstract methods raises TypeError on instantiation."""

    class _NoMethods(Detector):
        CATEGORY = "no_methods"
        # detect_static and detect_dynamic intentionally omitted

    with pytest.raises(TypeError):
        _NoMethods()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# categories_from_signals tests
# ---------------------------------------------------------------------------


def test_categories_from_signals_empty_returns_empty_dict() -> None:
    """categories_from_signals([], []) returns {}."""
    assert categories_from_signals([], []) == {}


def test_categories_from_signals_returns_dict_str_severity() -> None:
    """Result is dict[str, RiskLevel] with correct type annotations."""
    sig = RiskSignal(
        severity=RiskLevel.HIGH,
        category="env_theft",
        description="reads AWS_SECRET_ACCESS_KEY",
    )
    result = categories_from_signals([sig])
    assert isinstance(result, dict)
    assert "env_theft" in result
    assert isinstance(result["env_theft"], RiskLevel)
    assert result["env_theft"] == RiskLevel.HIGH


def test_categories_dict_preserves_max_severity_across_duplicates() -> None:
    """Two signals for the same category at different severities → MAX severity kept."""
    low_sig = RiskSignal(severity=RiskLevel.LOW, category="dns_tunnel", description="low")
    high_sig = RiskSignal(severity=RiskLevel.HIGH, category="dns_tunnel", description="high")

    result = categories_from_signals([low_sig, high_sig])
    assert result["dns_tunnel"] == RiskLevel.HIGH

    # Order should not matter
    result2 = categories_from_signals([high_sig, low_sig])
    assert result2["dns_tunnel"] == RiskLevel.HIGH


def test_categories_from_signals_static_medium_plus_dynamic_high_same_category_promotes() -> None:
    """MAX semantics: static MEDIUM + dynamic (→ MEDIUM) stays MEDIUM; static HIGH stays HIGH."""
    # Case 1: static=MEDIUM, dynamic contributes MEDIUM → result MEDIUM
    sig_med = RiskSignal(severity=RiskLevel.MEDIUM, category="steganography", description="img")
    result = categories_from_signals([sig_med], dynamic_signals=["steganography"])
    assert result["steganography"] == RiskLevel.MEDIUM

    # Case 2: static=HIGH, dynamic also present → stays HIGH (dynamic floor ≤ HIGH)
    sig_high = RiskSignal(severity=RiskLevel.HIGH, category="steganography", description="img")
    result2 = categories_from_signals([sig_high], dynamic_signals=["steganography"])
    assert result2["steganography"] == RiskLevel.HIGH

    # Case 3: dynamic only (no static) → contributes MEDIUM
    result3 = categories_from_signals([], dynamic_signals=["steganography"])
    assert result3["steganography"] == RiskLevel.MEDIUM
