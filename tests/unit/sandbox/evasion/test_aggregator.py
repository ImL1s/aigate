"""Unit tests for the evasion signal aggregator (Phase 3 T8-aggregator)."""

from __future__ import annotations

from aigate.models import RiskLevel, RiskSignal
from aigate.sandbox.evasion.aggregator import THRESHOLD_INITIAL, aggregate_signals


def _make(category: str, severity: RiskLevel, n: int = 1) -> list[RiskSignal]:
    return [
        RiskSignal(category=category, severity=severity, description=f"signal-{i}")
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# HIGH signals are always preserved individually
# ---------------------------------------------------------------------------


def test_aggregator_preserves_high_severity_individually() -> None:
    """5 HIGH same-category signals → all 5 preserved, no collapse."""
    signals = _make("anti_debug", RiskLevel.HIGH, THRESHOLD_INITIAL)
    result = aggregate_signals(signals)
    assert len(result) == THRESHOLD_INITIAL
    assert all(s.severity == RiskLevel.HIGH for s in result)
    assert all(s.category == "anti_debug" for s in result)


# ---------------------------------------------------------------------------
# MEDIUM cluster at threshold collapses
# ---------------------------------------------------------------------------


def test_aggregator_collapses_medium_cluster_at_threshold() -> None:
    """5 MEDIUM same-category signals → collapsed to 1 summary signal."""
    signals = _make("env_mutation", RiskLevel.MEDIUM, THRESHOLD_INITIAL)
    result = aggregate_signals(signals)
    assert len(result) == 1
    assert result[0].category == "env_mutation"
    assert result[0].severity == RiskLevel.MEDIUM
    assert "aggregated" in result[0].description


# ---------------------------------------------------------------------------
# Below threshold — no collapse
# ---------------------------------------------------------------------------


def test_aggregator_does_not_collapse_below_threshold() -> None:
    """4 MEDIUM same-category signals (< THRESHOLD_INITIAL=5) → 4 preserved."""
    signals = _make("time_bomb", RiskLevel.MEDIUM, THRESHOLD_INITIAL - 1)
    result = aggregate_signals(signals)
    assert len(result) == THRESHOLD_INITIAL - 1
    assert all(s.category == "time_bomb" for s in result)


# ---------------------------------------------------------------------------
# Mixed severity cluster — HIGH preserved + MEDIUM kept individually
# ---------------------------------------------------------------------------


def test_aggregator_preserves_mixed_severity_cluster() -> None:
    """4 MEDIUM + 1 HIGH same-category → HIGH preserved + 4 MEDIUM kept individually.

    No collapse occurs because a HIGH signal is present in the cluster.
    Threshold is on MEDIUM-only clusters; HIGH is hoisted out first, and its
    presence prevents collapsing the remaining MEDIUM signals.
    """
    medium_signals = _make("derived_exfil", RiskLevel.MEDIUM, THRESHOLD_INITIAL - 1)
    high_signal = _make("derived_exfil", RiskLevel.HIGH, 1)
    signals = medium_signals + high_signal
    result = aggregate_signals(signals)

    # All 5 signals preserved — no collapse.
    assert len(result) == THRESHOLD_INITIAL
    highs = [s for s in result if s.severity == RiskLevel.HIGH]
    mediums = [s for s in result if s.severity == RiskLevel.MEDIUM]
    assert len(highs) == 1
    assert len(mediums) == THRESHOLD_INITIAL - 1
    # Ensure no aggregated summary signal was produced.
    assert not any("aggregated" in s.description for s in result)
