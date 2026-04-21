"""Signal aggregator for evasion detectors (Phase 3 T8-aggregator).

Collapses clusters of same-category LOW/MEDIUM signals at or above
``THRESHOLD_INITIAL`` into a single summary signal.  HIGH and CRITICAL
signals are always preserved individually — aggregation must never hide P0.

See plan §Principle 4 (REV-6 scenario 4 tightening).
"""

from __future__ import annotations

from collections import defaultdict

from ...models import RiskLevel, RiskSignal

# Revisit after Phase 3 merge + 2 weeks of doctor telemetry (F-10).
THRESHOLD_INITIAL: int = 5

# Severity rank for MAX comparison — must not reference MALICIOUS (doesn't exist in RiskLevel).
_SEV_RANK: dict[RiskLevel, int] = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

# Signals at or above this rank are ALWAYS preserved individually (never collapsed).
_HIGH_OR_ABOVE = {RiskLevel.HIGH, RiskLevel.CRITICAL}


def _sev_rank(sev: RiskLevel) -> int:
    return _SEV_RANK.get(sev, 0)


def aggregate_signals(signals: list[RiskSignal]) -> list[RiskSignal]:
    """Collapse clusters of LOW/MEDIUM same-category signals >= THRESHOLD into one.

    Rules (REV-6 scenario 4 — preserves mixed severity):
    - HIGH / CRITICAL signals are ALWAYS preserved individually.
    - LOW / MEDIUM signals with >= THRESHOLD_INITIAL same-category count collapse
      to a single signal tagged at the max severity in the cluster.
    - Never collapses across categories.
    - Never hides a HIGH inside a MEDIUM collapse: if any HIGH/CRITICAL signal is
      present in a category cluster, NO collapse occurs for that category at all —
      all signals in the cluster are preserved individually.

    Returns a NEW list — input is not mutated.
    """
    # Separate HIGH/CRITICAL (always preserved) from collapsible (LOW/MEDIUM).
    high_preserved: list[RiskSignal] = []
    # Track categories that have at least one HIGH/CRITICAL signal.
    high_categories: set[str] = set()

    for sig in signals:
        if sig.severity in _HIGH_OR_ABOVE:
            high_preserved.append(sig)
            high_categories.add(sig.category)

    # Group LOW/MEDIUM by category.
    by_category: dict[str, list[RiskSignal]] = defaultdict(list)
    for sig in signals:
        if sig.severity not in _HIGH_OR_ABOVE:
            by_category[sig.category].append(sig)

    result: list[RiskSignal] = list(high_preserved)

    for cat, group in by_category.items():
        # If this category also has a HIGH/CRITICAL signal, do NOT collapse —
        # preserve all LOW/MEDIUM signals individually to maintain full audit trail.
        if cat in high_categories:
            result.extend(group)
            continue

        if len(group) >= THRESHOLD_INITIAL:
            # Collapse — use max severity across the cluster.
            max_sev = max(group, key=lambda s: _sev_rank(s.severity)).severity
            result.append(
                RiskSignal(
                    category=cat,
                    severity=max_sev,
                    description=(
                        f"multi_evasion_pattern: {len(group)} signals aggregated"
                        " (see doctor --sandbox for breakdown)"
                    ),
                )
            )
        else:
            result.extend(group)

    return result
