"""Unit tests for the T14 policy-layer multi-evasion gate.

CI grep invariants (enforced externally):
  grep -c "categories_from_signals" src/aigate/policy.py  == 2
  grep -c "trace.signatures" src/aigate/policy.py         == 0
"""

from __future__ import annotations

from unittest.mock import patch

from aigate.models import RiskLevel
from aigate.policy import (
    PolicyOutcome,
    _apply_multi_evasion_gate,
    max_verdict,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_categories(pairs: list[tuple[str, RiskLevel]]) -> dict[str, RiskLevel]:
    return dict(pairs)


# ---------------------------------------------------------------------------
# T14 gate rule tests — exact names required by CI grep
# ---------------------------------------------------------------------------


def test_multi_evasion_forces_needs_review_even_with_safe_consensus() -> None:
    """2 MEDIUM categories + SAFE consensus → NEEDS_REVIEW."""
    cats = _make_categories([
        ("env_mutation", RiskLevel.MEDIUM),
        ("time_bomb", RiskLevel.MEDIUM),
    ])
    result = _apply_multi_evasion_gate(PolicyOutcome.SAFE, cats, set())
    assert result == PolicyOutcome.NEEDS_REVIEW


def test_two_high_categories_with_dynamic_confirmation_forces_malicious() -> None:
    """2 HIGH categories + 1 in dynamic_confirmed → MALICIOUS."""
    cats = _make_categories([
        ("env_mutation", RiskLevel.HIGH),
        ("derived_exfil", RiskLevel.HIGH),
    ])
    result = _apply_multi_evasion_gate(PolicyOutcome.SAFE, cats, {"env_mutation"})
    assert result == PolicyOutcome.MALICIOUS


def test_duplicate_fire_of_same_category_does_not_trip_multi_evasion_gate() -> None:
    """env_mutation static + dynamic → dict has {env_mutation: HIGH} (size 1) → no gate trip."""
    # categories_from_signals with duplicate static+dynamic for same category
    # produces a dict with exactly 1 key — size-1 dict never trips the ≥2 gate.
    cats = _make_categories([("env_mutation", RiskLevel.HIGH)])
    # Even with dynamic confirmation, only 1 HIGH category → not ≥2 → no MALICIOUS
    result = _apply_multi_evasion_gate(PolicyOutcome.SAFE, cats, {"env_mutation"})
    # Also not ≥2 medium_or_above → no NEEDS_REVIEW lift either
    assert result == PolicyOutcome.SAFE


def test_medium_floor_does_not_downgrade_malicious_verdict() -> None:
    """MALICIOUS consensus + 2 MEDIUM categories → stays MALICIOUS (monotone-lift, not floor)."""
    cats = _make_categories([
        ("env_mutation", RiskLevel.MEDIUM),
        ("time_bomb", RiskLevel.MEDIUM),
    ])
    result = _apply_multi_evasion_gate(PolicyOutcome.MALICIOUS, cats, set())
    assert result == PolicyOutcome.MALICIOUS


def test_one_high_plus_multiple_medium_with_dynamic_confirm_stays_at_needs_review() -> None:
    """1 HIGH + 2 MEDIUM + HIGH in dynamic_confirmed → NEEDS_REVIEW (NOT MALICIOUS).

    Deliberate tightening (REV-NI2): autonomous blocking requires ≥2 orthogonal
    HIGH tactics. A single HIGH tactic is one hypothesis class; mixed
    HIGH+MEDIUM clusters preserve human-review-in-the-loop.
    """
    cats = _make_categories([
        ("anti_debug", RiskLevel.HIGH),
        ("env_mutation", RiskLevel.MEDIUM),
        ("time_bomb", RiskLevel.MEDIUM),
    ])
    # anti_debug is dynamically confirmed but it's the only HIGH → not ≥2 HIGH → no MALICIOUS
    result = _apply_multi_evasion_gate(PolicyOutcome.SAFE, cats, {"anti_debug"})
    assert result == PolicyOutcome.NEEDS_REVIEW
    assert result != PolicyOutcome.MALICIOUS


def test_darwin_standalone_static_direct_xpc_escalates_safe_to_needs_review() -> None:
    """platform=Darwin patched, dict={direct_xpc: MEDIUM}, NO other categories → NEEDS_REVIEW.

    Step 2 must fire BEFORE the count gate (REV-BS3): a lone direct_xpc at
    MEDIUM would not meet the ≥2 MEDIUM threshold in Step 4, but Step 2
    catches it first.
    """
    cats = _make_categories([("direct_xpc", RiskLevel.MEDIUM)])
    with patch("aigate.policy.platform.system", return_value="Darwin"):
        result = _apply_multi_evasion_gate(PolicyOutcome.SAFE, cats, set())
    assert result == PolicyOutcome.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# Additional invariant tests
# ---------------------------------------------------------------------------


def test_max_verdict_ordering() -> None:
    """max_verdict respects SAFE < NEEDS_REVIEW < MALICIOUS."""
    nr = PolicyOutcome.NEEDS_REVIEW
    mal = PolicyOutcome.MALICIOUS
    safe = PolicyOutcome.SAFE
    assert max_verdict(safe, nr) == nr
    assert max_verdict(nr, mal) == mal
    assert max_verdict(mal, safe) == mal
    assert max_verdict(safe, safe) == safe


def test_darwin_xpc_does_not_fire_on_linux() -> None:
    """Step 2 only fires on Darwin — Linux must fall through to count gates."""
    cats = _make_categories([("direct_xpc", RiskLevel.MEDIUM)])
    with patch("aigate.policy.platform.system", return_value="Linux"):
        result = _apply_multi_evasion_gate(PolicyOutcome.SAFE, cats, set())
    # 1 MEDIUM category → count gate (Step 4) requires ≥2 → no lift → SAFE
    assert result == PolicyOutcome.SAFE


def test_darwin_xpc_does_not_fire_when_other_categories_present() -> None:
    """Step 2 only fires when direct_xpc is the SOLE category (belt-and-braces rule)."""
    cats = _make_categories([
        ("direct_xpc", RiskLevel.MEDIUM),
        ("env_mutation", RiskLevel.MEDIUM),
    ])
    with patch("aigate.policy.platform.system", return_value="Darwin"):
        # dict keys != {"direct_xpc"} alone → Step 2 does NOT fire
        # But Step 4 fires because ≥2 MEDIUM → NEEDS_REVIEW anyway
        result = _apply_multi_evasion_gate(PolicyOutcome.SAFE, cats, set())
    assert result == PolicyOutcome.NEEDS_REVIEW


def test_two_high_no_dynamic_confirmation_stays_at_needs_review() -> None:
    """2 HIGH categories WITHOUT dynamic confirmation → NEEDS_REVIEW via Step 4, not MALICIOUS."""
    cats = _make_categories([
        ("env_mutation", RiskLevel.HIGH),
        ("derived_exfil", RiskLevel.HIGH),
    ])
    result = _apply_multi_evasion_gate(PolicyOutcome.SAFE, cats, set())
    # Step 3 needs dynamic_confirmed ≥ 1 → falls to Step 4 → NEEDS_REVIEW (≥2 medium_or_above)
    assert result == PolicyOutcome.NEEDS_REVIEW


def test_empty_categories_returns_verdict_unchanged() -> None:
    """No evasion categories → verdict passes through all steps unchanged."""
    gate = _apply_multi_evasion_gate
    assert gate(PolicyOutcome.SAFE, {}, set()) == PolicyOutcome.SAFE
    assert gate(PolicyOutcome.NEEDS_REVIEW, {}, set()) == PolicyOutcome.NEEDS_REVIEW
    assert gate(PolicyOutcome.MALICIOUS, {}, set()) == PolicyOutcome.MALICIOUS
