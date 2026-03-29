"""Compound signal detection — escalate when multiple signal categories appear in one file."""

from __future__ import annotations

COMPOUND_RULES: list[dict] = [
    {
        "id": "exec-plus-cred-theft",
        "description": "Code execution + credential file access in same file",
        "requires_all": ["execution", "credential_access"],
        "min_signals": 2,
        "escalate_to": "medium",
    },
    {
        "id": "exec-plus-exfiltration",
        "description": "Code execution + network exfiltration in same file",
        "requires_all": ["execution", "exfiltration"],
        "min_signals": 2,
        "escalate_to": "high",
    },
    {
        "id": "obfuscation-plus-exfiltration",
        "description": "Obfuscated code + network call in same file",
        "requires_all": ["obfuscation", "exfiltration"],
        "min_signals": 2,
        "escalate_to": "high",
    },
    {
        "id": "full-attack-chain",
        "description": "Execution + credential access + exfiltration",
        "requires_all": ["execution", "credential_access", "exfiltration"],
        "min_signals": 3,
        "escalate_to": "critical",
    },
]

_SEVERITY_LABEL = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}


def check_compound_signals(
    per_file_signals: dict[str, list[dict]],
) -> list[str]:
    """Check for compound signal patterns within individual files.

    Args:
        per_file_signals: Mapping of ``filepath`` to a list of signal dicts.
            Each signal dict must have ``rule_id`` (str) and ``tags`` (list[str]).

    Returns:
        List of compound signal strings (e.g.
        ``"compound(HIGH): 'exec-plus-exfiltration' in steal.py"``).
    """
    results: list[str] = []

    for filepath, signals in per_file_signals.items():
        if len(signals) < 2:
            continue

        # Collect all unique tags across signals in this file
        file_tags: set[str] = set()
        for sig in signals:
            file_tags.update(sig.get("tags", []))

        # Check each compound rule (most specific first = sorted by requires_all length desc)
        matched_ids: set[str] = set()
        for rule in sorted(COMPOUND_RULES, key=lambda r: len(r["requires_all"]), reverse=True):
            required = set(rule["requires_all"])
            if required.issubset(file_tags) and len(signals) >= rule["min_signals"]:
                # Don't add a less-specific rule if a more-specific one already matched this file
                # (e.g. skip exec+cred if full-attack-chain already matched)
                if not any(_is_superset_rule(mid, rule["id"]) for mid in matched_ids):
                    label = _SEVERITY_LABEL.get(rule["escalate_to"], "MEDIUM")
                    results.append(
                        f"compound({label}): '{rule['id']}' in {filepath} — {rule['description']}"
                    )
                    matched_ids.add(rule["id"])

    return results


def _is_superset_rule(existing_id: str, candidate_id: str) -> bool:
    """Check if *existing_id* is a more-specific compound rule than *candidate_id*.

    A rule is more specific if its ``requires_all`` is a strict superset.
    """
    existing = next((r for r in COMPOUND_RULES if r["id"] == existing_id), None)
    candidate = next((r for r in COMPOUND_RULES if r["id"] == candidate_id), None)
    if existing is None or candidate is None:
        return False
    return set(existing["requires_all"]) > set(candidate["requires_all"])
