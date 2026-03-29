"""YAML rule loader — reads builtin + user rule files, merges by ID."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"


@dataclass
class Rule:
    """A single detection rule loaded from YAML."""

    id: str
    pattern: re.Pattern  # type: ignore[type-arg]
    severity: str  # low, medium, high, critical
    scope: str  # install_script, source, any
    ecosystem: str  # "*" or specific like "pypi", "npm"
    description: str
    tags: list[str] = field(default_factory=list)
    case_sensitive: bool = False


def load_rules(
    builtin_dir: Path | None = None,
    user_dir: Path | None = None,
    ecosystem: str | None = None,
    disable_rules: list[str] | None = None,
) -> list[Rule]:
    """Load rules from builtin + user directories.

    User rules override builtin by matching ``id``.
    Invalid YAML files are skipped with a warning.

    Args:
        builtin_dir: Directory containing built-in YAML rule files.
        user_dir: Optional directory with user-provided overrides.
            Defaults to ``~/.aigate/rules/`` when not provided and that dir exists.
        ecosystem: If given, only return rules matching this ecosystem or ``"*"``.
        disable_rules: Rule IDs to exclude from the result.

    Returns:
        Merged list of Rule objects.
    """
    if builtin_dir is None:
        builtin_dir = BUILTIN_DIR

    rules_by_id: dict[str, Rule] = {}

    # Load builtin first
    _load_dir(builtin_dir, rules_by_id)

    # User rules override builtin by id
    if user_dir is not None:
        _load_dir(user_dir, rules_by_id)

    rules = list(rules_by_id.values())

    # Filter by ecosystem if requested
    if ecosystem is not None:
        rules = [r for r in rules if r.ecosystem == "*" or r.ecosystem == ecosystem]

    # Filter out disabled rules
    if disable_rules:
        disabled = set(disable_rules)
        rules = [r for r in rules if r.id not in disabled]

    return rules


def _load_dir(directory: Path, rules_by_id: dict[str, Rule]) -> None:
    """Load all YAML files from *directory* into *rules_by_id*."""
    if not directory.is_dir():
        logger.warning("Rules directory does not exist: %s", directory)
        return

    for yml_path in sorted(directory.glob("*.yml")):
        try:
            _load_file(yml_path, rules_by_id)
        except Exception:
            logger.warning("Skipping invalid rule file: %s", yml_path, exc_info=True)


def _load_file(path: Path, rules_by_id: dict[str, Rule]) -> None:
    """Parse a single YAML rule file and merge into *rules_by_id*."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "rules" not in data:
        logger.warning("No 'rules' key in %s — skipping", path)
        return

    for entry in data["rules"]:
        try:
            is_case_sensitive = entry.get("case_sensitive", False)
            flags = 0 if is_case_sensitive else re.IGNORECASE
            rule = Rule(
                id=entry["id"],
                pattern=re.compile(entry["pattern"], flags),
                severity=entry["severity"],
                scope=entry["scope"],
                ecosystem=entry.get("ecosystem", "*"),
                description=entry.get("description", ""),
                tags=entry.get("tags", []),
                case_sensitive=is_case_sensitive,
            )
            rules_by_id[rule.id] = rule
        except (KeyError, re.error) as exc:
            logger.warning("Skipping invalid rule entry in %s: %s", path, exc)
