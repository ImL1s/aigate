"""Configuration validation for .aigate.yml."""

from __future__ import annotations

import logging

from .config import Config

logger = logging.getLogger(__name__)

VALID_BACKENDS = {"claude", "codex", "gemini", "ollama", "openai_compat"}
VALID_ECOSYSTEMS = {
    "pypi",
    "npm",
    "pub",
    "crates",  # Rust — Phase 2, opensrc-integration-plan
    "cargo",  # legacy alias for crates
    "cocoapods",  # Phase 3, opensrc-integration-plan
    "pods",  # legacy alias for cocoapods
    "jsr",  # JSR (jsr.io) — Phase 4, opensrc-integration-plan §3.4
    "gem",
    "composer",
    "go",
    "nuget",
    "maven",
}


class ConfigValidationError(ValueError):
    """Raised when config contains invalid values."""


def validate_config(config: Config) -> None:
    """Validate a Config object. Raises ConfigValidationError on invalid values."""
    errors: list[str] = []

    # Validate models
    seen_names: set[str] = set()
    for m in config.models:
        if m.backend not in VALID_BACKENDS:
            errors.append(
                f"Model '{m.name}': invalid backend '{m.backend}'. "
                f"Must be one of: {', '.join(sorted(VALID_BACKENDS))}"
            )
        if not 0.0 <= m.weight <= 1.0:
            errors.append(f"Model '{m.name}': weight {m.weight} out of range [0.0, 1.0]")
        if m.timeout_seconds is not None and m.timeout_seconds < 0:
            errors.append(f"Model '{m.name}': timeout {m.timeout_seconds}s is negative")
        if m.name in seen_names:
            errors.append(f"Duplicate model name: '{m.name}'")
        seen_names.add(m.name)

    # Validate thresholds
    for threshold_field in ("malicious", "suspicious", "disagreement"):
        val = getattr(config.thresholds, threshold_field)
        if not 0.0 <= val <= 1.0:
            errors.append(f"threshold.{threshold_field} = {val} out of range [0.0, 1.0]")

    # Validate ecosystems
    for eco in config.ecosystems:
        if eco not in VALID_ECOSYSTEMS:
            errors.append(
                f"Invalid ecosystem '{eco}'. Must be one of: {', '.join(sorted(VALID_ECOSYSTEMS))}"
            )

    if errors:
        raise ConfigValidationError(
            "Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    # Warnings (non-fatal)
    enabled = [m for m in config.models if m.enabled]
    if not enabled:
        logger.warning("No enabled models in config — AI analysis will be skipped")
