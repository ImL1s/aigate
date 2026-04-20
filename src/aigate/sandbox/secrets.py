"""Secret-env-var redaction patterns (PRD v3.1 §3.2 P0-5).

Used by the sandbox observer to redact credential values before they
are persisted to ``.omc/logs/sandbox-*.jsonl`` or rendered into an AI
prompt via ``DynamicTrace.to_prompt_section()``.

Rules:
- Env var NAMES matching any pattern here → the var VALUE must NOT be
  logged; only the redaction marker ``<REDACTED:matched=<pattern>>``.
- The signal still fires (``credential_env_read(HIGH)``) so downstream
  policy knows a secret was touched.
- Symmetric rule for ``open()`` on canary-matched paths lives with the
  canary module, not here.

``SECRET_PATTERNS_VERSION`` is folded into ``policy_hash`` (PRD §3.8)
so bumping the tuple naturally invalidates the sandbox output cache.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
# Bump SECRET_PATTERNS_VERSION whenever this tuple changes (addition OR
# removal). Patch-level pattern churn MUST also bump the version so the
# sandbox output cache (§3.8) invalidates — otherwise stale cache entries
# could claim SAFE for a run that would now have flagged a secret read.
SECRET_PATTERNS_VERSION: int = 1

_RAW_SECRET_PATTERNS: tuple[str, ...] = (
    # Generic suffixes
    r".*_TOKEN$",
    r".*_KEY$",
    r".*_SECRET$",
    r".*_PASSWORD$",
    # Cloud vendors
    r"^AWS_.*",
    r"^GITHUB_.*",
    r"^GH_.*",
    # Package registries
    r"^NPM_TOKEN$",
    r"^PYPI_.*",
    r"^CARGO_REGISTRY_TOKEN$",
    # AI providers
    r"^OPENAI_API_KEY$",
    r"^ANTHROPIC_API_KEY$",
    r"^GEMINI_API_KEY$",
    # Comms providers
    r"^SLACK_.*",
    r"^DISCORD_.*",
    r"^TWILIO_.*",
    # Infrastructure
    r"^DATABASE_URL$",
    r"^DB_PASSWORD$",
    r"^REDIS_URL$",
    # Payment / notification
    r"^STRIPE_.*",
    r"^SENDGRID_.*",
)

SECRET_ENV_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p) for p in _RAW_SECRET_PATTERNS
)


def classify_env_name(name: str) -> str | None:
    """Return the first matching secret pattern source string, or None.

    The returned string is the RAW pattern (not the compiled regex) so it
    can be embedded in a redaction marker like
    ``<REDACTED:matched=^AWS_.*>`` without leaking the original var name.
    """
    if not name:
        return None
    for raw, compiled in zip(_RAW_SECRET_PATTERNS, SECRET_ENV_PATTERNS, strict=True):
        if compiled.fullmatch(name) is not None:
            return raw
    return None


def redact_secrets(text: str, scrub_values: Iterable[str]) -> str:
    """Replace every occurrence of every scrub value with a marker.

    Per PRD §3.2 v3.1 E5/T2, the sandbox maintains an in-memory
    ``scrub_set = {canary_tokens} ∪ {read secret values}`` and applies
    this replacement to exec stdout/stderr, argv of spawned processes,
    and content written to decoy bind-mounts BEFORE persisting to logs.

    Implementation is deliberately a simple ``str.replace`` loop — O(n*m)
    is acceptable at realistic scale (<10k events × <20 values × ~256 B)
    per PRD performance note.

    Empty / falsy values are skipped to avoid pathological full-string
    replacement (``"".replace("", X)`` explodes output size).
    """
    if not text or not scrub_values:
        return text
    out = text
    for value in scrub_values:
        if not value:
            continue
        out = out.replace(value, f"<REDACTED:{_classify_value(value)}>")
    return out


def _classify_value(value: str) -> str:
    """Best-effort tag for a scrubbed value (log-only, never loaded back)."""
    # Canary tokens are 128-bit random hex (32+ hex chars, all lowercase).
    if len(value) >= 32 and all(c in "0123456789abcdef" for c in value):
        return "canary"
    return "env-secret"
