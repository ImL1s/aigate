"""Unit tests for aigate.sandbox.canary (PRD v3.1 §3.2 P0-1).

Locks:
- Every run mints a fresh 128-bit hex token (32 lowercase hex chars).
- Each canary path gets a unique decoy backing file under the per-run
  decoy directory.
- ``CanaryScheme.contains_path`` recognises both exact canary paths
  and anything under a decoy autostart dir.
- ``scheme_version`` is a deliberate integer knob (feeds policy_hash →
  sandbox cache key per §3.8).
"""

from __future__ import annotations

import re

from aigate.sandbox.canary import (
    CANARY_SCHEME_VERSION,
    DEFAULT_CANARY_PATHS,
    DEFAULT_DECOY_AUTOSTART_DIRS,
    DEFAULT_SINKHOLE_DOMAINS,
    CanaryScheme,
    generate_canary_scheme,
)

_HEX32 = re.compile(r"^[0-9a-f]{32}$")


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------


def test_generate_canary_scheme_mints_128_bit_hex_token():
    scheme = generate_canary_scheme()
    assert _HEX32.fullmatch(scheme.run_token), scheme.run_token


def test_two_schemes_get_different_tokens():
    a = generate_canary_scheme()
    b = generate_canary_scheme()
    assert a.run_token != b.run_token


def test_scheme_version_is_declared_integer():
    scheme = generate_canary_scheme()
    assert scheme.scheme_version == CANARY_SCHEME_VERSION
    assert isinstance(scheme.scheme_version, int)


# ---------------------------------------------------------------------------
# Decoy mapping
# ---------------------------------------------------------------------------


def test_every_default_canary_path_gets_a_decoy():
    scheme = generate_canary_scheme()
    for path in DEFAULT_CANARY_PATHS:
        assert path in scheme.canary_paths, f"missing decoy for {path}"


def test_decoy_backing_files_are_unique():
    scheme = generate_canary_scheme()
    backings = list(scheme.canary_paths.values())
    assert len(backings) == len(set(backings)), "decoy backing paths collide"


def test_decoy_root_includes_run_token():
    # Per-run isolation: the decoy directory must embed the token so
    # two concurrent runs cannot clobber each other's canaries.
    scheme = generate_canary_scheme()
    for backing in scheme.canary_paths.values():
        assert scheme.run_token in backing


def test_sinkhole_and_autostart_defaults_propagate():
    scheme = generate_canary_scheme()
    assert scheme.sinkhole_domains == DEFAULT_SINKHOLE_DOMAINS
    assert scheme.decoy_autostart_dirs == DEFAULT_DECOY_AUTOSTART_DIRS


# ---------------------------------------------------------------------------
# contains_path
# ---------------------------------------------------------------------------


def test_contains_path_matches_exact_canary_file():
    scheme = generate_canary_scheme()
    assert scheme.contains_path("~/.ssh/id_rsa") is True


def test_contains_path_matches_nested_autostart_write():
    scheme = generate_canary_scheme()
    assert scheme.contains_path("~/.config/autostart/evil.desktop") is True
    assert scheme.contains_path("~/Library/LaunchAgents/com.evil.plist") is True


def test_contains_path_rejects_unrelated_paths():
    scheme = generate_canary_scheme()
    assert scheme.contains_path("/tmp/totally-benign-file") is False
    assert scheme.contains_path("") is False


def test_empty_scheme_contains_nothing():
    # A default-constructed (no generate) CanaryScheme has empty sets:
    # backends must not assume anything is a canary unless declared.
    scheme = CanaryScheme()
    assert scheme.contains_path("~/.ssh/id_rsa") is False
