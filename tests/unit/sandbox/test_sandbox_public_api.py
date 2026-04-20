"""Smoke tests for the public surface of aigate.sandbox.

Guards against accidental breakage of ``__all__`` — downstream phases
(config.py, policy.py, CLI wiring) import directly from the package
root, so the set of re-exported names is a contract, not an
implementation detail.
"""

from __future__ import annotations

import aigate.sandbox as sandbox

EXPECTED_PUBLIC_NAMES: frozenset[str] = frozenset(
    {
        "SandboxBackend",
        "SandboxCoverage",
        "SandboxMode",
        "DynamicTraceEvent",
        "DynamicTrace",
        "BIRDCAGE_EXPECTED_SKIPS",
        "DOCKER_PLAIN_EXPECTED_SKIPS",
        "DOCKER_PARANOID_EXPECTED_SKIPS",
        "CanaryScheme",
        "generate_canary_scheme",
        "SECRET_ENV_PATTERNS",
        "SECRET_PATTERNS_VERSION",
        "classify_env_name",
        "redact_secrets",
        "SandboxError",
        "SandboxUnavailable",
        "SandboxTimeout",
        "SandboxEscape",
    }
)


def test_all_expected_names_are_exported():
    assert EXPECTED_PUBLIC_NAMES.issubset(set(sandbox.__all__))


def test_every_exported_name_resolves_on_module():
    for name in sandbox.__all__:
        assert hasattr(sandbox, name), f"aigate.sandbox missing {name}"


def test_no_heavy_runtime_imports_at_package_level():
    # Phase 1 scaffold must not transitively import docker / mitmproxy /
    # httpx subprocess shims. ``aigate.cli`` imports the package on
    # every invocation; heavy imports belong in the concrete backend
    # modules (Phase 2+), not here.
    import sys

    forbidden_substrings = ("docker", "mitmproxy", "scapy")
    loaded = set(sys.modules)
    sandbox_loaded = {m for m in loaded if m.startswith("aigate.sandbox")}
    for modname in sandbox_loaded:
        for bad in forbidden_substrings:
            assert bad not in modname, f"{modname} pulls heavy dep {bad!r} at scaffold phase"
