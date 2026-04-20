"""aigate sandbox module — dynamic observe-not-deny execution backend (Phase 1 scaffold).

Per PRD v3.1 §3.1, this package will eventually host BirdcageBackend,
DockerBackend, Tracee parsing, evasion detectors, and the decoy+canary
mechanism that turns the sandbox into an OBSERVER rather than a blocker
(v3 P0-1).

Phase 1 scope (this scaffold): types, abstract backend, canary scheme,
secret-redaction patterns, and custom errors. Runtime backends (Birdcage,
Docker) ship in later phases.

IMPORTANT: keep top-level imports lazy / light-weight. This module is
imported by ``aigate.cli`` on every CLI invocation; heavy subprocess or
network imports (docker SDK, mitmproxy, etc.) must live inside the
concrete backend modules, not here.
"""

from __future__ import annotations

from .canary import CanaryScheme, generate_canary_scheme
from .errors import (
    SandboxError,
    SandboxEscape,
    SandboxTimeout,
    SandboxUnavailable,
)
from .secrets import (
    SECRET_ENV_PATTERNS,
    SECRET_PATTERNS_VERSION,
    classify_env_name,
    redact_secrets,
)
from .types import (
    BIRDCAGE_EXPECTED_SKIPS,
    DOCKER_PARANOID_EXPECTED_SKIPS,
    DOCKER_PLAIN_EXPECTED_SKIPS,
    DynamicTrace,
    DynamicTraceEvent,
    SandboxBackend,
    SandboxCoverage,
    SandboxMode,
)

__all__ = [
    # ABC
    "SandboxBackend",
    # Types / enums
    "SandboxCoverage",
    "SandboxMode",
    "DynamicTraceEvent",
    "DynamicTrace",
    # Tier floors
    "BIRDCAGE_EXPECTED_SKIPS",
    "DOCKER_PLAIN_EXPECTED_SKIPS",
    "DOCKER_PARANOID_EXPECTED_SKIPS",
    # Canary
    "CanaryScheme",
    "generate_canary_scheme",
    # Secrets
    "SECRET_ENV_PATTERNS",
    "SECRET_PATTERNS_VERSION",
    "classify_env_name",
    "redact_secrets",
    # Errors
    "SandboxError",
    "SandboxUnavailable",
    "SandboxTimeout",
    "SandboxEscape",
]
