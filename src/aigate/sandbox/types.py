"""Sandbox data types + abstract backend (PRD v3.1 §3.2).

This module holds the sandbox-local types that other aigate code will
import from ``aigate.sandbox``. The top-level ``aigate.models`` module
gains a thin optional ``dynamic_trace: DynamicTrace | None`` field on
``AnalysisReport`` in a separate task — Phase 1 scaffolds the shapes
first so downstream wiring is unblocked.

Design commitments preserved from Architect req #3 (§3.2):
- ``DynamicTrace`` is a STRUCTURED top-level field. It is never
  flattened into ``prefilter.risk_signals[]``.
- Tier floors (``*_EXPECTED_SKIPS``) are PUBLIC so users + the AI prompt
  know what the sandbox does NOT cover; the ``minimum_observability_floor``
  in ``has_observation_failure()`` is the anti-quiet defense (§3.2 P0-2).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from ..models import RiskLevel

if TYPE_CHECKING:  # avoid runtime circular with canary.py's dataclass
    from .canary import CanaryScheme


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SandboxMode(StrEnum):
    """Canonical sandbox mode names (PRD §3.8).

    ``strict`` supersedes the deprecated ``paranoid`` alias per P2-11;
    callers may still accept ``paranoid`` at the CLI / config boundary
    but MUST normalize to ``strict`` before computing any cache key.
    """

    LIGHT = "light"
    STRICT = "strict"
    DOCKER_RUNSC = "docker+runsc"


class SandboxCoverage(StrEnum):
    """Structured observation-surface enum (PRD §3.2).

    Each value names an independent observation surface a backend may
    or may not provide. Replaces v1's free-form ``coverage_gaps: list[str]``.
    """

    SYSCALL_TRACE = "syscall_trace"  # Tracee (strict/paranoid)
    NETWORK_CAPTURE = "network_capture"  # mitmproxy
    FS_WRITES = "fs_writes"  # fanotify / Tracee / strace
    PROCESS_TREE = "process_tree"  # Tracee / ps polling
    DNS = "dns"  # dnsmasq
    IMPORT_PROBE = "import_probe"  # post-install probe commands
    BUILD_TIME_HOOKS = "build_time_hooks"  # cargo build / setup.py exec
    ENV_READS = "env_reads"  # strace getenv / DTrace
    # macOS-only gap (PRD §3.2 v3.1 E1): hardcoded absolute writes
    # outside $HOME that SBPL-deny silently absorb.
    CANARY_ABSOLUTE_PATH_WRITES = "canary_absolute_path_writes"
    # Coverage gaps that only static scanning can catch (PRD §3.2 v3.1 E2):
    ENV_MUTATION = "env_mutation"
    DIRECT_XPC = "direct_xpc"
    DBUS_RAW = "dbus_raw"
    DERIVED_EXFIL = "derived_exfil"


# ---------------------------------------------------------------------------
# Tier floors — documented, public, NOT verdict-triggering on their own
# ---------------------------------------------------------------------------

BIRDCAGE_EXPECTED_SKIPS: frozenset[SandboxCoverage] = frozenset(
    {
        SandboxCoverage.SYSCALL_TRACE,  # Birdcage is Landlock-only
        SandboxCoverage.PROCESS_TREE,  # no PID-namespace isolation
        SandboxCoverage.ENV_READS,  # no uprobes without root
    }
)

DOCKER_PLAIN_EXPECTED_SKIPS: frozenset[SandboxCoverage] = frozenset()

# Strict mode (Docker + Tracee + mitmproxy) provides every surface.
DOCKER_PARANOID_EXPECTED_SKIPS: frozenset[SandboxCoverage] = frozenset()


# ---------------------------------------------------------------------------
# Events + trace
# ---------------------------------------------------------------------------


# Concrete event kinds the observer is allowed to emit. Kept as a tuple
# of strings (not an enum) so backend-specific parsers can emit new
# kinds without a coordination bump — the AI prompt section handles
# unknown kinds gracefully.
EVENT_KINDS: tuple[str, ...] = (
    "exec",
    "open",
    "connect",
    "dns",
    "write",
    "env_read",
    "sleep",
    "persist_write",
    "canary_read",
    "canary_exfil",
    "floor_violation",
)


@dataclass
class DynamicTraceEvent:
    """Single observed event in a sandbox run (PRD §3.2 dataclass).

    ``target`` and ``raw`` MUST be redaction-clean before this event is
    persisted — see ``sandbox.secrets.redact_secrets``. The observer
    applies redaction at capture time, not at load time, so a stale
    cache entry cannot leak a secret that the current session never
    read.
    """

    kind: str
    ts_ms: int
    pid: int
    process: str
    argv: list[str] = field(default_factory=list)
    target: str = ""
    severity: RiskLevel = RiskLevel.NONE
    raw: str = ""


@dataclass
class DynamicTrace:
    """Result of a sandbox run — consumed structurally by policy.py (§3.2).

    Never flattened: the shape lives all the way through to
    ``policy.decision_from_dynamic_trace()`` (Phase 3 integration).
    """

    ran: bool
    runtime: str
    image_digest: str = ""
    duration_ms: int = 0
    timeout: bool = False
    events: list[DynamicTraceEvent] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    observed: set[SandboxCoverage] = field(default_factory=set)
    skipped_expected: set[SandboxCoverage] = field(default_factory=set)
    skipped_unexpected: set[SandboxCoverage] = field(default_factory=set)
    resource_peak: dict[str, float] = field(default_factory=dict)
    canary: CanaryScheme | None = None
    canary_touches: list[str] = field(default_factory=list)
    error: str | None = None

    # --- Floor / quiet-run heuristics (§3.2 P0-2) -------------------------
    #
    # Concrete floor: ≥3 distinct event kinds OR ≥10 total events for a
    # run that lasted ≥2s. Rationale: even ``npm install lodash`` produces
    # dozens of events; a 2-second run with zero observability is anomalous
    # and must escalate rather than default-SAFE.
    FLOOR_MIN_DISTINCT_KINDS: int = 3
    FLOOR_MIN_TOTAL_EVENTS: int = 10
    FLOOR_APPLIES_IF_DURATION_MS_GTE: int = 2000

    def has_observation_failure(self) -> bool:
        """True iff observation failed OR the floor was not met.

        Only this method — never ``skipped_expected`` alone — should
        flip ``source_unavailable=True`` downstream. Expected-for-tier
        skips are documented coverage gaps, not observation failures.
        """
        if self.skipped_unexpected or self.error is not None:
            return True
        if self.ran and self.duration_ms >= self.FLOOR_APPLIES_IF_DURATION_MS_GTE:
            kinds = {e.kind for e in self.events}
            if (
                len(kinds) < self.FLOOR_MIN_DISTINCT_KINDS
                and len(self.events) < self.FLOOR_MIN_TOTAL_EVENTS
            ):
                return True
        return False

    def is_suspiciously_quiet(self) -> bool:
        """PRD §3.2 P0-2 heuristic.

        A package that produced 0 network + 0 external writes + 0 real
        exec (beyond the single manifest read) during its install run
        is abnormally silent and earns ``suspicious_quiet_run(MEDIUM)``.
        Does NOT by itself downgrade a prefilter-CLEAN SAFE verdict to
        MALICIOUS, but prevents the attacker from gaming "stay in
        expected-skip plane" + "stay below floor" to reach SAFE.
        """
        if not self.ran:
            return False
        has_net = any(e.kind in ("connect", "dns") for e in self.events)
        has_extern_write = any(e.kind in ("write", "persist_write") for e in self.events)
        real_exec_count = sum(1 for e in self.events if e.kind == "exec")
        has_real_exec = real_exec_count > 1
        return not (has_net or has_extern_write or has_real_exec)


# ---------------------------------------------------------------------------
# Backend ABC
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxRunRequest:
    """Input to ``SandboxBackend.run()``.

    Kept minimal at Phase 1; richer fields (per-ecosystem probe args,
    env allowlist, network policy) are Phase 2+. The backend MAY ignore
    fields it does not yet support, but MUST reflect that skip in
    ``DynamicTrace.skipped_expected`` / ``skipped_unexpected`` so the
    caller can decide whether to fail closed.
    """

    package_name: str
    version: str
    ecosystem: str
    source_archive_path: str  # already-resolved tarball / zip on disk
    mode: SandboxMode = SandboxMode.LIGHT
    timeout_s: int = 60
    env_allowlist: tuple[str, ...] = ("HOME", "PATH")


class SandboxBackend(ABC):
    """Abstract sandbox runtime (PRD §3.1 ``base.py``).

    Mirrors the existing ``AIBackend`` ABC convention: ``name`` class
    attribute + an async ``run()`` + a sync ``check_available()`` used
    by ``runtime_select``.
    """

    name: str = "base"

    @abstractmethod
    async def run(self, request: SandboxRunRequest) -> DynamicTrace:
        """Execute the package install inside the sandbox.

        Implementations MUST:
        1. Always return a ``DynamicTrace`` — raising is reserved for
           ``SandboxUnavailable`` / ``SandboxEscape``; timeouts should
           populate ``trace.timeout=True`` and still return.
        2. Apply secret + canary redaction to every captured event
           BEFORE appending it to ``trace.events``.
        3. Stamp ``trace.canary`` with the scheme actually deployed so
           downstream consumers can recompute ``policy_hash``.
        """
        ...

    @abstractmethod
    def check_available(self) -> bool:
        """Cheap preflight: can this backend run on the current host?

        Must NOT start subprocesses / pull images. Used by
        ``runtime_select.detect_available()`` during ``aigate doctor``.
        """
        ...

    # Convenience helpers that concrete backends inherit. Kept small so
    # subclasses don't have to re-implement expected-skip bookkeeping.

    @staticmethod
    def expected_skips_for(mode: SandboxMode) -> frozenset[SandboxCoverage]:
        """Return the publicly-documented tier floor for a mode."""
        if mode == SandboxMode.LIGHT:
            return BIRDCAGE_EXPECTED_SKIPS
        if mode == SandboxMode.STRICT:
            return DOCKER_PARANOID_EXPECTED_SKIPS
        if mode == SandboxMode.DOCKER_RUNSC:
            return DOCKER_PARANOID_EXPECTED_SKIPS
        return frozenset()

    @staticmethod
    def classify_skips(
        mode: SandboxMode,
        observed: Iterable[SandboxCoverage],
        attempted: Iterable[SandboxCoverage],
    ) -> tuple[set[SandboxCoverage], set[SandboxCoverage]]:
        """Split unobserved surfaces into (expected, unexpected).

        ``attempted`` is the set of surfaces the backend TRIED to cover
        on this run. Any surface in ``attempted`` but not in ``observed``
        and not in the tier floor is UNEXPECTED and trips
        ``has_observation_failure()``.
        """
        observed_set = set(observed)
        attempted_set = set(attempted)
        floor = SandboxBackend.expected_skips_for(mode)
        missing = attempted_set - observed_set
        expected = {s for s in missing if s in floor}
        unexpected = {s for s in missing if s not in floor}
        return expected, unexpected
