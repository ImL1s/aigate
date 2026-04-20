"""Backend selection + observer detection (PRD v3.1 §3.1)."""

from __future__ import annotations

import platform
import shutil
from typing import TYPE_CHECKING

from .errors import SandboxUnavailable
from .types import SandboxBackend, SandboxMode

if TYPE_CHECKING:
    from .birdcage_backend import BirdcageBackend  # noqa: F401 — forward-decl, Task 2

# REV-3 — Linux connect-observer probe order (first available wins)
LINUX_CONNECT_OBSERVER_PROBE_ORDER: tuple[str, ...] = ("birdcage-native", "strace", "bpftrace")


def detect_linux_connect_observer() -> str | None:
    """Return the first available observer name, or None if none.

    birdcage-native is checked via feature probe on the binary itself — stub
    out here and wire up in Task 2 once BirdcageBackend lands.
    """
    for name in LINUX_CONNECT_OBSERVER_PROBE_ORDER:
        if name == "birdcage-native":
            # Placeholder: will call birdcage --version or feature flag check
            # once Task 2 exposes it. For now, skip.
            continue
        if shutil.which(name):
            return name
    return None


def detect_available() -> list[type]:
    """List backend classes whose check_available() returns True.

    Phase 1b ships BirdcageBackend only; Phase 4 adds DockerBackend.
    Import is deferred to avoid a circular at module load.
    """
    backends: list[type] = []
    try:
        from .birdcage_backend import BirdcageBackend  # noqa: PLC0415
    except ImportError:
        return backends
    if BirdcageBackend().check_available():
        backends.append(BirdcageBackend)
    return backends


def select_backend(mode: SandboxMode, required: bool) -> SandboxBackend:
    """Pick the best available backend for the requested mode.

    Fail-closed when ``required=True`` and no backend supports ``mode``.
    Phase 1b ships only ``BirdcageBackend`` (light mode). Strict and
    docker+runsc modes land in Phase 4; until then we must refuse to
    silently downgrade a caller who asked for kernel-enforced strict
    isolation — that was the old bug where ``SandboxMode.STRICT`` routed
    to cooperative Linux-light with no warning (reviewer P1).
    """
    available = detect_available()
    if not available:
        if required:
            obs = detect_linux_connect_observer() if platform.system() == "Linux" else "n/a"
            raise SandboxUnavailable(
                f"No sandbox backend available (Linux connect-observer={obs}). "
                "Install Birdcage via `cargo install birdcage` and, on Linux, "
                "ensure at least one of {strace, bpftrace} is on PATH."
            )
        # required=False — caller must handle None; we still raise for clarity
        raise SandboxUnavailable(
            "No sandbox backend available; sandbox.required=False so caller should fallback."
        )

    # Phase 1b only ships light mode. Anything stricter has no backend yet.
    if mode in (SandboxMode.STRICT, SandboxMode.DOCKER_RUNSC):
        raise SandboxUnavailable(
            f"Sandbox mode {mode.value!r} requires kernel-enforced isolation "
            "(Phase 4 Docker+runsc) which is not yet implemented. "
            "Either switch to --sandbox-mode=light (cooperative + observed on Linux, "
            "sandbox-exec kernel on macOS) or wait for Phase 4."
        )

    return available[0]()
