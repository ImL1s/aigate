"""Birdcage subprocess wrapper (PRD v3.1 §3.1, Phase 1b).

License boundary: Birdcage is GPL-3.0. We call it as a subprocess only —
no imports, no linking, no bundled binary. The user installs birdcage
themselves (``cargo install birdcage``).
"""

from __future__ import annotations

import platform
import shutil

from .runtime_select import detect_linux_connect_observer
from .types import (
    BIRDCAGE_EXPECTED_SKIPS,
    DynamicTrace,
    SandboxBackend,
    SandboxRunRequest,
)

# REV-2: split profiles per platform.
# Linux Landlock is FS-only — no network primitive. Document the gap explicitly.
NPM_LIGHT_PROFILE_LINUX: dict = {
    "fs_read_only": ["/usr", "/lib", "/etc"],
    "fs_read_write": ["${SCRATCH_HOME}", "/tmp"],
    # NOTE: Landlock has no network primitive pre-6.7. Egress is NOT kernel-blocked here.
    # Enforcement is cooperative (npm --offline + bogus NPM_CONFIG_REGISTRY) and
    # observed (strace/bpftrace). See Principle 6 tier split.
}

# macOS sandbox-exec DOES support network deny at the kernel — emit it explicitly.
NPM_LIGHT_PROFILE_MACOS: str = """\
(version 1)
(deny default)
(deny network*)
(allow file-read*)
(allow file-write* (subpath (param "scratch_home")) (subpath "/tmp"))
(allow process-fork)
(allow process-exec)
"""


class BirdcageBackend(SandboxBackend):
    name = "birdcage"

    def check_available(self) -> bool:
        if shutil.which("birdcage") is None:
            return False
        if platform.system() == "Linux":
            # Linux-light needs a connect-observer (REV-3)
            return detect_linux_connect_observer() is not None
        return True  # macOS kernel-enforces via sandbox-exec

    async def run(self, request: SandboxRunRequest) -> DynamicTrace:
        """Skeleton — full impl lands in Task #6 (worker-5)."""
        return DynamicTrace(
            ran=False,
            runtime="birdcage",
            error="BirdcageBackend.run() not yet implemented (Phase 1b Task 4)",
            skipped_expected=set(BIRDCAGE_EXPECTED_SKIPS),
        )
