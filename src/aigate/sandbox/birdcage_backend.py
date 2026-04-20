"""Birdcage subprocess wrapper (PRD v3.1 §3.1, Phase 1b).

License boundary: Birdcage is GPL-3.0. We call it as a subprocess only —
no imports, no linking, no bundled binary. The user installs birdcage
themselves (``cargo install birdcage``).
"""

from __future__ import annotations

import json
import platform
import shutil
from collections.abc import Iterable

from .runtime_select import detect_linux_connect_observer
from .secrets import redact_secrets
from .types import (
    BIRDCAGE_EXPECTED_SKIPS,
    DynamicTrace,
    DynamicTraceEvent,
    SandboxBackend,
    SandboxCoverage,
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


def parse_birdcage_stream(
    raw_lines: list[str],
    scrub_values: Iterable[str] = (),
) -> tuple[list[DynamicTraceEvent], int, int]:
    """Parse Birdcage stdout JSON-lines into redacted DynamicTraceEvent list.

    Returns (events, events_parsed, raw_lines_seen).

    Wire format (both Linux and macOS): one JSON object per stdout line.
    Expected shape: {"kind":"open","ts_ms":123,"pid":42,"process":"npm","target":"/tmp/x"}

    Secret redaction via scrub_values is applied BEFORE appending each event so
    a stale cache entry cannot leak a secret the current session never read.
    """
    events: list[DynamicTraceEvent] = []
    nonblank = [line for line in raw_lines if line.strip()]
    raw_lines_seen = len(nonblank)
    events_parsed = 0
    scrub = list(scrub_values)

    for line in nonblank:
        ev = _try_parse_line(line)
        if ev is None:
            continue
        ev.target = redact_secrets(ev.target, scrub)
        ev.raw = redact_secrets(ev.raw, scrub)
        events.append(ev)
        events_parsed += 1

    return events, events_parsed, raw_lines_seen


def _try_parse_line(line: str) -> DynamicTraceEvent | None:
    """Parse a single Birdcage stdout event line.

    Expected format (stdout JSON-lines, both Linux and macOS):
      {"kind":"open","ts_ms":123,"pid":42,"process":"npm","target":"/tmp/x"}

    Returns None if the line is not a recognized event (e.g., log preamble).
    """
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    kind = obj.get("kind")
    if not kind:
        return None
    return DynamicTraceEvent(
        kind=kind,
        ts_ms=int(obj.get("ts_ms", 0)),
        pid=int(obj.get("pid", 0)),
        process=str(obj.get("process", "")),
        target=str(obj.get("target", "")),
        raw=line,
    )


def classify_parse_quality(
    events_parsed: int, raw_lines_seen: int
) -> tuple[str | None, SandboxCoverage | None]:
    """Detect parser_never_matched vs partial_drift per REV-4.

    Returns (error_message, coverage_to_add) — both None if healthy.
    """
    if raw_lines_seen == 0:
        return None, None  # No output at all — different failure mode (floor)
    if events_parsed == 0:
        return (
            f"parser matched 0/{raw_lines_seen} lines — full schema drift or wrong channel",
            SandboxCoverage.PARSER_PARTIAL_DRIFT,
        )
    if raw_lines_seen >= 4:
        ratio = events_parsed / raw_lines_seen
        if ratio < DynamicTrace.PARSE_RATIO_FLOOR:
            return (
                f"parser matched {events_parsed}/{raw_lines_seen} lines ({ratio:.0%})"
                " — likely partial Birdcage schema drift",
                SandboxCoverage.PARSER_PARTIAL_DRIFT,
            )
    return None, None


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
