"""Birdcage subprocess wrapper (PRD v3.1 §3.1, Phase 1b).

License boundary: Birdcage is GPL-3.0. We call it as a subprocess only —
no imports, no linking, no bundled binary. The user installs birdcage
themselves (``cargo install birdcage``).
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import resource
import shutil
import tempfile
import time
from collections.abc import Iterable

from .canary import generate_canary_scheme
from .errors import SandboxUnavailable
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

BIRDCAGE_MIN_VERSION: tuple[int, int, int] = (0, 5, 0)
BIRDCAGE_TESTED_MAX_VERSION: tuple[int, int, int] = (0, 8, 1)

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
(allow file-write* (subpath "${SCRATCH_HOME}") (subpath "/tmp"))
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
        birdcage = shutil.which("birdcage")
        if birdcage is None:
            raise SandboxUnavailable("birdcage binary not on PATH")
        npm = shutil.which("npm")
        if npm is None:
            raise SandboxUnavailable("npm binary not on PATH")

        canary = generate_canary_scheme()
        scratch_home = tempfile.mkdtemp(prefix="aigate-sandbox-")

        rule_args = self._build_rule_args(scratch_home)
        argv = [
            birdcage,
            *rule_args,
            "--",
            npm,
            "install",
            request.source_archive_path,
            "--offline",
            "--ignore-scripts=false",
            "--no-audit",
            "--no-fund",
            "--no-save",
        ]
        env = {
            "HOME": scratch_home,
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "CI": "1",
            "NPM_CONFIG_YES": "true",
            "NPM_CONFIG_OFFLINE": "true",
            "NPM_CONFIG_LOGLEVEL": "error",
            "NPM_CONFIG_REGISTRY": "http://127.0.0.1:1",
        }
        start_ms = int(time.monotonic() * 1000)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        synthetic_events: list[DynamicTraceEvent] = []
        stop = asyncio.Event()
        scrub: list[str] = [canary.run_token] if canary.run_token else []

        # Emit the bootstrap synthetic event synchronously BEFORE any await —
        # Python 3.12+ asyncio can skip the probe task entirely if communicate()
        # completes on the first step (mocked tests), so the resource-probe
        # guarantee has to live outside the background task.
        synthetic_events.append(
            DynamicTraceEvent(
                kind="exec",
                source="resource_probe",
                pid=proc.pid or 0,
                process="npm",
                ts_ms=int(time.monotonic() * 1000) - start_ms,
                target=npm,
            )
        )

        async def resource_probe() -> None:
            while not stop.is_set():
                ru = resource.getrusage(resource.RUSAGE_CHILDREN)
                synthetic_events.append(
                    DynamicTraceEvent(
                        kind="exec",
                        source="resource_probe",
                        pid=proc.pid or 0,
                        process="npm",
                        ts_ms=int(time.monotonic() * 1000) - start_ms,
                        target=f"rss_kb={ru.ru_maxrss}",
                    )
                )
                try:
                    await asyncio.wait_for(stop.wait(), timeout=0.2)
                except TimeoutError:
                    continue

        probe_task = asyncio.create_task(resource_probe())

        timed_out = False
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=request.timeout_s
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            stdout_b, stderr_b = b"", b""
            timed_out = True
        finally:
            stop.set()
            await probe_task

        duration_ms = int(time.monotonic() * 1000) - start_ms

        raw_lines = stdout_b.decode("utf-8", errors="replace").splitlines()
        parsed_events, events_parsed, raw_lines_seen = parse_birdcage_stream(raw_lines, scrub)
        err_msg, drift_cov = classify_parse_quality(events_parsed, raw_lines_seen)

        all_events = synthetic_events + parsed_events
        skipped_unexpected: set[SandboxCoverage] = set()
        if drift_cov is not None:
            skipped_unexpected.add(drift_cov)

        error: str | None = None
        if timed_out:
            error = f"birdcage wall-clock timeout after {request.timeout_s}s"
        elif proc.returncode and proc.returncode != 0:
            stderr_text = redact_secrets(stderr_b.decode(errors="replace"), scrub)
            error = f"birdcage exited rc={proc.returncode}; stderr={stderr_text[:200]}"
        elif err_msg:
            error = err_msg

        return DynamicTrace(
            ran=True,
            runtime="birdcage",
            duration_ms=duration_ms,
            timeout=timed_out,
            events=all_events,
            observed={SandboxCoverage.FS_WRITES},
            skipped_expected=set(BIRDCAGE_EXPECTED_SKIPS),
            skipped_unexpected=skipped_unexpected,
            canary=canary,
            error=error,
        )

    def _build_rule_args(self, scratch_home: str) -> list[str]:
        """Compose birdcage argv flags per platform from profile constants."""
        if platform.system() == "Linux":
            args: list[str] = []
            for path in NPM_LIGHT_PROFILE_LINUX["fs_read_only"]:
                args.extend(["--allow-read", path])
            for path in NPM_LIGHT_PROFILE_LINUX["fs_read_write"]:
                actual = path.replace("${SCRATCH_HOME}", scratch_home)
                args.extend(["--allow-read", actual, "--allow-write", actual])
            return args
        # macOS: write SBPL profile to scratch dir and pass via flag
        sbpl = NPM_LIGHT_PROFILE_MACOS.replace("${SCRATCH_HOME}", scratch_home)
        prof_path = os.path.join(scratch_home, "npm-light.sb")
        with open(prof_path, "w") as f:
            f.write(sbpl)
        return ["--sbpl-profile", prof_path]
