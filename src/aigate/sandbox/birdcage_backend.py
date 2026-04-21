"""Birdcage subprocess wrapper (PRD v3.1 §3.1, Phase 1b/2).

License boundary: Birdcage is GPL-3.0. We call it as a subprocess only —
no imports, no linking, no bundled binary. The user installs birdcage
themselves (``cargo install birdcage``).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import platform
import resource
import shutil
import signal
import tempfile
import time
from collections.abc import Iterable

from .canary import generate_canary_scheme
from .errors import SandboxUnavailable
from .observers.base import FifoSink
from .observers.canary import emit_canary_syscall
from .observers.watchdog import ObserverWatchdog
from .runtime_select import detect_linux_connect_observer, select_linux_observer
from .secrets import redact_secrets
from .types import (
    BIRDCAGE_EXPECTED_SKIPS,
    DynamicTrace,
    DynamicTraceEvent,
    SandboxBackend,
    SandboxCoverage,
    SandboxRunRequest,
    is_real_event,
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
    # Guard int() against schema drift (e.g., Birdcage emits "ts_ms": "???" or
    # "pid": null during a version upgrade) — ValueError/TypeError here would
    # propagate uncaught through parse_birdcage_stream and silence every
    # subsequent line, so we treat the whole row as parse failure and let
    # classify_parse_quality surface PARSER_PARTIAL_DRIFT.
    try:
        ts_ms = int(obj.get("ts_ms", 0) or 0)
        pid = int(obj.get("pid", 0) or 0)
    except (ValueError, TypeError):
        return None
    return DynamicTraceEvent(
        kind=kind,
        ts_ms=ts_ms,
        pid=pid,
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
        """Return True iff Birdcage + (on Linux) a connect-observer are reachable.

        **Phase 1b caveat (reviewer P1):** the Linux observer gate requires
        strace/bpftrace to be present on PATH, but ``_run_inside_scratch`` does
        NOT yet prepend that observer to the birdcage argv — real runs
        produce only npm's human-readable stdout, yield 0 parsed events, and
        trip ``PARSER_PARTIAL_DRIFT``/``NETWORK_CAPTURE`` so every Linux-light
        scan escalates to ``NEEDS_HUMAN_REVIEW`` until Phase 2 wires the
        observer into argv. The gate is kept (rather than loosened) so
        hosts without an observer still fail closed via ``SandboxUnavailable``
        when ``--sandbox-required`` is set.
        """
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
        try:
            return await self._run_inside_scratch(request, birdcage, npm, canary, scratch_home)
        finally:
            # REV-cleanup: always delete the scratch HOME + any SBPL profile
            # we wrote inside it. Leaking one directory per run under continuous
            # scanning silently fills /tmp.
            shutil.rmtree(scratch_home, ignore_errors=True)

    async def _run_inside_scratch(
        self,
        request: SandboxRunRequest,
        birdcage: str,
        npm: str,
        canary,  # type: ignore[no-untyped-def]
        scratch_home: str,
    ) -> DynamicTrace:
        rule_args = self._build_rule_args(scratch_home)
        birdcage_argv = [
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

        # --- Phase 2: observer selection (REV-C/D/F) ---
        # On Linux, prepend the observer (strace) argv so strace becomes the
        # PGID leader and birdcage is its child via ``--``.  Teardown uses
        # ``os.killpg(observer_pgid)`` which cascades via PTRACE_O_TRACECLONE
        # to the entire birdcage subtree (REV-C Principle 5).
        observer = select_linux_observer() if platform.system() == "Linux" else None
        sink: FifoSink | None = None
        fifo_path = os.path.join(scratch_home, "observer.fifo")
        observer_events: list[DynamicTraceEvent] = []
        # raw_chunks: each appended item is one read() chunk; watchdog counts len().
        raw_chunks: list[bytes] = []

        if observer is not None:
            sink = FifoSink(fifo_path)
            sink.__enter__()  # os.mkfifo — creates the named pipe
            argv = observer.argv_prefix(sink) + birdcage_argv
        else:
            argv = birdcage_argv

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

        # Emit canary BEFORE the main subprocess (REV-B).
        # The canary subprocess opens OBSERVER_CANARY_MARKER which strace
        # captures through the PGID trace, proving parser liveness.
        if observer is not None and sink is not None:
            emit_canary_syscall(sink)

        # start_new_session=True:
        # - observer present → strace is PGID leader (REV-C); birdcage is its
        #   child.  ``os.killpg(observer_pgid)`` cascades via ``-f`` to birdcage.
        # - observer absent → birdcage is PGID leader (Phase 1b behaviour).
        proc = await asyncio.create_subprocess_exec(
            *argv,
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        # REV-C: capture the PGID of the outermost process (observer or birdcage).
        observer_pgid: int | None = None
        if observer is not None:
            with contextlib.suppress(OSError):
                observer_pgid = os.getpgid(proc.pid)

        scrub: list[str] = [canary.run_token] if canary.run_token else []
        synthetic_events: list[DynamicTraceEvent] = []
        stop = asyncio.Event()

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
                try:
                    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
                except OSError:
                    # Kernel configs where getrusage is unavailable must not
                    # poison the probe task — the finally-block would then
                    # re-raise here and swallow the real exception from
                    # communicate() / our timeout path.
                    ru = None
                target = f"rss_kb={ru.ru_maxrss}" if ru is not None else "rss_kb=unavailable"
                synthetic_events.append(
                    DynamicTraceEvent(
                        kind="exec",
                        source="resource_probe",
                        pid=proc.pid or 0,
                        process="npm",
                        ts_ms=int(time.monotonic() * 1000) - start_ms,
                        target=target,
                    )
                )
                try:
                    await asyncio.wait_for(stop.wait(), timeout=0.2)
                except TimeoutError:
                    continue

        async def fifo_reader() -> None:
            """Stream strace output from FIFO; drain remaining data after stop."""
            if observer is None or sink is None:
                return
            loop = asyncio.get_event_loop()
            fd = -1
            try:
                fd = await loop.run_in_executor(
                    None, lambda: os.open(sink.argv_arg(), os.O_RDONLY | os.O_NONBLOCK)
                )
                # Streaming phase: process events while subprocess is running.
                while not stop.is_set():
                    try:
                        chunk = await loop.run_in_executor(None, lambda: os.read(fd, 4096))
                        if chunk:
                            raw_chunks.append(chunk)
                            ev = observer.parse_event(chunk, scrub)
                            if ev is not None:
                                observer_events.append(ev)
                        else:
                            # EOF — write end closed (observer exited early)
                            return
                    except BlockingIOError:
                        await asyncio.sleep(0.01)
                    except OSError:
                        return
                # Drain phase: stop is set; collect any bytes still buffered.
                try:
                    while True:
                        chunk = await loop.run_in_executor(None, lambda: os.read(fd, 4096))
                        if not chunk:
                            break
                        raw_chunks.append(chunk)
                        ev = observer.parse_event(chunk, scrub)
                        if ev is not None:
                            observer_events.append(ev)
                except (BlockingIOError, OSError):
                    pass
            finally:
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)

        probe_task = asyncio.create_task(resource_probe())
        reader_task = asyncio.create_task(fifo_reader()) if observer is not None else None
        watchdog: ObserverWatchdog | None = None
        watchdog_task: asyncio.Task | None = None  # type: ignore[type-arg]
        if observer is not None:
            watchdog = ObserverWatchdog(observer_events, raw_chunks, stop)
            watchdog_task = asyncio.create_task(watchdog.run())

        timed_out = False
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=request.timeout_s
            )
        except TimeoutError:
            # REV-C: kill observer PGID when present — strace is PGID leader and
            # cascades SIGKILL via PTRACE_O_TRACECLONE (-f) to the birdcage subtree.
            # Fall back to birdcage's own PGID when no observer (Phase 1b path).
            if observer_pgid is not None:
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.killpg(observer_pgid, signal.SIGKILL)
            else:
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            stdout_b, stderr_b = b"", b""
            timed_out = True
        finally:
            stop.set()
            # Drain reader before cancelling so events are not lost.
            if reader_task is not None:
                with contextlib.suppress(asyncio.CancelledError, Exception, TimeoutError):
                    await asyncio.wait_for(asyncio.shield(reader_task), timeout=2.0)
                reader_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await reader_task
            # Cancel remaining background tasks.
            probe_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await probe_task
            if watchdog_task is not None:
                watchdog_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await watchdog_task
            # Release FIFO and observer resources.
            if sink is not None:
                sink.cleanup()
            if observer is not None:
                await observer.cleanup()

        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Parse birdcage stdout JSON-lines (present on all platforms; strace
        # output arrives via FIFO and is already in observer_events).
        raw_lines = stdout_b.decode("utf-8", errors="replace").splitlines()
        parsed_events, events_parsed, raw_lines_seen = parse_birdcage_stream(raw_lines, scrub)
        err_msg, drift_cov = classify_parse_quality(events_parsed, raw_lines_seen)

        all_events = synthetic_events + parsed_events + observer_events
        observed: set[SandboxCoverage] = {SandboxCoverage.FS_WRITES}
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

        # REV-F: evidence-based NETWORK_CAPTURE coverage decision (Phase 2).
        # Replaces Phase 1b's unconditional ``skipped_unexpected.add(NETWORK_CAPTURE)``
        # on Linux.  Every branch is fail-closed except the final ``else`` which
        # requires ≥1 real event (canary excluded) from the observer stream.
        if platform.system() == "Linux":
            real_event_count = sum(1 for e in all_events if is_real_event(e))
            observer_rc = proc.returncode if proc.returncode is not None else 0
            # Observer crashed: strace exited non-zero and produced zero events
            # (strace propagates birdcage's exit code; non-zero + zero events
            # means strace itself failed, e.g. ptrace_scope=2 refused attach).
            observer_crashed = (
                observer is not None and observer_rc != 0 and real_event_count == 0
            )
            stuck_observer_detected = watchdog.stuck if watchdog is not None else False

            if observer is None:
                # No observer available (strace not on PATH etc.).
                skipped_unexpected.add(SandboxCoverage.NETWORK_CAPTURE)
                error = error or "No Linux connect-observer available (install strace)"
            elif timed_out or observer_crashed:
                # REV-F: crash or timeout → fail-closed regardless of partial events.
                skipped_unexpected.add(SandboxCoverage.NETWORK_CAPTURE)
                if observer_crashed and not timed_out:
                    error = error or f"observer_crash: {observer.name} rc={observer_rc}"
            elif stuck_observer_detected:
                # REV-A drift-aware watchdog tripped (fully-silent or drift-masked).
                skipped_unexpected.add(SandboxCoverage.NETWORK_CAPTURE)
                error = error or "stuck_observer: drift-aware watchdog tripped"
            elif real_event_count < 1:
                # REV-B + REV-F: observer alive but zero real events — fail-closed.
                # Canary event (source="observer_canary") excluded by is_real_event().
                skipped_unexpected.add(SandboxCoverage.NETWORK_CAPTURE)
                error = error or "observer_silent: no real events observed (canary missing)"
            else:
                # Observer produced ≥1 real event — coverage confirmed.
                observed.add(SandboxCoverage.NETWORK_CAPTURE)
                observed.add(SandboxCoverage.DNS)
                observed.add(SandboxCoverage.PROCESS_TREE)

        return DynamicTrace(
            ran=True,
            runtime="birdcage",
            duration_ms=duration_ms,
            timeout=timed_out,
            events=all_events,
            observed=observed,
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
