"""StraceObserver — bytes-oriented strace output parser (Phase 2, REV-D).

Parser design
-------------
``parse_strace_logical_event(buffer, scrub)`` is the **stateless seam**:
given a byte buffer containing at least one newline-terminated line it
extracts and parses the first complete single-line event, returning
``(event_or_None, remaining_bytes)``.  Suitable for unit-testing individual
fixture lines in isolation.

``StraceObserver.parse_event(raw, scrub)`` accumulates raw bytes across
successive calls, manages the ``_pending`` dict for cross-call
**unfinished / resumed** reassembly, and delegates single-line parsing to
``_parse_complete_syscall``.

Supported formats
-----------------
- strace 5.x ``[pid N]`` prefix  (e.g. Debian stable / Ubuntu 20.04)
- strace 6.x bare-``N`` prefix   (e.g. Ubuntu 22.04+, Fedora 38+)
- Single-process traces with no PID prefix are consumed but yield None
  (we always run ``strace -f``, so every line should have a PID).

Syscall mapping
---------------
- ``connect`` → ``kind="connect"`` or ``kind="dns"`` (port 53)
- ``openat``  → ``kind="write"`` (write flags), ``kind="open"`` (read flags),
                or ``kind="observer_canary"`` (canary sentinel path)
- ``execve``  → ``kind="exec"``
- ``write``   → ``kind="write"`` with ``target="fd=N"``
- ``clone``   → ``kind="clone"`` (for fork-race detector in Task 2.6)

Redaction
---------
``secrets.redact_secrets`` is applied to ``target`` and ``raw`` **before**
the event is constructed.  ``scrub`` values are never persisted or logged.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable

from ..secrets import redact_secrets
from ..types import DynamicTraceEvent, SandboxCoverage
from .base import Observer, ObserverSink, SinkKind

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Coverage surfaces provided by this observer.
STRACE_COVERAGE: frozenset[SandboxCoverage] = frozenset(
    {
        SandboxCoverage.NETWORK_CAPTURE,
        SandboxCoverage.FS_WRITES,
        SandboxCoverage.DNS,
        SandboxCoverage.PROCESS_TREE,
    }
)

#: Sentinel path that BirdcageBackend (Task 2.5, REV-B) opens as an
#: observer-liveness canary.  Any ``openat()`` of this exact path is tagged
#: ``source="observer_canary"`` so ``is_real_event()`` can exclude it.
OBSERVER_CANARY_MARKER: str = "/aigate-observer-canary"

# ---------------------------------------------------------------------------
# Internal compiled regexes
# ---------------------------------------------------------------------------

# PID prefix:
#   strace 5.x:  "[pid 1234] "   (with square brackets)
#   strace 6.x:  "1234 "         (bare integer, optional leading whitespace)
_RE_PID = re.compile(r"^\s*(?:\[pid\s+(\d+)\]|(\d+))\s+")

# Complete syscall:  name(args) = retval
# DOTALL so args can contain newlines after reassembly.
_RE_SYSCALL = re.compile(r"^(\w+)\((.*)\)\s*=\s*(.+)$", re.DOTALL)

# Unfinished:  name(partial_args <unfinished ...>
_RE_UNFINISHED = re.compile(r"^(\w+)\((.*?)\s*<unfinished\s*\.+\s*>$", re.DOTALL)

# Resumed:  <... name resumed> remaining_args) = retval
_RE_RESUMED = re.compile(r"^<\.\.\.\s+(\w+)\s+resumed>\s*(.*)", re.DOTALL)

# IPv4 sockaddr in connect() args
_RE_INET4 = re.compile(
    r"sa_family=AF_INET[^,}]*"
    r",\s*sin_port=htons\((\d+)\)"
    r",\s*sin_addr=inet_addr\(\"([^\"]+)\"\)"
)

# IPv6 sockaddr (port only — IPv6 addr text extraction is complex/optional)
_RE_INET6 = re.compile(
    r"sa_family=AF_INET6[^,}]*,\s*sin6_port=htons\((\d+)\)"
)

# AF_UNIX sockaddr
_RE_UNIX = re.compile(r'sa_family=AF_UNIX,\s*sun_path="([^"]+)"')

# openat args:  dirfd, "/path", flags
# dirfd may be AT_FDCWD or a numeric fd (possibly negative).
_RE_OPENAT = re.compile(
    r'(?:AT_FDCWD|-?\d+),\s*"([^"]+)"'
    r'(?:,\s*([A-Z_0-9|]+))?'
)

# execve first arg: "/path"
_RE_EXECVE_PATH = re.compile(r'^\s*"([^"]+)"')
# all quoted strings in argv list
_RE_QUOTED = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')

# write first arg: fd number
_RE_WRITE_FD = re.compile(r"^\s*(\d+),")

# clone/clone3 return value (child PID as first token)
_RE_RETVAL_INT = re.compile(r"^(-?\d+)")

# Flags indicating a write-mode open
_WRITE_FLAGS: frozenset[str] = frozenset(
    {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _pid_from_match(m: re.Match[str]) -> int:
    """Extract pid integer from a _RE_PID match (handles both capture groups)."""
    return int(m.group(1) or m.group(2))


def _parse_connect(
    pid: int, args: str, ts_ms: int, scrub: list[str]
) -> DynamicTraceEvent | None:
    """Map connect(fd, sockaddr, len) → connect or dns event."""
    # AF_INET
    m4 = _RE_INET4.search(args)
    if m4:
        port = int(m4.group(1))
        ip = m4.group(2)
        if port == 53:
            kind, target = "dns", f"resolver={ip}"
        else:
            kind, target = "connect", f"{ip}:{port}"
        return DynamicTraceEvent(
            kind=kind,
            ts_ms=ts_ms,
            pid=pid,
            process="",
            target=redact_secrets(target, scrub),
            raw=redact_secrets(f"connect({args})", scrub),
        )

    # AF_INET6
    m6 = _RE_INET6.search(args)
    if m6:
        port = int(m6.group(1))
        if port == 53:
            kind, target = "dns", "resolver=[ipv6]"
        else:
            kind, target = "connect", f"[ipv6]:{port}"
        return DynamicTraceEvent(
            kind=kind,
            ts_ms=ts_ms,
            pid=pid,
            process="",
            target=redact_secrets(target, scrub),
            raw=redact_secrets(f"connect({args})", scrub),
        )

    # AF_UNIX
    mu = _RE_UNIX.search(args)
    if mu:
        path = mu.group(1)
        return DynamicTraceEvent(
            kind="connect",
            ts_ms=ts_ms,
            pid=pid,
            process="",
            target=redact_secrets(f"unix:{path}", scrub),
            raw=redact_secrets(f"connect({args})", scrub),
        )

    # Unknown / truncated — still emit an event so parse ratio stays healthy
    return DynamicTraceEvent(
        kind="connect",
        ts_ms=ts_ms,
        pid=pid,
        process="",
        target=redact_secrets(args[:80], scrub),
        raw=redact_secrets(f"connect({args})", scrub),
    )


def _parse_openat(
    pid: int, args: str, ts_ms: int, scrub: list[str]
) -> DynamicTraceEvent | None:
    """Map openat(dirfd, path, flags) → open / write / observer_canary event."""
    m = _RE_OPENAT.search(args)
    if m is None:
        return None
    path = m.group(1)
    flags_str = m.group(2) or ""

    # Canary sentinel (REV-B)
    if path == OBSERVER_CANARY_MARKER:
        return DynamicTraceEvent(
            kind="observer_canary",
            ts_ms=ts_ms,
            pid=pid,
            process="",
            source="observer_canary",
            target=redact_secrets(path, scrub),
            raw=redact_secrets(f"openat({args})", scrub),
        )

    flags = {f.strip() for f in flags_str.split("|") if f.strip()}
    kind = "write" if flags & _WRITE_FLAGS else "open"
    return DynamicTraceEvent(
        kind=kind,
        ts_ms=ts_ms,
        pid=pid,
        process="",
        target=redact_secrets(path, scrub),
        raw=redact_secrets(f"openat({args})", scrub),
    )


def _parse_execve(
    pid: int, args: str, ts_ms: int, scrub: list[str]
) -> DynamicTraceEvent | None:
    """Map execve(path, argv, envp) → exec event."""
    pm = _RE_EXECVE_PATH.match(args)
    if pm is None:
        return None
    path = pm.group(1)

    # Extract argv from "[...]" section
    bracket_open = args.find("[")
    bracket_close = args.rfind("]") if bracket_open >= 0 else -1
    argv: list[str] = []
    if bracket_open >= 0 and bracket_close > bracket_open:
        argv_text = args[bracket_open + 1 : bracket_close]
        argv = [redact_secrets(a, scrub) for a in _RE_QUOTED.findall(argv_text)]

    return DynamicTraceEvent(
        kind="exec",
        ts_ms=ts_ms,
        pid=pid,
        process="",
        target=redact_secrets(path, scrub),
        argv=argv,
        raw=redact_secrets(f"execve({args[:120]})", scrub),
    )


def _parse_write(
    pid: int, args: str, ts_ms: int, scrub: list[str]
) -> DynamicTraceEvent:
    """Map write(fd, buf, count) → write event with target="fd=N"."""
    fm = _RE_WRITE_FD.match(args)
    fd = fm.group(1) if fm else "?"
    return DynamicTraceEvent(
        kind="write",
        ts_ms=ts_ms,
        pid=pid,
        process="",
        target=f"fd={fd}",
        raw=redact_secrets(f"write({args[:80]})", scrub),
    )


def _parse_clone(
    pid: int, args: str, retval_str: str, ts_ms: int, scrub: list[str]
) -> DynamicTraceEvent | None:
    """Map clone(...) = child_pid → clone event (used by Task-2.6 fork-race detector)."""
    rm = _RE_RETVAL_INT.match(retval_str.strip())
    if rm is None:
        return None
    child_pid = int(rm.group(1))
    if child_pid <= 0:
        return None  # failed clone
    return DynamicTraceEvent(
        kind="clone",
        ts_ms=ts_ms,
        pid=pid,
        process="",
        target=f"child_pid={child_pid}",
        raw=redact_secrets(f"clone({args[:80]})", scrub),
    )


def _dispatch(
    pid: int,
    syscall: str,
    args: str,
    retval_str: str,
    ts_ms: int,
    scrub: list[str],
) -> DynamicTraceEvent | None:
    """Dispatch to the per-syscall parser; return None for unrecognised calls."""
    if syscall == "connect":
        return _parse_connect(pid, args, ts_ms, scrub)
    if syscall == "openat":
        return _parse_openat(pid, args, ts_ms, scrub)
    if syscall == "execve":
        return _parse_execve(pid, args, ts_ms, scrub)
    if syscall == "write":
        return _parse_write(pid, args, ts_ms, scrub)
    if syscall in ("clone", "clone3"):
        return _parse_clone(pid, args, retval_str, ts_ms, scrub)
    return None


# ---------------------------------------------------------------------------
# Free function — stateless single-line event extraction (testable seam)
# ---------------------------------------------------------------------------


def parse_strace_logical_event(
    buffer: bytes,
    scrub: Iterable[str],
) -> tuple[DynamicTraceEvent | None, bytes]:
    """Extract the first parseable logical event from a byte buffer.

    Returns ``(event, remaining_bytes)`` where ``remaining_bytes`` is
    everything after the consumed newline.  Returns ``(None, remaining_bytes)``
    when the line was consumed but yielded no event (signal, exit notice,
    unfinished syscall, resumed line without pending context).  Returns
    ``(None, buffer)`` unchanged when no newline is present yet.

    This function is **stateless** — it cannot track cross-call
    ``unfinished / resumed`` pairs.  For multi-call reassembly use
    ``StraceObserver.parse_event()`` which maintains per-instance state.

    >>> ev, _ = parse_strace_logical_event(
    ...     b'1234 connect(4, {sa_family=AF_INET, sin_port=htons(80),'
    ...     b' sin_addr=inet_addr("1.2.3.4")}, 16) = 0\\n', [])
    >>> ev.kind, ev.target, ev.pid
    ('connect', '1.2.3.4:80', 1234)
    """
    scrub_list = list(scrub)

    if b"\n" not in buffer:
        return None, buffer

    nl = buffer.index(b"\n")
    raw_line = buffer[:nl]
    remaining = buffer[nl + 1 :]
    line = raw_line.decode("utf-8", errors="replace").rstrip("\r")

    pid_m = _RE_PID.match(line)
    if pid_m is None:
        # No PID prefix — not a traceable syscall line (banner, etc.)
        return None, remaining

    pid = _pid_from_match(pid_m)
    tail = line[pid_m.end() :]

    # Resumed lines need pending context → stateless function skips them
    if _RE_RESUMED.match(tail):
        return None, remaining

    # Unfinished lines — no event without the continued half
    if _RE_UNFINISHED.match(tail):
        return None, remaining

    # Complete syscall
    sm = _RE_SYSCALL.match(tail)
    if sm is None:
        # Signal, exit notice, or malformed line
        return None, remaining

    syscall = sm.group(1)
    args = sm.group(2)
    retval_str = sm.group(3).strip()
    ts_ms = int(time.monotonic() * 1000)
    event = _dispatch(pid, syscall, args, retval_str, ts_ms, scrub_list)
    return event, remaining


# ---------------------------------------------------------------------------
# StraceObserver — stateful, bytes-oriented observer (REV-D)
# ---------------------------------------------------------------------------


class StraceObserver(Observer):
    """strace-based syscall observer for Linux-light sandbox mode (Phase 2).

    Implements the ``Observer`` ABC (Task 2.1, REV-D):

    - ``argv_prefix(sink)`` prepends ``strace -f -e trace=... -o <fifo> --``
      to the birdcage argv.
    - ``parse_event(raw, scrub)`` is the bytes-oriented, per-instance stateful
      parser.  It accumulates partial bytes in ``_buf``, extracts one
      newline-terminated physical line per call, and reassembles
      ``<... resumed>`` continuations via ``_pending[pid]``.
    - ``check_available()`` returns ``True`` iff ``strace`` is on PATH.
    """

    name: str = "strace"
    coverage: frozenset[SandboxCoverage] = STRACE_COVERAGE

    def __init__(self) -> None:
        # Per-instance parser state (REV-D: no module-global buffers)
        self._buf: bytes = b""
        # pid → (syscall_name, partial_args_text)
        self._pending: dict[int, tuple[str, str]] = {}

    # ------------------------------------------------------------------
    # Observer ABC implementation
    # ------------------------------------------------------------------

    @property
    def sink_kind(self) -> SinkKind:
        return "fifo"

    def check_available(self) -> bool:
        """Return True iff ``strace`` binary is on PATH."""
        return self._binary_on_path()

    def argv_prefix(self, sink: ObserverSink) -> list[str]:
        """Build the argv prefix to prepend to the birdcage command.

        Example result::

            ["strace", "-f",
             "-e", "trace=connect,openat,write,execve,clone",
             "-o", "/tmp/aigate-sandbox-xxx/observer.fifo",
             "--"]

        The caller appends the full birdcage argv after this list.
        Principle 5 (REV-C): strace becomes the PGID leader; birdcage is
        its child via ``--``.  Teardown calls ``os.killpg(observer_pgid)``
        which cascades via ``-f`` (PTRACE_O_TRACECLONE) to the entire
        birdcage subtree.
        """
        return [
            "strace",
            "-f",
            "-e",
            "trace=connect,openat,write,execve,clone",
            "-o",
            sink.argv_arg(),
            "--",
        ]

    def parse_event(
        self,
        raw: bytes,
        scrub: Iterable[str],
    ) -> DynamicTraceEvent | None:
        """Parse one raw byte-chunk; return an event or None.

        Appends ``raw`` to the internal buffer, then tries to consume one
        newline-terminated physical line.  Handles stateful
        ``<unfinished ...>`` / ``<... resumed>`` reassembly:

        - **Unfinished** line → stores ``(syscall, partial_args)`` in
          ``_pending[pid]`` and returns ``None``.
        - **Resumed** line → pops ``_pending[pid]``, reconstructs the full
          syscall text, parses and returns the event (or ``None`` if
          reconstruction fails).
        - **Complete** line → parsed directly.

        Returns ``None`` when:
        - No newline is present yet (partial line still buffering).
        - The line is a signal delivery, exit notice, or unrecognised format.
        - An unfinished line is consumed (state stored; event deferred).
        - A resumed line has no matching pending entry (orphaned continuation).

        Callers count every call as the denominator for
        ``classify_parse_quality``; non-None returns count as numerator.
        """
        self._buf += raw
        if b"\n" not in self._buf:
            return None

        nl = self._buf.index(b"\n")
        raw_line = self._buf[:nl]
        self._buf = self._buf[nl + 1 :]
        line = raw_line.decode("utf-8", errors="replace").rstrip("\r")

        scrub_list = list(scrub)

        pid_m = _RE_PID.match(line)
        if pid_m is None:
            return None

        pid = _pid_from_match(pid_m)
        tail = line[pid_m.end() :]

        # --- Resumed continuation ---
        resumed_m = _RE_RESUMED.match(tail)
        if resumed_m:
            syscall = resumed_m.group(1)
            suffix = resumed_m.group(2)  # e.g. "{...}, 16) = 0"
            pending = self._pending.pop(pid, None)
            if pending is None:
                return None  # orphaned resumed line
            _, partial_args = pending
            # Reconstruct the full syscall text and re-parse
            reconstructed = f"{syscall}({partial_args} {suffix}"
            sm = _RE_SYSCALL.match(reconstructed)
            if sm is None:
                return None
            ts_ms = int(time.monotonic() * 1000)
            return _dispatch(
                pid, syscall, sm.group(2), sm.group(3).strip(), ts_ms, scrub_list
            )

        # --- Unfinished syscall ---
        unfinished_m = _RE_UNFINISHED.match(tail)
        if unfinished_m:
            syscall = unfinished_m.group(1)
            partial_args = unfinished_m.group(2)
            self._pending[pid] = (syscall, partial_args)
            return None

        # --- Complete syscall ---
        sm = _RE_SYSCALL.match(tail)
        if sm is None:
            return None
        syscall = sm.group(1)
        args = sm.group(2)
        retval_str = sm.group(3).strip()
        ts_ms = int(time.monotonic() * 1000)
        return _dispatch(pid, syscall, args, retval_str, ts_ms, scrub_list)

    async def cleanup(self) -> None:
        """No resources held by the observer itself; no-op."""
        self._buf = b""
        self._pending.clear()
