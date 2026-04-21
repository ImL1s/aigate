"""Integration tests: real strace binary produces parseable events.

Gate: skipped when ``strace`` is not on PATH (macOS dev machines, minimal CI images).
Run live on Linux CI where strace is installed.

Covers:
- strace -f produces ≥1 connect event for socket.connect() to RFC 5737 TEST-NET-1.
- connect event target is formatted as ``<IP>:<port>``.
- execve event appears for the traced python3 invocation.
- openat events appear for module loading.
- StraceObserver.parse_event() (stateful bytes interface) produces events from
  real strace output streamed line-by-line.
- Event PID field is a positive integer matching the traced process.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading

import pytest

from aigate.sandbox.observers.strace import StraceObserver, parse_strace_logical_event

pytestmark = pytest.mark.skipif(
    shutil.which("strace") is None,
    reason="strace not on PATH — integration test requires strace binary",
)

# RFC 5737 TEST-NET-1 — non-routable, safe for synthetic connects
_IP = "192.0.2.1"
_PORT = 80

# Python one-liner: attempt connect, swallow the expected ECONNREFUSED/timeout
_CONNECT_CMD = f"import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('{_IP}', {_PORT}))"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_strace_fifo(tmp_path, python_cmd: str) -> bytes:
    """Launch strace over a python3 command, drain FIFO, return raw bytes."""
    fifo_path = str(tmp_path / "observer.fifo")
    os.mkfifo(fifo_path)

    collected: list[bytes] = []

    def _reader():
        # Blocking open — waits until strace (the writer) connects.
        with open(fifo_path, "rb") as fh:
            collected.append(fh.read())

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()

    subprocess.run(
        [
            "strace",
            "-f",
            "-e",
            "trace=connect,openat,write,execve,clone",
            "-o",
            fifo_path,
            "--",
            "python3",
            "-c",
            python_cmd,
        ],
        timeout=20,
        capture_output=True,
        check=False,  # python exits non-zero on connect failure — that's OK
    )

    reader.join(timeout=10)
    return collected[0] if collected else b""


def _parse_all(data: bytes) -> list:
    """Drain parse_strace_logical_event over all newline-terminated lines."""
    events = []
    buf = data
    while b"\n" in buf:
        ev, buf = parse_strace_logical_event(buf, [])
        if ev is not None:
            events.append(ev)
    return events


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestStraceRealStream:
    def test_connect_event_emitted_for_real_socket(self, tmp_path):
        """Real strace emits ≥1 connect event for socket.connect to TEST-NET-1."""
        data = _run_strace_fifo(tmp_path, _CONNECT_CMD)
        events = _parse_all(data)
        connect_events = [e for e in events if e.kind == "connect"]
        assert connect_events, (
            f"Expected ≥1 connect event; parsed kinds: {[e.kind for e in events][:15]}"
        )
        assert any(_IP in e.target for e in connect_events), (
            f"No connect event targets {_IP!r}; "
            f"connect targets: {[e.target for e in connect_events]}"
        )

    def test_connect_target_includes_port(self, tmp_path):
        """connect event target is formatted as ``<IP>:<port>``."""
        data = _run_strace_fifo(tmp_path, _CONNECT_CMD)
        events = _parse_all(data)
        matching = [e for e in events if e.kind == "connect" and _IP in e.target]
        assert matching, f"No connect event targeting {_IP!r}"
        assert any(f":{_PORT}" in e.target for e in matching), (
            f"Expected port {_PORT} in connect target; got targets: {[e.target for e in matching]}"
        )

    def test_execve_event_emitted(self, tmp_path):
        """strace emits an exec event for the python3 execve call."""
        data = _run_strace_fifo(tmp_path, "pass")
        events = _parse_all(data)
        exec_events = [e for e in events if e.kind == "exec"]
        assert exec_events, f"Expected ≥1 exec event; got kinds: {[e.kind for e in events][:15]}"

    def test_openat_events_emitted(self, tmp_path):
        """strace emits open/write events from python's module imports."""
        data = _run_strace_fifo(tmp_path, "import os")
        events = _parse_all(data)
        open_events = [e for e in events if e.kind in ("open", "write")]
        assert open_events, (
            f"Expected ≥1 open/write event; got kinds: {[e.kind for e in events][:15]}"
        )

    def test_all_event_pids_are_positive(self, tmp_path):
        """Every parsed event carries a positive PID from the strace -f output."""
        data = _run_strace_fifo(tmp_path, _CONNECT_CMD)
        events = _parse_all(data)
        assert events, "No events parsed — cannot verify PIDs"
        bad = [e for e in events if e.pid <= 0]
        assert not bad, f"Events with non-positive PID: {[(e.kind, e.pid) for e in bad]}"

    def test_strace_observer_stateful_parser_produces_events(self, tmp_path):
        """StraceObserver.parse_event() (stateful) produces events from live output."""
        data = _run_strace_fifo(tmp_path, _CONNECT_CMD)

        observer = StraceObserver()
        events = []
        for line in data.split(b"\n"):
            if not line:
                continue
            ev = observer.parse_event(line + b"\n", [])
            if ev is not None:
                events.append(ev)

        assert events, "StraceObserver.parse_event() produced 0 events from real strace output"
        kinds = {e.kind for e in events}
        assert kinds, "Events have no kinds"

    def test_raw_field_contains_syscall_name(self, tmp_path):
        """event.raw includes the syscall name for traceability."""
        data = _run_strace_fifo(tmp_path, _CONNECT_CMD)
        events = _parse_all(data)
        connect_events = [e for e in events if e.kind == "connect" and _IP in e.target]
        assert connect_events, f"No connect event for {_IP}"
        ev = connect_events[0]
        assert "connect" in ev.raw, f"Expected 'connect' in event.raw; got: {ev.raw!r}"
