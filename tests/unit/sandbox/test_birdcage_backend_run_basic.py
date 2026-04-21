"""Unit tests for BirdcageBackend.run() — subprocess mocked.

Covers:
- Happy path: exits 0, 5 valid events parsed, synthetic events present.
- Timeout: communicate() times out → trace.timeout=True, error set.
- Non-zero exit: rc=1 with stderr → trace.error contains "birdcage exited rc=1".
- Parser drift: 10 non-JSON lines → PARSER_PARTIAL_DRIFT in skipped_unexpected.
- Phase 2 Linux+observer (REV-C/F): NETWORK_CAPTURE in observed; observer_pgid killed.
"""

from __future__ import annotations

import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from aigate.sandbox.birdcage_backend import BirdcageBackend
from aigate.sandbox.types import DynamicTraceEvent, SandboxCoverage, SandboxMode, SandboxRunRequest


def _request(**kwargs) -> SandboxRunRequest:
    defaults = dict(
        package_name="test-pkg",
        version="1.0.0",
        ecosystem="npm",
        source_archive_path="/tmp/test.tgz",
        mode=SandboxMode.LIGHT,
        timeout_s=10,
    )
    defaults.update(kwargs)
    return SandboxRunRequest(**defaults)


def _mock_proc(
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    pid: int = 42,
) -> MagicMock:
    proc = MagicMock()
    proc.pid = pid
    proc.returncode = returncode
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=None)
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


_FIVE_EVENTS_STDOUT = "\n".join(
    [
        '{"kind":"exec","ts_ms":1,"pid":42,"process":"npm","target":"/usr/bin/node"}',
        '{"kind":"open","ts_ms":2,"pid":42,"process":"npm","target":"/tmp/pkg/package.json"}',
        '{"kind":"write","ts_ms":3,"pid":42,"process":"npm","target":"/tmp/pkg/node_modules"}',
        '{"kind":"connect","ts_ms":4,"pid":42,"process":"node","target":"127.0.0.1:1"}',
        '{"kind":"dns","ts_ms":5,"pid":42,"process":"node","target":"localhost"}',
    ]
).encode()

_TEN_NON_JSON_LINES = b"\n".join([b"npm warn deprecated old-pkg@1.0.0"] * 10)


def _patch_which(name: str) -> str:
    return f"/usr/bin/{name}"


def _mock_strace_observer(real_event: DynamicTraceEvent | None = None) -> MagicMock:
    """Return a MagicMock StraceObserver.  parse_event returns real_event if supplied."""
    obs = MagicMock()
    obs.name = "strace"
    obs.sink_kind = "fifo"
    obs.argv_prefix = Mock(
        return_value=[
            "strace",
            "-f",
            "-e",
            "trace=connect,openat,write,execve,clone",
            "-o",
            "/tmp/aigate-sandbox-test/observer.fifo",
            "--",
        ]
    )
    obs.check_available.return_value = True
    obs.cleanup = AsyncMock()
    # Return real_event on first call, None forever after — prevents the
    # post-drain flush loop (PR #6 comment 3117030564 fix) from spinning
    # on a MagicMock that returns the same event every invocation.
    if real_event is not None:
        obs.parse_event.side_effect = [real_event] + [None] * 10_000
    else:
        obs.parse_event.return_value = None  # observer_silent path
    return obs


# _LINUX_OBSERVER_PATCHES: context managers that must be added when testing
# the Linux+observer path in addition to the base patches in _run_with_mock.
def _linux_observer_cm(mock_observer: MagicMock, read_side_effect=BlockingIOError):
    """Return list of patch context-managers for the Linux+strace path."""
    return [
        patch("aigate.sandbox.birdcage_backend.platform.system", return_value="Linux"),
        patch("aigate.sandbox.birdcage_backend.select_linux_observer", return_value=mock_observer),
        patch("aigate.sandbox.birdcage_backend.os.mkfifo"),
        patch("aigate.sandbox.birdcage_backend.os.open", return_value=99),
        patch("aigate.sandbox.birdcage_backend.os.read", side_effect=read_side_effect),
        patch("aigate.sandbox.birdcage_backend.os.close"),
        patch("aigate.sandbox.birdcage_backend.os.unlink"),
    ]


async def _run_with_mock(proc: MagicMock, timeout_s: int = 10) -> object:
    request = _request(timeout_s=timeout_s)
    with (
        patch("aigate.sandbox.birdcage_backend.shutil.which", side_effect=_patch_which),
        patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=proc),
        ),
        patch("tempfile.mkdtemp", return_value="/tmp/aigate-sandbox-test"),
        patch("os.path.join", side_effect=lambda *a: "/".join(a)),
        patch("builtins.open", MagicMock()),
        # Keep timeout tests hermetic — the mock proc.pid=42 would otherwise
        # target a real process group when killpg fires (reviewer P2).
        patch("aigate.sandbox.birdcage_backend.os.getpgid", return_value=42),
        patch("aigate.sandbox.birdcage_backend.os.killpg"),
        # Phase 2: select_linux_observer → None keeps existing tests hermetic
        # (observer is None path = Phase 1b behaviour on any platform).
        patch("aigate.sandbox.birdcage_backend.select_linux_observer", return_value=None),
        # Default platform to Darwin so hermetic tests don't trip the Linux
        # REV-F "no observer → error" branch unless they opt into Linux via
        # _linux_observer_cm. Individual Linux-path tests override this.
        patch("aigate.sandbox.birdcage_backend.platform.system", return_value="Darwin"),
    ):
        backend = BirdcageBackend()
        return await backend.run(request)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_happy_path_returns_populated_trace():
    proc = _mock_proc(returncode=0, stdout=_FIVE_EVENTS_STDOUT)
    trace = await _run_with_mock(proc)

    assert trace.ran is True
    assert trace.timeout is False
    assert trace.error is None
    assert trace.runtime == "birdcage"
    assert trace.canary is not None

    real_events = [e for e in trace.events if getattr(e, "source", None) != "resource_probe"]
    assert len(real_events) == 5

    synthetic_events = [e for e in trace.events if getattr(e, "source", None) == "resource_probe"]
    assert len(synthetic_events) >= 1

    kinds = {e.kind for e in real_events}
    assert kinds == {"exec", "open", "write", "connect", "dns"}


async def test_happy_path_fs_writes_observed():
    proc = _mock_proc(returncode=0, stdout=_FIVE_EVENTS_STDOUT)
    trace = await _run_with_mock(proc)
    assert SandboxCoverage.FS_WRITES in trace.observed


async def test_happy_path_no_unexpected_skips():
    # macOS path: no observer, no Linux REV-F block → skipped_unexpected stays empty.
    proc = _mock_proc(returncode=0, stdout=_FIVE_EVENTS_STDOUT)
    with patch("aigate.sandbox.birdcage_backend.platform.system", return_value="Darwin"):
        trace = await _run_with_mock(proc)
    assert trace.skipped_unexpected == set()


async def test_happy_path_linux_observer_network_capture_observed():
    """Phase 2 REV-F: Linux + strace observer + ≥1 real event → NETWORK_CAPTURE in observed."""
    real_event = DynamicTraceEvent(kind="connect", ts_ms=1, pid=42, process="", target="1.2.3.4:80")
    mock_observer = _mock_strace_observer(real_event)

    # os.read: first call (drain phase) returns strace bytes; second raises BlockingIOError.
    _read_calls = [0]

    def _read_side(fd, n):
        _read_calls[0] += 1
        if _read_calls[0] == 1:
            # RFC 5737 TEST-NET-1 connect event (non-routable)
            return (
                b"1234 connect(4, {sa_family=AF_INET, sin_port=htons(80),"
                b' sin_addr=inet_addr("192.0.2.1")}, 16) = 0\n'
            )
        raise BlockingIOError

    proc = _mock_proc(returncode=0, stdout=b"")
    request = _request(timeout_s=10)

    base_cms = [
        patch("aigate.sandbox.birdcage_backend.shutil.which", side_effect=_patch_which),
        patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
        patch("tempfile.mkdtemp", return_value="/tmp/aigate-sandbox-test"),
        patch("os.path.join", side_effect=lambda *a: "/".join(a)),
        patch("builtins.open", MagicMock()),
        patch("aigate.sandbox.birdcage_backend.os.getpgid", return_value=99),
        patch("aigate.sandbox.birdcage_backend.os.killpg"),
    ]
    with contextlib.ExitStack() as stack:
        for cm in base_cms + _linux_observer_cm(mock_observer, read_side_effect=_read_side):
            stack.enter_context(cm)
        backend = BirdcageBackend()
        trace = await backend.run(request)

    assert SandboxCoverage.NETWORK_CAPTURE in trace.observed
    assert SandboxCoverage.FS_WRITES in trace.observed
    assert trace.skipped_unexpected == set()
    assert trace.has_observation_failure() is False


# ---------------------------------------------------------------------------
# Timeout path
# ---------------------------------------------------------------------------


async def test_timeout_sets_timeout_flag():
    async def _slow_communicate():
        await asyncio.sleep(30)
        return b"", b""

    proc = _mock_proc(returncode=None)
    proc.communicate = _slow_communicate

    trace = await _run_with_mock(proc, timeout_s=1)

    assert trace.ran is True
    assert trace.timeout is True
    assert trace.error is not None
    assert "timeout" in trace.error.lower()
    assert str(1) in trace.error  # timeout_s in message


async def test_timeout_proc_kill_called():
    async def _slow_communicate():
        await asyncio.sleep(30)
        return b"", b""

    proc = _mock_proc(returncode=None)
    proc.communicate = _slow_communicate

    await _run_with_mock(proc, timeout_s=1)

    proc.kill.assert_called_once()


# ---------------------------------------------------------------------------
# Non-zero exit
# ---------------------------------------------------------------------------


async def test_nonzero_exit_sets_error():
    stderr_msg = b"npm ERR! code ENOENT\nnpm ERR! syscall open"
    proc = _mock_proc(returncode=1, stdout=b"", stderr=stderr_msg)
    trace = await _run_with_mock(proc)

    assert trace.ran is True
    assert trace.error is not None
    assert "birdcage exited rc=1" in trace.error


async def test_nonzero_exit_stderr_in_error():
    stderr_msg = b"fatal: something went wrong"
    proc = _mock_proc(returncode=2, stdout=b"", stderr=stderr_msg)
    trace = await _run_with_mock(proc)

    assert "stderr=" in trace.error


# ---------------------------------------------------------------------------
# Parser drift
# ---------------------------------------------------------------------------


async def test_ten_non_json_lines_triggers_drift():
    proc = _mock_proc(returncode=0, stdout=_TEN_NON_JSON_LINES)
    trace = await _run_with_mock(proc)

    assert trace.ran is True
    assert SandboxCoverage.PARSER_PARTIAL_DRIFT in trace.skipped_unexpected
    assert trace.error is not None
    assert "schema drift" in trace.error or "partial Birdcage schema drift" in trace.error


async def test_ten_non_json_lines_observation_failure():
    proc = _mock_proc(returncode=0, stdout=_TEN_NON_JSON_LINES)
    trace = await _run_with_mock(proc)
    # skipped_unexpected is non-empty → has_observation_failure() is True
    assert trace.has_observation_failure() is True


# ---------------------------------------------------------------------------
# Synthetic exec event always present
# ---------------------------------------------------------------------------


async def test_synthetic_exec_event_present_even_on_empty_stdout():
    proc = _mock_proc(returncode=0, stdout=b"")
    trace = await _run_with_mock(proc)

    synthetic = [e for e in trace.events if getattr(e, "source", None) == "resource_probe"]
    assert len(synthetic) >= 1
    assert any(e.kind == "exec" for e in synthetic)


# ---------------------------------------------------------------------------
# Phase 2 REV-C: teardown kills observer_pgid (not birdcage_pgid)
# ---------------------------------------------------------------------------


async def test_teardown_kills_observer_pgid_cascades_to_birdcage():
    """REV-C: timeout → os.killpg called with observer_pgid (99), never birdcage_pgid.

    strace is the PGID leader (start_new_session=True).  SIGKILL on observer_pgid
    cascades via PTRACE_O_TRACECLONE (-f) to the entire birdcage subtree.
    """

    async def _slow_communicate():
        await asyncio.sleep(30)
        return b"", b""

    proc = _mock_proc(returncode=None)
    proc.communicate = _slow_communicate

    mock_observer = _mock_strace_observer(real_event=None)
    killpg_calls: list[tuple[int, int]] = []

    def _track_killpg(pgid: int, sig: int) -> None:
        killpg_calls.append((pgid, sig))

    base_cms = [
        patch("aigate.sandbox.birdcage_backend.shutil.which", side_effect=_patch_which),
        patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
        patch("tempfile.mkdtemp", return_value="/tmp/aigate-sandbox-test"),
        patch("os.path.join", side_effect=lambda *a: "/".join(a)),
        patch("builtins.open", MagicMock()),
        # observer_pgid = 99 (strace is PGID leader per REV-C)
        patch("aigate.sandbox.birdcage_backend.os.getpgid", return_value=99),
        patch("aigate.sandbox.birdcage_backend.os.killpg", side_effect=_track_killpg),
    ]
    with contextlib.ExitStack() as stack:
        for cm in base_cms + _linux_observer_cm(mock_observer, read_side_effect=BlockingIOError):
            stack.enter_context(cm)
        backend = BirdcageBackend()
        trace = await backend.run(_request(timeout_s=1))

    # REV-C invariant: observer_pgid (99) was killed, NOT birdcage_pgid (42 = proc.pid)
    assert any(pgid == 99 for pgid, _ in killpg_calls), (
        f"observer_pgid 99 not killed; killpg calls: {killpg_calls}"
    )
    # birdcage_pgid (42) must never be the target when observer is present
    assert not any(pgid == 42 for pgid, _ in killpg_calls), (
        "birdcage_pgid 42 must not be killed directly when observer is present"
    )
    assert trace.timeout is True
    assert trace.has_observation_failure() is True


# ---------------------------------------------------------------------------
# Phase 2 REV-F: evidence-based NETWORK_CAPTURE classification
# ---------------------------------------------------------------------------


async def test_linux_no_observer_network_capture_in_skipped_unexpected():
    """REV-F: Linux + observer=None → NETWORK_CAPTURE in skipped_unexpected."""
    proc = _mock_proc(returncode=0, stdout=b"")
    with (
        patch("aigate.sandbox.birdcage_backend.shutil.which", side_effect=_patch_which),
        patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
        patch("tempfile.mkdtemp", return_value="/tmp/aigate-sandbox-test"),
        patch("os.path.join", side_effect=lambda *a: "/".join(a)),
        patch("builtins.open", MagicMock()),
        patch("aigate.sandbox.birdcage_backend.os.getpgid", return_value=42),
        patch("aigate.sandbox.birdcage_backend.os.killpg"),
        patch("aigate.sandbox.birdcage_backend.platform.system", return_value="Linux"),
        patch("aigate.sandbox.birdcage_backend.select_linux_observer", return_value=None),
    ):
        backend = BirdcageBackend()
        trace = await backend.run(_request())

    assert SandboxCoverage.NETWORK_CAPTURE in trace.skipped_unexpected
    assert trace.error is not None
    assert "install strace" in trace.error
    assert trace.has_observation_failure() is True


async def test_linux_observer_silent_zero_real_events_fails_closed():
    """REV-F + REV-B: observer attached but 0 real events → observer_silent fail-closed."""
    # os.read always raises BlockingIOError → 0 events parsed from FIFO
    mock_observer = _mock_strace_observer(real_event=None)
    proc = _mock_proc(returncode=0, stdout=b"")

    base_cms = [
        patch("aigate.sandbox.birdcage_backend.shutil.which", side_effect=_patch_which),
        patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
        patch("tempfile.mkdtemp", return_value="/tmp/aigate-sandbox-test"),
        patch("os.path.join", side_effect=lambda *a: "/".join(a)),
        patch("builtins.open", MagicMock()),
        patch("aigate.sandbox.birdcage_backend.os.getpgid", return_value=99),
        patch("aigate.sandbox.birdcage_backend.os.killpg"),
    ]
    with contextlib.ExitStack() as stack:
        for cm in base_cms + _linux_observer_cm(mock_observer, read_side_effect=BlockingIOError):
            stack.enter_context(cm)
        backend = BirdcageBackend()
        trace = await backend.run(_request())

    assert SandboxCoverage.NETWORK_CAPTURE in trace.skipped_unexpected
    assert trace.error is not None
    assert "observer_silent" in trace.error
    assert trace.has_observation_failure() is True
