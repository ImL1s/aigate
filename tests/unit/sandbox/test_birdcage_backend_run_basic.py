"""Unit tests for BirdcageBackend.run() — subprocess mocked.

Covers:
- Happy path: exits 0, 5 valid events parsed, synthetic events present.
- Timeout: communicate() times out → trace.timeout=True, error set.
- Non-zero exit: rc=1 with stderr → trace.error contains "birdcage exited rc=1".
- Parser drift: 10 non-JSON lines → PARSER_PARTIAL_DRIFT in skipped_unexpected.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from aigate.sandbox.birdcage_backend import BirdcageBackend
from aigate.sandbox.types import SandboxCoverage, SandboxMode, SandboxRunRequest


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


_FIVE_EVENTS_STDOUT = "\n".join([
    '{"kind":"exec","ts_ms":1,"pid":42,"process":"npm","target":"/usr/bin/node"}',
    '{"kind":"open","ts_ms":2,"pid":42,"process":"npm","target":"/tmp/pkg/package.json"}',
    '{"kind":"write","ts_ms":3,"pid":42,"process":"npm","target":"/tmp/pkg/node_modules"}',
    '{"kind":"connect","ts_ms":4,"pid":42,"process":"node","target":"127.0.0.1:1"}',
    '{"kind":"dns","ts_ms":5,"pid":42,"process":"node","target":"localhost"}',
]).encode()

_TEN_NON_JSON_LINES = b"\n".join(
    [b"npm warn deprecated old-pkg@1.0.0"] * 10
)


def _patch_which(name: str) -> str:
    return f"/usr/bin/{name}"


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
    proc = _mock_proc(returncode=0, stdout=_FIVE_EVENTS_STDOUT)
    trace = await _run_with_mock(proc)
    assert trace.skipped_unexpected == set()


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
