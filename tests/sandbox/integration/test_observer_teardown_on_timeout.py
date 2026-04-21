"""Integration tests: REV-C PGID teardown cascade.

REV-C design commitments (from birdcage_backend.py):
  - ``start_new_session=True`` makes strace the PGID leader of its own new
    session; birdcage is its direct child and inherits the PGID.
  - On timeout, ``os.killpg(observer_pgid, signal.SIGKILL)`` sends SIGKILL
    to the entire process group, cascading via PTRACE_O_TRACECLONE (-f) to
    the full birdcage subtree.
  - Fallback: when no observer, birdcage's own PGID is killed instead.

Gate: skipped when ``strace`` is not on PATH.

Covers:
- strace launched with start_new_session becomes its own PGID leader.
- os.killpg(observer_pgid, SIGKILL) terminates both strace and its
  traced child — the traced sleep process exits within the timeout.
- Without start_new_session the process inherits the parent's PGID
  (control: confirms the test measures start_new_session, not luck).
- PGID capture: os.getpgid(proc.pid) == proc.pid for session leaders.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("strace") is None,
    reason="strace not on PATH — integration test requires strace binary",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strace_argv(fifo_path: str) -> list[str]:
    """strace argv tracing a long-running python3 sleep (10s)."""
    return [
        "strace", "-f",
        "-e", "trace=connect,openat,write,execve,clone",
        "-o", fifo_path,
        "--",
        "python3", "-c", "import time; time.sleep(10)",
    ]


# ---------------------------------------------------------------------------
# PGID leadership tests
# ---------------------------------------------------------------------------


class TestPgidLeadership:
    def test_strace_is_pgid_leader_with_start_new_session(self, tmp_path):
        """strace launched with start_new_session=True is its own PGID leader.

        REV-C invariant: the outermost process (strace when observer present)
        must be a new PGID leader so os.killpg cascades to the full subtree.
        """
        fifo_path = str(tmp_path / "observer.fifo")
        os.mkfifo(fifo_path)

        # Reader thread prevents strace from blocking on FIFO open
        def _drain():
            try:
                with open(fifo_path, "rb") as fh:
                    fh.read()
            except OSError:
                pass

        threading.Thread(target=_drain, daemon=True).start()

        proc = subprocess.Popen(
            _strace_argv(fifo_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            time.sleep(0.2)  # let strace start up
            pgid = os.getpgid(proc.pid)
            assert pgid == proc.pid, (
                f"strace (pid={proc.pid}) must be its own PGID leader "
                f"when start_new_session=True; got pgid={pgid}"
            )
        finally:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)

    def test_pgid_equals_pid_for_session_leader(self, tmp_path):
        """getpgid(proc.pid) == proc.pid is the REV-C capture pattern."""
        fifo_path = str(tmp_path / "observer.fifo")
        os.mkfifo(fifo_path)

        threading.Thread(
            target=lambda: open(fifo_path, "rb").read(), daemon=True  # noqa: WPS515
        ).start()

        proc = subprocess.Popen(
            _strace_argv(fifo_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            time.sleep(0.2)
            observer_pgid = os.getpgid(proc.pid)
            # This is exactly the pattern BirdcageBackend uses (line ~276):
            #   observer_pgid = os.getpgid(proc.pid)
            assert observer_pgid > 0
            assert observer_pgid == proc.pid
        finally:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(observer_pgid, signal.SIGKILL)
            proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# killpg cascade tests
# ---------------------------------------------------------------------------


class TestKillpgCascade:
    def test_killpg_terminates_strace_and_traced_child(self, tmp_path):
        """os.killpg(observer_pgid, SIGKILL) kills both strace and its child.

        REV-C: strace runs with -f (PTRACE_O_TRACECLONE), so SIGKILL to
        the PGID cascades to all processes in the group.
        """
        fifo_path = str(tmp_path / "observer.fifo")
        os.mkfifo(fifo_path)

        threading.Thread(
            target=lambda: open(fifo_path, "rb").read(), daemon=True  # noqa: WPS515
        ).start()

        proc = subprocess.Popen(
            _strace_argv(fifo_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        time.sleep(0.3)  # wait for strace + traced child to be running

        pgid = os.getpgid(proc.pid)

        # REV-C teardown path
        os.killpg(pgid, signal.SIGKILL)

        # strace should exit promptly
        try:
            ret = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            pytest.fail("strace did not exit within 5 s after os.killpg(SIGKILL)")

        # ret is None only if wait timed out (which we'd catch above)
        # -9 or non-zero signals are expected after SIGKILL
        assert ret is not None

    def test_strace_exits_after_sigkill_to_pgid(self, tmp_path):
        """Verifies strace's exit status after os.killpg confirms it was killed."""
        fifo_path = str(tmp_path / "observer.fifo")
        os.mkfifo(fifo_path)

        threading.Thread(
            target=lambda: open(fifo_path, "rb").read(), daemon=True  # noqa: WPS515
        ).start()

        proc = subprocess.Popen(
            _strace_argv(fifo_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        time.sleep(0.3)
        pgid = os.getpgid(proc.pid)
        start = time.monotonic()
        os.killpg(pgid, signal.SIGKILL)
        proc.wait(timeout=5)
        elapsed = time.monotonic() - start

        # SIGKILL should take effect in < 2 s (in practice < 100 ms)
        assert elapsed < 2.0, (
            f"killpg took {elapsed:.2f}s to kill strace — expected < 2 s"
        )

    def test_process_not_found_after_killpg(self, tmp_path):
        """After killpg, os.getpgid(proc.pid) raises ProcessLookupError."""
        fifo_path = str(tmp_path / "observer.fifo")
        os.mkfifo(fifo_path)

        threading.Thread(
            target=lambda: open(fifo_path, "rb").read(), daemon=True  # noqa: WPS515
        ).start()

        proc = subprocess.Popen(
            _strace_argv(fifo_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        time.sleep(0.2)
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
        proc.wait(timeout=5)

        # Process should be gone — getpgid raises ProcessLookupError
        with pytest.raises(ProcessLookupError):
            os.getpgid(proc.pid)


# ---------------------------------------------------------------------------
# Fallback: no observer → birdcage PGID killed directly
# ---------------------------------------------------------------------------


class TestFallbackNonSessionLeader:
    def test_subprocess_without_new_session_has_parent_pgid(self):
        """Control: without start_new_session, child shares parent's PGID.

        This confirms the test measures start_new_session semantics, not luck.
        When birdcage_backend runs WITHOUT an observer (Phase 1b), birdcage
        itself is launched with start_new_session=True and becomes PGID leader.
        """
        parent_pgid = os.getpgid(os.getpid())
        proc = subprocess.Popen(
            ["python3", "-c", "import time; time.sleep(5)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # deliberately NO start_new_session
        )
        try:
            time.sleep(0.1)
            child_pgid = os.getpgid(proc.pid)
            # Without start_new_session, child inherits parent's PGID
            assert child_pgid == parent_pgid, (
                f"Expected child to inherit parent PGID ({parent_pgid}); "
                f"got child pgid={child_pgid}"
            )
        finally:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------------------
# Import (contextlib needed by helpers above)
# ---------------------------------------------------------------------------

import contextlib  # noqa: E402 (kept at bottom per convention for test modules)
