"""E2E tests: fail-closed behaviour when strace observer is unavailable.

Gate: AIGATE_RUN_E2E=1 env var must be set.
Platform: Linux only (observer logic is Linux-specific in birdcage_backend).

REV-F §"observer is None" branch:
  When ``select_linux_observer()`` returns None (strace not on PATH, or
  observer probe fails), BirdcageBackend must:
  - Add NETWORK_CAPTURE to ``skipped_unexpected`` (fail-closed).
  - Set ``trace.error`` to a human-readable message about the missing observer.
  - NOT crash or raise — always return a DynamicTrace.

The "observer missing" condition is induced by monkeypatching
``select_linux_observer`` to return None, regardless of what binaries are
installed on the host.  This lets the test run even when strace IS installed
(to verify that the code path exists), which is the common CI configuration.

Prereqs: birdcage + npm on PATH (strace presence is irrelevant here; we
override it).  test skips if birdcage or npm are absent.
"""

from __future__ import annotations

import io
import json
import os
import platform
import shutil
import tarfile

import pytest

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

_E2E_GATE = pytest.mark.skipif(
    not os.environ.get("AIGATE_RUN_E2E"),
    reason="AIGATE_RUN_E2E=1 not set — e2e test skipped",
)
_LINUX_GATE = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="REV-F observer-missing path is Linux-specific",
)

pytestmark = [_E2E_GATE, _LINUX_GATE]


def _prereqs() -> None:
    missing = [b for b in ("birdcage", "npm") if shutil.which(b) is None]
    if missing:
        pytest.skip(f"Missing required binaries: {missing}")


@pytest.fixture(autouse=True)
def _check_prereqs():
    _prereqs()


# ---------------------------------------------------------------------------
# Minimal tarball fixture
# ---------------------------------------------------------------------------


def _make_tarball(tmp_path) -> str:
    pkg_json = json.dumps(
        {"name": "aigate-e2e-no-observer-pkg", "version": "1.0.0"}
    ).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(pkg_json)
        tf.addfile(info, io.BytesIO(pkg_json))
    tgz = str(tmp_path / "aigate-e2e-no-observer-pkg-1.0.0.tgz")
    with open(tgz, "wb") as f:
        f.write(buf.getvalue())
    return tgz


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from aigate.sandbox.birdcage_backend import BirdcageBackend  # noqa: E402
from aigate.sandbox.types import (  # noqa: E402
    DynamicTrace,
    SandboxCoverage,
    SandboxRunRequest,
)

# ---------------------------------------------------------------------------
# E2E tests — observer-missing (REV-F fail-closed path)
# ---------------------------------------------------------------------------


class TestE2EObserverMissing:
    @pytest.fixture()
    def no_observer(self, monkeypatch):
        """Patch select_linux_observer to return None regardless of PATH."""
        import aigate.sandbox.birdcage_backend as bb

        monkeypatch.setattr(bb, "select_linux_observer", lambda: None)

    @pytest.mark.asyncio
    async def test_returns_dynamic_trace_not_exception(self, tmp_path, no_observer):
        """BirdcageBackend.run() never raises when observer is missing."""
        tarball = _make_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-no-observer-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        # Must return a DynamicTrace, never raise
        trace = await BirdcageBackend().run(request)
        assert isinstance(trace, DynamicTrace)

    @pytest.mark.asyncio
    async def test_network_capture_in_skipped_unexpected(self, tmp_path, no_observer):
        """REV-F: NETWORK_CAPTURE is fail-closed in skipped_unexpected when observer=None."""
        tarball = _make_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-no-observer-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)
        assert SandboxCoverage.NETWORK_CAPTURE in trace.skipped_unexpected, (
            "REV-F: observer=None must add NETWORK_CAPTURE to skipped_unexpected; "
            f"got skipped_unexpected={trace.skipped_unexpected}"
        )

    @pytest.mark.asyncio
    async def test_error_message_set_when_observer_missing(self, tmp_path, no_observer):
        """trace.error is set to a human-readable message when observer is None."""
        tarball = _make_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-no-observer-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)
        assert trace.error is not None, (
            "trace.error must be set when observer is missing; got None"
        )
        assert "observer" in trace.error.lower() or "strace" in trace.error.lower(), (
            f"trace.error should mention the missing observer; got: {trace.error!r}"
        )

    @pytest.mark.asyncio
    async def test_network_capture_not_in_observed(self, tmp_path, no_observer):
        """REV-F: NETWORK_CAPTURE must NOT appear in trace.observed when observer=None."""
        tarball = _make_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-no-observer-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)
        assert SandboxCoverage.NETWORK_CAPTURE not in trace.observed, (
            "NETWORK_CAPTURE must not be in observed when observer is missing; "
            f"got observed={trace.observed}"
        )

    @pytest.mark.asyncio
    async def test_has_observation_failure_true(self, tmp_path, no_observer):
        """has_observation_failure() must be True when NETWORK_CAPTURE is unexpected-skipped."""
        tarball = _make_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-no-observer-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)
        assert trace.has_observation_failure(), (
            "has_observation_failure() must return True when observer is missing; "
            f"skipped_unexpected={trace.skipped_unexpected}, error={trace.error!r}"
        )

    @pytest.mark.asyncio
    async def test_ran_is_true_even_without_observer(self, tmp_path, no_observer):
        """trace.ran must be True — birdcage still ran even without an observer."""
        tarball = _make_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-no-observer-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)
        assert trace.ran, "trace.ran must be True even when observer is missing"
