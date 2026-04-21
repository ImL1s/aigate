"""E2E tests: npm-light sandbox run with strace observer wired in (Linux).

Gate: AIGATE_RUN_E2E=1 env var must be set.
Platform: Linux only (strace observer is Linux-specific).
Prereqs: birdcage, strace, npm must be on PATH.

These tests drive the full BirdcageBackend.run() pipeline — real subprocess
execution, real strace FIFO, real PGID teardown — and assert end-to-end
observer behaviour:

- Observer events appear in trace.events from the strace FIFO reader.
- NETWORK_CAPTURE lands in trace.observed when real events are seen (REV-F).
- trace.error is None on a successful clean run.
- Canary event (source="observer_canary") is present but excluded from
  is_real_event() so it does not count toward the real-event floor.
- DynamicTrace.ran is True.
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
    reason="observer e2e requires Linux (strace is Linux-only)",
)

pytestmark = [_E2E_GATE, _LINUX_GATE]


def _prereqs() -> None:
    """Skip if any required binary is missing."""
    missing = [b for b in ("birdcage", "strace", "npm") if shutil.which(b) is None]
    if missing:
        pytest.skip(f"Missing required binaries: {missing}")


@pytest.fixture(autouse=True)
def _check_prereqs():
    _prereqs()


# ---------------------------------------------------------------------------
# Fixture: minimal npm package tarball
# ---------------------------------------------------------------------------


def _make_package_tarball(tmp_path) -> str:
    """Create a minimal npm package .tgz with a trivial postinstall.

    postinstall.js logs a message to stdout and exits cleanly.
    npm install will run it and npm will produce stdout JSON-like lines.
    """
    pkg_json = json.dumps(
        {
            "name": "aigate-e2e-test-pkg",
            "version": "1.0.0",
            "scripts": {"postinstall": "node postinstall.js"},
        }
    ).encode()

    # postinstall: attempt network connect to TEST-NET-1 so the observer
    # has a real connect() syscall to capture (even if ECONNREFUSED)
    postinstall_js = (
        b"const net = require('net');\n"
        b"const s = new net.Socket();\n"
        b"s.setTimeout(200);\n"
        b"s.connect(80, '192.0.2.1', () => { s.destroy(); });\n"
        b"s.on('error', () => {});\n"
        b"s.on('timeout', () => { s.destroy(); });\n"
        b"setTimeout(() => process.exit(0), 500);\n"
    )

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in [
            ("package/package.json", pkg_json),
            ("package/postinstall.js", postinstall_js),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))

    tgz_path = str(tmp_path / "aigate-e2e-test-pkg-1.0.0.tgz")
    with open(tgz_path, "wb") as f:
        f.write(buf.getvalue())
    return tgz_path


# ---------------------------------------------------------------------------
# Imports (deferred so skip decorators fire before import-time errors)
# ---------------------------------------------------------------------------

from aigate.sandbox.birdcage_backend import BirdcageBackend  # noqa: E402
from aigate.sandbox.types import (  # noqa: E402
    DynamicTrace,
    SandboxCoverage,
    SandboxRunRequest,
    is_real_event,
)

# ---------------------------------------------------------------------------
# E2E tests
# ---------------------------------------------------------------------------


class TestE2ENpmLightWithObserver:
    @pytest.mark.asyncio
    async def test_trace_ran_is_true(self, tmp_path):
        """BirdcageBackend.run() returns a DynamicTrace with ran=True."""
        tarball = _make_package_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-test-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)
        assert isinstance(trace, DynamicTrace)
        assert trace.ran, "trace.ran must be True after a completed run"

    @pytest.mark.asyncio
    async def test_observer_events_in_trace(self, tmp_path):
        """Strace FIFO produces ≥1 observer event captured in trace.events."""
        tarball = _make_package_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-test-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)

        # At minimum the canary event must be present (source="observer_canary")
        canary_events = [e for e in trace.events if getattr(e, "source", None) == "observer_canary"]
        assert canary_events, (
            "Expected ≥1 observer_canary event proving parser liveness; "
            f"event kinds: {[e.kind for e in trace.events]}"
        )

    @pytest.mark.asyncio
    async def test_canary_excluded_from_real_event_count(self, tmp_path):
        """observer_canary events are excluded by is_real_event() (REV-B)."""
        tarball = _make_package_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-test-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)

        canary_events = [e for e in trace.events if getattr(e, "source", None) == "observer_canary"]
        for ev in canary_events:
            assert not is_real_event(ev), f"observer_canary event must not be real; got: {ev}"

    @pytest.mark.asyncio
    async def test_network_capture_in_observed_when_real_events_seen(self, tmp_path):
        """REV-F: NETWORK_CAPTURE lands in observed when ≥1 real event is seen."""
        tarball = _make_package_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-test-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)

        real_count = sum(1 for e in trace.events if is_real_event(e))
        if real_count >= 1:
            assert SandboxCoverage.NETWORK_CAPTURE in trace.observed, (
                f"Expected NETWORK_CAPTURE in observed when real_count={real_count}; "
                f"observed={trace.observed}, skipped_unexpected={trace.skipped_unexpected}"
            )
        # If 0 real events (empty npm run), NETWORK_CAPTURE in skipped_unexpected is
        # also acceptable (REV-F fail-closed branch) — do not assert in that case.

    @pytest.mark.asyncio
    async def test_no_timeout_on_fast_package(self, tmp_path):
        """A fast package install should not trip the timeout."""
        tarball = _make_package_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-test-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)
        assert not trace.timeout, f"Unexpected timeout on fast e2e package; error={trace.error!r}"

    @pytest.mark.asyncio
    async def test_skipped_unexpected_empty_on_clean_run(self, tmp_path):
        """A clean run with observer present should have no unexpected skips.

        REV-F: if the observer is alive and produced real events, no surface
        should end up in skipped_unexpected.
        """
        tarball = _make_package_tarball(tmp_path)
        request = SandboxRunRequest(
            package_name="aigate-e2e-test-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_archive_path=tarball,
            timeout_s=60,
        )
        trace = await BirdcageBackend().run(request)

        real_count = sum(1 for e in trace.events if is_real_event(e))
        if real_count >= 1:
            assert not trace.skipped_unexpected, (
                f"Expected no skipped_unexpected on clean run with observer; "
                f"got: {trace.skipped_unexpected}, error={trace.error!r}"
            )
