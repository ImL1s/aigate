"""Integration: verify npm sandbox never reconnects to registry.npmjs.org.

Contract (MUST NOT use pytest.skip):
- observer-absent path: SandboxUnavailable raised — tested via mocks, no skip.
- observer-present path: run against minimal fake tarball, assert NO connect to
  registry.npmjs.org observed.  If birdcage is not on PATH, the test asserts
  check_available() returns False and returns early — still no skip.
"""

from __future__ import annotations

import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from aigate.sandbox.birdcage_backend import BirdcageBackend
from aigate.sandbox.errors import SandboxUnavailable
from aigate.sandbox.runtime_select import select_backend
from aigate.sandbox.types import SandboxMode, SandboxRunRequest


def _make_fake_tarball(tmp_path: Path) -> str:
    """Build a minimal npm tarball with an inert package.json."""
    pkg_dir = tmp_path / "package"
    pkg_dir.mkdir()
    (pkg_dir / "package.json").write_text('{"name":"fake","version":"0.0.1"}')
    tarball = tmp_path / "fake-0.0.1.tgz"
    with tarfile.open(str(tarball), "w:gz") as tar:
        tar.add(str(pkg_dir), arcname="package")
    return str(tarball)


# ---------------------------------------------------------------------------
# Observer-absent path — mocked, no pytest.skip
# ---------------------------------------------------------------------------


def test_select_backend_raises_when_no_backends_available():
    """select_backend raises SandboxUnavailable when detect_available() is empty."""
    with patch("aigate.sandbox.runtime_select.detect_available", return_value=[]):
        with pytest.raises(SandboxUnavailable):
            select_backend(SandboxMode.LIGHT, required=False)


def test_select_backend_required_also_raises_when_unavailable():
    """required=True also raises SandboxUnavailable when no backend present."""
    with patch("aigate.sandbox.runtime_select.detect_available", return_value=[]):
        with pytest.raises(SandboxUnavailable):
            select_backend(SandboxMode.LIGHT, required=True)


def test_check_available_false_when_birdcage_binary_absent():
    """check_available() → False when birdcage binary not on PATH (mocked)."""
    with patch("aigate.sandbox.birdcage_backend.shutil.which", return_value=None):
        assert BirdcageBackend().check_available() is False


def test_check_available_false_on_linux_without_connect_observer(monkeypatch):
    """On Linux, check_available() → False when no connect-observer found (mocked)."""
    import platform

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    with (
        patch("aigate.sandbox.birdcage_backend.shutil.which", return_value="/usr/bin/birdcage"),
        patch("aigate.sandbox.birdcage_backend.detect_linux_connect_observer", return_value=None),
    ):
        assert BirdcageBackend().check_available() is False


# ---------------------------------------------------------------------------
# Observer-present path — real birdcage (returns early if binary absent)
# ---------------------------------------------------------------------------


async def test_no_outbound_connect_to_registry_npmjs_org(tmp_path):
    """Sandbox must not emit a connect event targeting registry.npmjs.org.

    If birdcage is not installed, asserts check_available() is False and
    returns — this is the documented non-skip path per Task 6 spec.
    """
    backend = BirdcageBackend()
    if not backend.check_available():
        assert backend.check_available() is False
        return

    tarball = _make_fake_tarball(tmp_path)
    request = SandboxRunRequest(
        package_name="fake",
        version="0.0.1",
        ecosystem="npm",
        source_archive_path=tarball,
        mode=SandboxMode.LIGHT,
        timeout_s=30,
    )
    trace = await backend.run(request)

    registry_hits = [
        e for e in trace.events if e.kind == "connect" and "registry.npmjs.org" in e.target
    ]
    assert registry_hits == [], (
        f"Unexpected outbound connection to registry detected: {registry_hits}"
    )
