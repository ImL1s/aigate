"""E2E: sandbox runs a net.connect postinstall and observes the attempt.

Uses tests/fixtures/fake_npm_net_connect_bypass — a minimal npm package whose
postinstall.js fires net.connect to 192.0.2.1:65535 (RFC 5737 TEST-NET-1,
non-routable) then exits after 100 ms.

Assertions:
- trace.events contains a "connect" event targeting 192.0.2.1 OR
  trace.has_observation_failure() returns True (sandbox observed the attempt
  at the kernel level but parse-layer didn't match — still a non-SAFE outcome).

Skipped when birdcage is not installed (real sandbox binary required).
"""

from __future__ import annotations

import shutil
import tarfile
from pathlib import Path

import pytest

from aigate.sandbox.birdcage_backend import BirdcageBackend
from aigate.sandbox.types import SandboxMode, SandboxRunRequest

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "fake_npm_net_connect_bypass"

pytestmark = pytest.mark.skipif(
    shutil.which("birdcage") is None,
    reason="birdcage binary not on PATH — install via `cargo install birdcage`",
)


def _make_fixture_tarball(tmp_path: Path) -> str:
    """Wrap the fixture package into a .tgz that npm install can consume."""
    tarball = tmp_path / "fake-npm-net-connect-bypass-1.0.0.tgz"
    with tarfile.open(str(tarball), "w:gz") as tar:
        tar.add(str(FIXTURE_DIR), arcname="package")
    return str(tarball)


async def test_net_connect_postinstall_observed_or_observation_failure(tmp_path):
    """Sandbox must detect or flag the net.connect postinstall attempt."""
    backend = BirdcageBackend()
    if not backend.check_available():
        pytest.skip("birdcage on PATH but check_available()=False (connect-observer missing)")

    tarball = _make_fixture_tarball(tmp_path)
    request = SandboxRunRequest(
        package_name="fake-npm-net-connect-bypass",
        version="1.0.0",
        ecosystem="npm",
        source_archive_path=tarball,
        mode=SandboxMode.LIGHT,
        timeout_s=30,
    )

    trace = await backend.run(request)

    connect_events = [e for e in trace.events if e.kind == "connect" and "192.0.2.1" in e.target]
    observation_failure = trace.has_observation_failure()

    assert connect_events or observation_failure, (
        "Expected either a connect event to 192.0.2.1 or has_observation_failure()=True. "
        f"events={[e.kind for e in trace.events]!r}, "
        f"has_observation_failure={observation_failure}, "
        f"error={trace.error!r}"
    )


async def test_fixture_tarball_contains_postinstall_js(tmp_path):
    """Sanity: fixture tarball includes postinstall.js with net.connect code."""
    tarball = _make_fixture_tarball(tmp_path)
    with tarfile.open(tarball, "r:gz") as tar:
        names = tar.getnames()

    assert any("postinstall.js" in n for n in names), (
        f"postinstall.js not found in tarball members: {names}"
    )
    assert any("package.json" in n for n in names), (
        f"package.json not found in tarball members: {names}"
    )


async def test_fixture_postinstall_contains_net_connect():
    """Sanity: postinstall.js source contains the net.connect call."""
    postinstall = FIXTURE_DIR / "postinstall.js"
    assert postinstall.exists(), f"fixture missing: {postinstall}"
    content = postinstall.read_text()
    assert "net" in content and "connect" in content, (
        f"postinstall.js doesn't contain net.connect: {content!r}"
    )
    assert "192.0.2.1" in content, "Expected RFC 5737 TEST-NET-1 address in postinstall.js"
