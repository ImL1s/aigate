"""End-to-end detection tests.

Runs aigate's prefilter pipeline against synthetic malicious packages
served by a local pypiserver.  No mocking -- real download, real extract,
real prefilter analysis.

Requires: AIGATE_E2E=1 (set by docker compose)
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import httpx
import pytest

from tests.e2e.build_packages import FIXTURES

PYPI_URL = os.environ.get("AIGATE_E2E_PYPI_URL", "http://localhost:8080/simple/")
E2E = os.environ.get("AIGATE_E2E") == "1"


# Build parametrize lists from the canonical FIXTURES in build_packages.py.
# Determine ecosystem from the file paths: package.json → npm, setup.py → pypi.
def _ecosystem_for(fixture: dict) -> str:
    """Infer ecosystem from fixture module name heuristics."""
    # npm packages: crossenv, event_stream (flatmap-stream), colors, ua_parser
    npm_modules = {"crossenv", "event_stream", "colors", "ua_parser"}
    parts = fixture["module"].split("fake_malicious_")[-1]
    for npm_name in npm_modules:
        if parts.startswith(npm_name):
            return "npm"
    return "pypi"


ALL_PACKAGES = [
    pytest.param(f["name"], f["version"], _ecosystem_for(f), id=f["name"]) for f in FIXTURES
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _pypi_available() -> None:
    """Check that pypiserver is reachable (session-scoped, runs once).

    Retries a few times since pypiserver may still be starting up
    even after Docker healthcheck passes.
    """
    if not E2E:
        pytest.skip("E2E not enabled")
    import time

    base = PYPI_URL.split("/simple")[0] + "/"
    last_exc: Exception | None = None
    for attempt in range(10):
        try:
            resp = httpx.get(base, timeout=5)
            if resp.status_code == 200:
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(1)
    pytest.fail(f"pypiserver not reachable at {PYPI_URL} after 10 retries: {last_exc}")


# ---------------------------------------------------------------------------
# TestPrefilterDetection — the REAL tests
# ---------------------------------------------------------------------------


class TestPrefilterDetection:
    """Download from local pypiserver, extract, run prefilter, assert detection."""

    @pytest.mark.parametrize("name,version,ecosystem", ALL_PACKAGES)
    async def test_prefilter_detects_malicious_package(
        self,
        _pypi_available: None,
        name: str,
        version: str,
        ecosystem: str,
    ) -> None:
        """Prefilter should flag every synthetic package as >= MEDIUM risk."""
        from aigate.config import Config
        from aigate.models import PackageInfo, RiskLevel
        from aigate.prefilter import run_prefilter
        from aigate.resolver import download_from_local_pypi

        # Download from local pypiserver
        source_files = await download_from_local_pypi(name, base_url=PYPI_URL)
        assert source_files, f"No files extracted for {name}-{version}"

        package = PackageInfo(name=name, version=version, ecosystem=ecosystem)
        result = run_prefilter(package, Config.default(), source_files)

        assert result.risk_level in (
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ), f"{name}: expected >= MEDIUM, got {result.risk_level}. Signals: {result.risk_signals}"
        # Verify we actually got meaningful signals, not just a passthrough
        assert len(result.risk_signals) > 0, f"{name}: no risk signals detected"


# ---------------------------------------------------------------------------
# TestNetworkIsolation — verify sandbox has no internet
# ---------------------------------------------------------------------------


class TestNetworkIsolation:
    """Verify the Docker sandbox blocks outbound internet."""

    async def test_cannot_reach_real_pypi(self, _pypi_available: None) -> None:
        """Should not be able to reach the real pypi.org."""
        async with httpx.AsyncClient(timeout=3) as client:
            with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout)):
                await client.get("https://pypi.org/simple/requests/")

    async def test_cannot_reach_arbitrary_url(self, _pypi_available: None) -> None:
        """Should not be able to reach any external host."""
        async with httpx.AsyncClient(timeout=3) as client:
            with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout)):
                await client.get("https://example.com")


# ---------------------------------------------------------------------------
# TestCLIIntegration — test the actual CLI binary
# ---------------------------------------------------------------------------


class TestCLIIntegration:
    """Test aigate CLI binary with --skip-ai using --local flag (no network needed)."""

    @pytest.fixture(autouse=True)
    def _extract_ctx_package(self, tmp_path: Path, _pypi_available: None) -> None:
        """Extract ctx package to a temp dir for --local testing."""
        import tarfile

        pkg_dir = Path(__file__).parent / "packages"
        tar_path = pkg_dir / "ctx-0.2.6.tar.gz"
        if not tar_path.exists():
            pytest.skip("ctx-0.2.6.tar.gz not built")
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(tmp_path)
        self._local_path = str(tmp_path)

    async def test_cli_check_flags_malicious(self) -> None:
        """aigate check with --local should return exit code >= 1 for malicious."""
        proc = await asyncio.create_subprocess_exec(
            "aigate",
            "check",
            "ctx",
            "--local",
            self._local_path,
            "--skip-ai",
            "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        # Exit code 1 (suspicious) or 2 (malicious) — both acceptable
        assert proc.returncode is not None
        assert proc.returncode in (1, 2), (
            f"Expected exit 1 or 2, got {proc.returncode}. Output: {stdout.decode()[:500]}"
        )

    async def test_cli_check_json_output_valid(self) -> None:
        """JSON output should be parseable with expected fields."""
        proc = await asyncio.create_subprocess_exec(
            "aigate",
            "check",
            "ctx",
            "--local",
            self._local_path,
            "--skip-ai",
            "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        data = json.loads(stdout.decode())
        assert "decision" in data
        assert "exit_code" in data
        assert data["decision"] in ("needs_review", "malicious")
