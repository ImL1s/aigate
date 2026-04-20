"""Integration: macOS sandbox-exec with NPM_LIGHT_PROFILE_MACOS blocks outbound network.

Skipped on Linux (SBPL / sandbox-exec is macOS-only).
On macOS: calls subprocess sandbox-exec with the production SBPL profile and
asserts that curl to https://example.com exits non-zero with a denial indicator
in stderr (or the program fails to connect), proving the kernel enforces the
(deny network*) rule.
"""

from __future__ import annotations

import os
import platform
import subprocess
import tempfile

import pytest

from aigate.sandbox.birdcage_backend import NPM_LIGHT_PROFILE_MACOS

pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="macOS-only kernel test — sandbox-exec / SBPL not available on Linux",
)


def _write_sbpl_profile(scratch: str) -> str:
    sbpl = NPM_LIGHT_PROFILE_MACOS.replace("${SCRATCH_HOME}", scratch)
    prof_path = os.path.join(scratch, "npm-light-test.sb")
    with open(prof_path, "w") as f:
        f.write(sbpl)
    return prof_path


def test_sbpl_profile_denies_outbound_network():
    """sandbox-exec with (deny network*) must block curl from connecting."""
    with tempfile.TemporaryDirectory() as scratch:
        prof_path = _write_sbpl_profile(scratch)
        result = subprocess.run(
            [
                "sandbox-exec",
                "-f",
                prof_path,
                "curl",
                "-s",
                "--max-time",
                "3",
                "--connect-timeout",
                "3",
                "https://example.com",
            ],
            capture_output=True,
            timeout=15,
        )

    assert result.returncode != 0, (
        "Expected sandbox to block curl (network deny), but it exited 0. "
        f"stdout={result.stdout[:200]} stderr={result.stderr[:200]}"
    )

    # macOS sandbox-exec may silently drop connections; curl then exits with a
    # network-failure code and empty stderr.  Exit codes 6 (DNS), 7 (connect),
    # and 28 (timeout) all prove the kernel blocked the request.
    curl_network_fail = {6, 7, 28}
    stderr_lower = result.stderr.lower()
    network_blocked = (
        result.returncode in curl_network_fail
        or b"not permitted" in result.stderr
        or b"operation not permitted" in result.stderr
        or b"sandbox" in stderr_lower
        or b"couldn" in stderr_lower
        or b"failed to connect" in stderr_lower
        or b"could not resolve" in stderr_lower
        or b"not permitted" in result.stdout.lower()
    )
    assert network_blocked, (
        f"curl exited {result.returncode} but no network-denial indicator found. "
        f"stderr={result.stderr[:300]!r}"
    )


def test_sbpl_profile_allows_file_read_in_scratch(tmp_path):
    """sandbox-exec should still allow file reads so npm can access the package."""
    with tempfile.TemporaryDirectory() as scratch:
        prof_path = _write_sbpl_profile(scratch)
        # Write a file inside scratch and read it under sandbox
        test_file = os.path.join(scratch, "hello.txt")
        with open(test_file, "w") as f:
            f.write("hello")

        result = subprocess.run(
            ["sandbox-exec", "-f", prof_path, "cat", test_file],
            capture_output=True,
            timeout=5,
        )

    assert result.returncode == 0, (
        f"Expected cat inside scratch to succeed. stderr={result.stderr!r}"
    )
    assert result.stdout == b"hello"
