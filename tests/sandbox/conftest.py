"""Shared fixtures and marks for tests/sandbox/.

skip_if_no_strace — fixture that skips integration tests when strace is
not on PATH.  Integration tests require the real strace binary; they run
in CI Linux runners where strace is installed and are skipped gracefully
on macOS dev machines and minimal CI images.
"""

from __future__ import annotations

import shutil

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_strace: mark test as requiring strace on PATH (skipped if absent)",
    )


@pytest.fixture
def skip_if_no_strace() -> None:
    """Skip the calling test when strace is not installed."""
    if shutil.which("strace") is None:
        pytest.skip("strace not on PATH — integration test requires real strace binary")
