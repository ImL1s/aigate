"""E2E test configuration. Skips unless running in Docker sandbox."""

from __future__ import annotations

import os

import pytest

E2E_ENABLED = os.environ.get("AIGATE_E2E") == "1"
PYPI_URL = os.environ.get("AIGATE_E2E_PYPI_URL", "http://localhost:8080/simple/")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip all E2E tests unless AIGATE_E2E=1."""
    if E2E_ENABLED:
        return
    skip = pytest.mark.skip(reason="E2E tests require AIGATE_E2E=1 (run via docker compose)")
    for item in items:
        if "e2e" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def pypi_url() -> str:
    """Return the local pypiserver URL."""
    return PYPI_URL
