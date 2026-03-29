"""Tests for auto-updating popular package lists."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from aigate.rules.popular_packages import (
    CACHE_TTL_DAYS,
    _get_builtin_fallback,
    _read_cache,
    _write_cache,
    get_popular_packages,
)


def _make_pypi_response(count: int = 1000) -> dict:
    """Build a fake top-pypi-packages JSON response."""
    return {
        "last_update": "2026-03-20",
        "rows": [{"project": f"pkg-{i}", "download_count": 10000 - i} for i in range(count)],
    }


def _make_npm_response(count: int = 1000) -> list[dict]:
    """Build a fake npm registry search response (objects list)."""
    return [{"package": {"name": f"npm-pkg-{i}"}} for i in range(count)]


def _make_mock_response(json_data: dict | list) -> AsyncMock:
    """Create a mock httpx.Response with .json() as a sync method."""
    mock_resp = AsyncMock()
    # httpx Response.json() is a sync method, not async
    mock_resp.json = lambda: json_data
    mock_resp.raise_for_status = lambda: None
    return mock_resp


def _make_mock_client(mock_resp: AsyncMock) -> AsyncMock:
    """Create a mock httpx.AsyncClient that returns mock_resp on .get()."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


class TestGetPopularPyPI:
    @pytest.mark.asyncio
    async def test_get_popular_pypi_returns_1000_names(self, tmp_path: Path):
        """Mock API returns 1000+ package names."""
        resp_data = _make_pypi_response(1200)
        mock_resp = _make_mock_response(resp_data)
        mock_client = _make_mock_client(mock_resp)

        with (
            patch("aigate.rules.popular_packages.httpx.AsyncClient", return_value=mock_client),
            patch("aigate.rules.popular_packages.CACHE_FILE", tmp_path / "cache.json"),
        ):
            packages = await get_popular_packages("pypi")

        assert len(packages) >= 1000
        assert "pkg-0" in packages
        assert "pkg-999" in packages


class TestCacheUsedWhenFresh:
    @pytest.mark.asyncio
    async def test_cache_used_when_fresh(self, tmp_path: Path):
        """When cache file exists and is fresh, API is NOT called."""
        cache_file = tmp_path / "cache.json"
        cached_data = {
            "pypi": {
                "packages": [f"cached-{i}" for i in range(50)],
                "updated_at": time.time(),  # now = fresh
            }
        }
        cache_file.write_text(json.dumps(cached_data))

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("aigate.rules.popular_packages.httpx.AsyncClient", return_value=mock_client),
            patch("aigate.rules.popular_packages.CACHE_FILE", cache_file),
        ):
            packages = await get_popular_packages("pypi")

        # API should NOT have been called
        mock_client.get.assert_not_called()
        assert "cached-0" in packages
        assert len(packages) == 50


class TestAPIFailureFallback:
    @pytest.mark.asyncio
    async def test_api_failure_fallback(self, tmp_path: Path):
        """When API fails, returns hardcoded fallback list."""
        mock_client = _make_mock_client(AsyncMock())
        mock_client.get.side_effect = httpx.ConnectError("unreachable")

        with (
            patch("aigate.rules.popular_packages.httpx.AsyncClient", return_value=mock_client),
            patch("aigate.rules.popular_packages.CACHE_FILE", tmp_path / "cache.json"),
        ):
            packages = await get_popular_packages("pypi")

        # Should return the hardcoded fallback, not empty
        fallback = _get_builtin_fallback("pypi")
        assert packages == fallback
        assert len(packages) > 0


class TestGetPopularNPM:
    @pytest.mark.asyncio
    async def test_get_popular_npm(self, tmp_path: Path):
        """Mock npm API returns package names."""
        resp_data = _make_npm_response(1000)
        mock_resp = _make_mock_response({"objects": resp_data})
        mock_client = _make_mock_client(mock_resp)

        with (
            patch("aigate.rules.popular_packages.httpx.AsyncClient", return_value=mock_client),
            patch("aigate.rules.popular_packages.CACHE_FILE", tmp_path / "cache.json"),
        ):
            packages = await get_popular_packages("npm")

        assert len(packages) >= 250  # npm search returns fewer
        assert "npm-pkg-0" in packages


class TestCacheReadWrite:
    def test_write_and_read_cache(self, tmp_path: Path):
        """Cache roundtrip: write then read."""
        cache_file = tmp_path / "cache.json"
        packages = {f"pkg-{i}" for i in range(100)}

        with patch("aigate.rules.popular_packages.CACHE_FILE", cache_file):
            _write_cache("pypi", packages)
            result = _read_cache("pypi")

        assert result is not None
        assert result == packages

    def test_read_cache_stale(self, tmp_path: Path):
        """Stale cache returns None."""
        cache_file = tmp_path / "cache.json"
        stale_time = time.time() - (CACHE_TTL_DAYS + 1) * 86400
        data = {
            "pypi": {
                "packages": ["stale-pkg"],
                "updated_at": stale_time,
            }
        }
        cache_file.write_text(json.dumps(data))

        with patch("aigate.rules.popular_packages.CACHE_FILE", cache_file):
            result = _read_cache("pypi")

        assert result is None

    def test_read_cache_missing_file(self, tmp_path: Path):
        """Missing cache file returns None."""
        with patch("aigate.rules.popular_packages.CACHE_FILE", tmp_path / "nope.json"):
            result = _read_cache("pypi")
        assert result is None


class TestBuiltinFallback:
    def test_pypi_fallback_nonempty(self):
        fb = _get_builtin_fallback("pypi")
        assert "requests" in fb
        assert "numpy" in fb

    def test_npm_fallback_nonempty(self):
        fb = _get_builtin_fallback("npm")
        assert "express" in fb
        assert "react" in fb

    def test_unknown_ecosystem_returns_empty(self):
        fb = _get_builtin_fallback("unknown-eco")
        assert fb == set()
