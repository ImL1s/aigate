"""Tests for cache file locking under concurrent access."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aigate.cache import _cache_key, get_cached, set_cached
from aigate.models import (
    AnalysisReport,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
)


def _make_report(value: int = 0) -> AnalysisReport:
    return AnalysisReport(
        package=PackageInfo(name="pkg", version="1.0", ecosystem="pypi"),
        prefilter=PrefilterResult(passed=True, reason=f"value={value}", risk_level=RiskLevel.NONE),
    )


async def test_concurrent_writes_dont_corrupt(tmp_path: Path):
    """Multiple writes to same key should not produce corrupt JSON."""
    cache_dir = str(tmp_path)

    async def write_value(i: int):
        report = _make_report(i)
        set_cached("pkg", "1.0", "pypi", report, cache_dir)

    tasks = [write_value(i) for i in range(20)]
    await asyncio.gather(*tasks)

    # The cache file should be valid JSON regardless of write order
    result = get_cached("pkg", "1.0", "pypi", cache_dir, ttl_hours=1)
    assert result is not None
    assert result["prefilter"]["passed"] is True


async def test_read_during_write_returns_valid_or_none(tmp_path: Path):
    """Reading while another coroutine writes should get valid data or None, never corrupt."""
    cache_dir = str(tmp_path)
    set_cached("pkg", "1.0", "pypi", _make_report(0), cache_dir)

    async def reader():
        for _ in range(50):
            result = get_cached("pkg", "1.0", "pypi", cache_dir, ttl_hours=1)
            if result is not None:
                assert "prefilter" in result
                assert "package" in result
            await asyncio.sleep(0)

    async def writer():
        for i in range(50):
            set_cached("pkg", "1.0", "pypi", _make_report(i), cache_dir)
            await asyncio.sleep(0)

    await asyncio.gather(reader(), writer())


def test_corrupt_cache_file_returns_none(tmp_path: Path):
    """A corrupt cache file should return None, not raise."""
    cache_dir = str(tmp_path)
    key = _cache_key("pkg", "1.0", "pypi")
    cache_file = tmp_path / f"{key}.json"
    cache_file.write_text("{truncated")
    result = get_cached("pkg", "1.0", "pypi", cache_dir, ttl_hours=1)
    assert result is None


def test_empty_cache_file_returns_none(tmp_path: Path):
    """An empty cache file should return None, not raise."""
    cache_dir = str(tmp_path)
    key = _cache_key("pkg", "1.0", "pypi")
    cache_file = tmp_path / f"{key}.json"
    cache_file.write_text("")
    result = get_cached("pkg", "1.0", "pypi", cache_dir, ttl_hours=1)
    assert result is None


def test_atomic_write_no_leftover_tmp_files(tmp_path: Path):
    """After a successful write, no .tmp files should remain."""
    cache_dir = str(tmp_path)
    for i in range(10):
        set_cached("pkg", "1.0", "pypi", _make_report(i), cache_dir)

    tmp_files = list(tmp_path.glob("*.tmp"))
    assert tmp_files == [], f"Leftover temp files: {tmp_files}"


def test_atomic_write_preserves_valid_json(tmp_path: Path):
    """Each write should produce valid JSON on disk."""
    cache_dir = str(tmp_path)
    key = _cache_key("pkg", "1.0", "pypi")
    cache_file = tmp_path / f"{key}.json"

    for i in range(10):
        set_cached("pkg", "1.0", "pypi", _make_report(i), cache_dir)
        # Verify the file is always valid JSON after each write
        data = json.loads(cache_file.read_text())
        assert data["prefilter"]["passed"] is True
