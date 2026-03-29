"""Tests for enrichment cache atomic writes (Q4)."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from unittest.mock import patch

from aigate.enrichment import _read_cache, _write_cache
from aigate.models import PackageInfo


def _pkg() -> PackageInfo:
    return PackageInfo(name="pkg", version="1.0", ecosystem="pypi")


async def test_concurrent_enrichment_cache_writes(tmp_path: Path):
    """Multiple concurrent writes should not produce corrupt JSON."""
    with patch("aigate.enrichment._cache_dir", return_value=tmp_path):

        async def write_value(i: int):
            _write_cache(_pkg(), "osv", {"value": i})

        tasks = [write_value(i) for i in range(20)]
        await asyncio.gather(*tasks)

        result = _read_cache(_pkg(), "osv", ttl_hours=1)
        assert result is not None
        assert "value" in result


def test_enrichment_cache_uses_atomic_write():
    """_write_cache must use tempfile+os.replace for atomic writes, not path.write_text."""
    source = inspect.getsource(_write_cache)
    # Must use os.replace (atomic on POSIX) instead of path.write_text
    assert "os.replace" in source or "replace(" in source, (
        "_write_cache should use tempfile+os.replace for atomic writes"
    )
    assert "write_text" not in source, "_write_cache should not use path.write_text (non-atomic)"


def test_enrichment_cache_no_leftover_tmp(tmp_path: Path):
    """After successful writes, no .tmp files should remain."""
    with patch("aigate.enrichment._cache_dir", return_value=tmp_path):
        for i in range(10):
            _write_cache(_pkg(), "osv", {"value": i})

    tmp_files = list(tmp_path.glob("*.tmp"))
    assert tmp_files == [], f"Leftover temp files: {tmp_files}"


def test_enrichment_cache_corrupt_file_returns_none(tmp_path: Path):
    """A corrupt enrichment cache file should return None."""
    from aigate.enrichment import _cache_key

    with patch("aigate.enrichment._cache_dir", return_value=tmp_path):
        key = _cache_key(_pkg(), "osv")
        cache_file = tmp_path / f"{key}.json"
        cache_file.write_text("{truncated")
        result = _read_cache(_pkg(), "osv", ttl_hours=1)
        assert result is None
