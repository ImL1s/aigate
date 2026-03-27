"""Tests for file-based analysis cache."""

import json
import time
from pathlib import Path

from aigate.cache import _cache_key, get_cached, set_cached
from aigate.models import (
    AnalysisReport,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
)


def _make_report() -> AnalysisReport:
    return AnalysisReport(
        package=PackageInfo(name="testpkg", version="1.0.0", ecosystem="pypi"),
        prefilter=PrefilterResult(
            passed=True, reason="safe", risk_level=RiskLevel.NONE
        ),
    )


class TestCacheKey:
    def test_deterministic(self):
        k1 = _cache_key("pkg", "1.0", "pypi")
        k2 = _cache_key("pkg", "1.0", "pypi")
        assert k1 == k2

    def test_different_versions(self):
        k1 = _cache_key("pkg", "1.0", "pypi")
        k2 = _cache_key("pkg", "2.0", "pypi")
        assert k1 != k2

    def test_different_ecosystems(self):
        k1 = _cache_key("pkg", "1.0", "pypi")
        k2 = _cache_key("pkg", "1.0", "npm")
        assert k1 != k2


class TestSetAndGet:
    def test_roundtrip(self, tmp_path: Path):
        report = _make_report()
        set_cached("testpkg", "1.0.0", "pypi", report, str(tmp_path))
        result = get_cached("testpkg", "1.0.0", "pypi", str(tmp_path), ttl_hours=1)
        assert result is not None
        assert result["prefilter"]["passed"] is True

    def test_miss_returns_none(self, tmp_path: Path):
        result = get_cached("nonexistent", "1.0", "pypi", str(tmp_path), ttl_hours=1)
        assert result is None

    def test_expired_returns_none(self, tmp_path: Path):
        report = _make_report()
        set_cached("testpkg", "1.0.0", "pypi", report, str(tmp_path))
        # Manually set cached_at to past
        key = _cache_key("testpkg", "1.0.0", "pypi")
        cache_file = tmp_path / f"{key}.json"
        data = json.loads(cache_file.read_text())
        data["_cached_at"] = time.time() - 9999999
        cache_file.write_text(json.dumps(data))
        result = get_cached("testpkg", "1.0.0", "pypi", str(tmp_path), ttl_hours=1)
        assert result is None

    def test_corrupted_file_returns_none(self, tmp_path: Path):
        key = _cache_key("testpkg", "1.0.0", "pypi")
        cache_file = tmp_path / f"{key}.json"
        cache_file.write_text("not json{{{")
        result = get_cached("testpkg", "1.0.0", "pypi", str(tmp_path), ttl_hours=1)
        assert result is None

    def test_cache_dir_created(self, tmp_path: Path):
        nested = tmp_path / "a" / "b" / "c"
        report = _make_report()
        set_cached("testpkg", "1.0.0", "pypi", report, str(nested))
        assert nested.exists()
