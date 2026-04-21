"""Tests for file-based analysis cache."""

import json
import time
from pathlib import Path

import pytest

from aigate.cache import _cache_key, get_cached, report_from_cached, set_cached
from aigate.models import (
    AnalysisReport,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
)


def _make_report() -> AnalysisReport:
    return AnalysisReport(
        package=PackageInfo(name="testpkg", version="1.0.0", ecosystem="pypi"),
        prefilter=PrefilterResult(passed=True, reason="safe", risk_level=RiskLevel.NONE),
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

    # --- US-001: Provenance in cache key ---

    def test_different_provenance_different_key(self):
        """Local and registry results must NOT share cache keys."""
        k_reg = _cache_key("requests", "2.32.0", "pypi", provenance="registry")
        k_local = _cache_key("requests", "2.32.0", "pypi", provenance="local")
        assert k_reg != k_local

    def test_provenance_default_is_registry(self):
        """Default provenance should be 'registry' for backwards compat."""
        k_explicit = _cache_key("pkg", "1.0", "pypi", provenance="registry")
        k_default = _cache_key("pkg", "1.0", "pypi")
        assert k_explicit == k_default

    def test_provenance_deterministic(self):
        k1 = _cache_key("pkg", "1.0", "pypi", provenance="local")
        k2 = _cache_key("pkg", "1.0", "pypi", provenance="local")
        assert k1 == k2


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

    # --- US-001: Provenance isolation ---

    def test_local_does_not_poison_registry(self, tmp_path: Path):
        """A local scan result must not be returned for a registry lookup."""
        report = _make_report()
        set_cached("pkg", "1.0", "pypi", report, str(tmp_path), provenance="local")
        result = get_cached("pkg", "1.0", "pypi", str(tmp_path), ttl_hours=1, provenance="registry")
        assert result is None

    def test_registry_does_not_poison_local(self, tmp_path: Path):
        """A registry result must not be returned for a local lookup."""
        report = _make_report()
        set_cached("pkg", "1.0", "pypi", report, str(tmp_path), provenance="registry")
        result = get_cached("pkg", "1.0", "pypi", str(tmp_path), ttl_hours=1, provenance="local")
        assert result is None

    def test_provenance_roundtrip(self, tmp_path: Path):
        """Same provenance should roundtrip correctly."""
        report = _make_report()
        set_cached("pkg", "1.0", "pypi", report, str(tmp_path), provenance="local")
        result = get_cached("pkg", "1.0", "pypi", str(tmp_path), ttl_hours=1, provenance="local")
        assert result is not None


class TestAigateNoCacheEnv:
    """AIGATE_NO_CACHE env kill-switch must short-circuit both read and write."""

    @pytest.mark.parametrize("truthy", ["1", "true", "True", "YES", "on"])
    def test_get_cached_returns_none_when_disabled(self, tmp_path: Path, monkeypatch, truthy: str):
        report = _make_report()
        # Seed cache with env unset so the file actually exists.
        monkeypatch.delenv("AIGATE_NO_CACHE", raising=False)
        set_cached("pkg", "1.0", "pypi", report, str(tmp_path))
        # Now set env and confirm read returns None despite the file.
        monkeypatch.setenv("AIGATE_NO_CACHE", truthy)
        result = get_cached("pkg", "1.0", "pypi", str(tmp_path), ttl_hours=1)
        assert result is None

    def test_set_cached_is_noop_when_disabled(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("AIGATE_NO_CACHE", "1")
        report = _make_report()
        set_cached("pkg", "1.0", "pypi", report, str(tmp_path))
        # Directory may have been created lazily by get_cached; what matters is
        # that no cache file was persisted for this key.
        key = _cache_key("pkg", "1.0", "pypi")
        assert not (tmp_path / f"{key}.json").exists()

    @pytest.mark.parametrize("falsy", ["0", "false", "", "no", "off"])
    def test_falsy_values_do_not_disable_cache(self, tmp_path: Path, monkeypatch, falsy: str):
        monkeypatch.setenv("AIGATE_NO_CACHE", falsy)
        report = _make_report()
        set_cached("pkg", "1.0", "pypi", report, str(tmp_path))
        result = get_cached("pkg", "1.0", "pypi", str(tmp_path), ttl_hours=1)
        assert result is not None


class TestReportFromCached:
    """report_from_cached reconstructs an AnalysisReport from a roundtripped dict."""

    def test_roundtrip_preserves_prefilter(self, tmp_path: Path):
        report = _make_report()
        set_cached("testpkg", "1.0.0", "pypi", report, str(tmp_path))
        cached = get_cached("testpkg", "1.0.0", "pypi", str(tmp_path), ttl_hours=1)
        assert cached is not None
        rebuilt = report_from_cached(
            cached,
            fallback_package=report.package,
            total_latency_ms=0,
        )
        assert rebuilt.package.name == "testpkg"
        assert rebuilt.prefilter.passed is True
        assert rebuilt.cached is True

    def test_tolerates_unknown_enrichment_fields(self, tmp_path: Path):
        """Schema drift: an older cache file with now-removed fields must not
        raise TypeError in ProvenanceInfo/SecurityMention/KnownVulnerability
        constructors, otherwise the hook's broad except swallows it and
        installs silently fail-open."""
        cached = {
            "package": {"name": "p", "version": "1.0.0", "ecosystem": "pypi"},
            "prefilter": {
                "passed": True,
                "reason": "safe",
                "risk_level": "none",
                "risk_signals": [],
                "needs_ai_review": False,
            },
            "enrichment": {
                "provenance": {"source": "x", "future_field_removed_in_v2": "boom"},
                "security_mentions": [
                    {"title": "t", "url": "", "snippet": "s", "legacy_unknown": 1}
                ],
                "known_vulnerabilities": [
                    {"id": "X", "summary": "s", "dropped_in_newer_schema": True}
                ],
            },
        }
        fallback = PackageInfo(name="p", version="1.0.0", ecosystem="pypi")
        rebuilt = report_from_cached(cached, fallback_package=fallback, total_latency_ms=0)
        assert rebuilt.enrichment is not None
        assert rebuilt.enrichment.provenance is not None
        assert rebuilt.enrichment.provenance.source == "x"
        assert len(rebuilt.enrichment.security_mentions) == 1
        assert len(rebuilt.enrichment.known_vulnerabilities) == 1
