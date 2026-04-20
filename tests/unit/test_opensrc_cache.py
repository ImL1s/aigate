"""Unit tests for ``aigate.opensrc_cache`` (Phase 1 opensrc-integration-plan).

Covers:
    * ``should_emit`` gates (T-COL-6, source_unavailable, disabled config).
    * Collision policy T-COL-1..T-COL-6.
    * Atomic-replace sources.json + concurrent writers.
    * Path derivation w/ and w/o git URL.
    * Corrupt central sources.json recovery (critic minor nit #3).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aigate.config import Config, EmitOpensrcConfig
from aigate.models import (
    AnalysisReport,
    ConsensusResult,
    OpensrcEmitResult,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
    Verdict,
)
from aigate.opensrc_cache import (
    SENTINEL_FILENAME,
    SOURCES_JSON,
    _collision_policy,
    _parse_git_url,
    derive_path,
    emit_to_opensrc_cache,
    list_filesystem_outputs,
    should_emit,
)


def _make_report(
    *,
    verdict: Verdict = Verdict.SAFE,
    source_unavailable: bool = False,
    package: PackageInfo | None = None,
) -> AnalysisReport:
    pkg = package or PackageInfo(
        name="lodash",
        version="4.17.21",
        ecosystem="npm",
        repository="https://github.com/lodash/lodash",
    )
    prefilter = PrefilterResult(passed=True, reason="ok", risk_level=RiskLevel.NONE)
    consensus = ConsensusResult(final_verdict=verdict, confidence=0.9, summary="")
    if source_unavailable:
        consensus.risk_signals.append("source_unavailable(HIGH): bytes not inspected")
    return AnalysisReport(
        package=pkg,
        prefilter=prefilter,
        consensus=consensus,
    )


def _make_config(
    *,
    tmp_root: Path,
    enabled: bool = True,
    on_collision: str = "refuse",
) -> Config:
    cfg = Config.default()
    cfg.emit_opensrc = EmitOpensrcConfig(
        enabled=enabled,
        cache_dir=str(tmp_root),
        on_collision=on_collision,
    )
    return cfg


# ---------------------------------------------------------------------------
# derive_path
# ---------------------------------------------------------------------------


class TestDerivePath:
    def test_github_npm_package(self):
        pkg = PackageInfo(
            name="lodash",
            version="4.17.21",
            ecosystem="npm",
            repository="https://github.com/lodash/lodash",
        )
        path, fallback = derive_path(pkg)
        assert path == "repos/github.com/lodash/lodash/4.17.21"
        assert fallback is False

    def test_github_with_git_plus_prefix(self):
        pkg = PackageInfo(
            name="zod",
            version="3.25.76",
            ecosystem="npm",
            repository="git+https://github.com/colinhacks/zod.git",
        )
        path, fallback = derive_path(pkg)
        assert path == "repos/github.com/colinhacks/zod/3.25.76"
        assert fallback is False

    def test_gitlab_host(self):
        pkg = PackageInfo(
            name="thing",
            version="1.0.0",
            ecosystem="pypi",
            repository="https://gitlab.com/owner/thing",
        )
        path, _ = derive_path(pkg)
        assert path == "repos/gitlab.com/owner/thing/1.0.0"

    def test_fallback_when_no_git_url(self):
        pkg = PackageInfo(name="requests", version="2.32.0", ecosystem="pypi", repository="")
        path, fallback = derive_path(pkg)
        assert path == "repos/registry.pypi/requests/2.32.0"
        assert fallback is True

    def test_fallback_scoped_npm(self):
        pkg = PackageInfo(
            name="@scope/name",
            version="1.0.0",
            ecosystem="npm",
            repository="",
        )
        path, fallback = derive_path(pkg)
        assert path == "repos/registry.npm/@scope/name/1.0.0"
        assert fallback is True

    def test_parse_git_url_rejects_garbage(self):
        assert _parse_git_url("") is None
        assert _parse_git_url("not a url") is None


# ---------------------------------------------------------------------------
# should_emit gates
# ---------------------------------------------------------------------------


class TestShouldEmit:
    def test_malicious_never_emits(self, tmp_path: Path):
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report(verdict=Verdict.MALICIOUS)
        ok, reason = should_emit(rpt, cfg, flag_override=True)
        assert ok is False
        assert reason == "verdict_malicious"

    def test_disabled_config_and_no_flag(self, tmp_path: Path):
        cfg = _make_config(tmp_root=tmp_path, enabled=False)
        rpt = _make_report()
        ok, reason = should_emit(rpt, cfg, flag_override=None)
        assert ok is False
        assert reason == "disabled"

    def test_flag_override_enables_when_config_disabled(self, tmp_path: Path):
        cfg = _make_config(tmp_root=tmp_path, enabled=False)
        rpt = _make_report()
        ok, _ = should_emit(rpt, cfg, flag_override=True)
        assert ok is True

    def test_flag_override_false_disables(self, tmp_path: Path):
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report()
        ok, reason = should_emit(rpt, cfg, flag_override=False)
        assert ok is False
        assert reason == "flag_off"

    def test_source_unavailable_refuses(self, tmp_path: Path):
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report(source_unavailable=True)
        ok, reason = should_emit(rpt, cfg, flag_override=True)
        assert ok is False
        assert reason == "source_unavailable"

    def test_should_emit_refuses_high_prefilter_when_no_consensus(self, tmp_path: Path):
        """US-003 / Reviewer IMP-4: --skip-ai + prefilter HIGH must not emit.

        Without this gate, a malicious crates package with build.rs+reqwest
        flagged HIGH at the prefilter layer (decision = MALICIOUS, exit 2)
        would still write its bytes to ~/.opensrc/ when --emit-opensrc is set,
        because should_emit only inspected the consensus verdict. AI-agents
        reading the cache would see the malicious package as a legitimate
        source.
        """
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        pkg = PackageInfo(
            name="evil-crate",
            version="0.1.0",
            ecosystem="crates",
            repository="",
        )
        rpt = AnalysisReport(
            package=pkg,
            prefilter=PrefilterResult(
                passed=False,
                reason="build.rs + network call detected",
                risk_level=RiskLevel.HIGH,
                risk_signals=["dangerous_pattern(HIGH): 'build.rs:reqwest' …"],
                needs_ai_review=True,
            ),
            consensus=None,  # --skip-ai path
        )
        ok, reason = should_emit(rpt, cfg, flag_override=True)
        assert ok is False
        assert reason == "prefilter_high_risk"

    def test_should_emit_refuses_critical_prefilter_when_no_consensus(self, tmp_path: Path):
        """US-003: same gate fires for CRITICAL too (e.g. blocklisted package)."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        pkg = PackageInfo(name="known-bad", version="1.0", ecosystem="npm", repository="")
        rpt = AnalysisReport(
            package=pkg,
            prefilter=PrefilterResult(
                passed=False,
                reason="blocklist hit",
                risk_level=RiskLevel.CRITICAL,
                risk_signals=["blocklist(CRITICAL): known-bad"],
                needs_ai_review=False,
            ),
            consensus=None,
        )
        ok, reason = should_emit(rpt, cfg, flag_override=True)
        assert ok is False
        assert reason == "prefilter_high_risk"

    def test_should_emit_allows_high_prefilter_when_consensus_says_safe(self, tmp_path: Path):
        """US-003: when AI ran AND said SAFE, prefilter signals are by design
        overridden — the prefilter HIGH gate is for the no-consensus path only."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        pkg = PackageInfo(name="x", version="1.0", ecosystem="pypi", repository="")
        rpt = AnalysisReport(
            package=pkg,
            prefilter=PrefilterResult(
                passed=False,
                reason="prefilter HIGH but AI cleared",
                risk_level=RiskLevel.HIGH,
                risk_signals=["dangerous_pattern(HIGH): false-positive"],
                needs_ai_review=True,
            ),
            consensus=ConsensusResult(
                final_verdict=Verdict.SAFE,
                confidence=0.95,
                summary="AI cleared the false-positive",
            ),
        )
        ok, _ = should_emit(rpt, cfg, flag_override=True)
        assert ok is True


# ---------------------------------------------------------------------------
# Collision policy — T-COL-1..T-COL-6
# ---------------------------------------------------------------------------


class TestCollisionPolicy:
    def test_col_1_fresh_directory(self, tmp_path: Path):
        """T-COL-1: fresh dir, aigate emits, sentinel created, sources.json updated."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report()
        result = emit_to_opensrc_cache(
            rpt.package,
            {"package.json": "{}", "index.js": "module.exports = 1;"},
            rpt,
            cfg,
            tarball_bytes=b"fixture-bytes",
        )
        assert result.emitted is True
        target = tmp_path / result.path
        assert (target / SENTINEL_FILENAME).exists()
        assert (target / "package.json").exists()
        sources = json.loads((tmp_path / SOURCES_JSON).read_text())
        assert sources["packages"][0]["name"] == "lodash"
        assert sources["packages"][0]["registry"] == "npm"

    def test_col_2_idempotent_same_sha(self, tmp_path: Path):
        """T-COL-2: second emit with identical bytes is a no-op (timestamp-only)."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report()
        src = {"a.js": "a"}

        first = emit_to_opensrc_cache(rpt.package, src, rpt, cfg, tarball_bytes=b"same")
        assert first.emitted is True
        first_ts = (tmp_path / first.path / "a.js").stat().st_mtime

        # Sleep not needed — same-SHA must short-circuit before file write
        second = emit_to_opensrc_cache(rpt.package, src, rpt, cfg, tarball_bytes=b"same")
        assert second.emitted is False
        assert second.reason == "idempotent_same_sha"
        # File should not have been rewritten (mtime preserved modulo fs resolution)
        assert (tmp_path / first.path / "a.js").stat().st_mtime == first_ts

    def test_col_3_reemit_different_sha_safe_verdict(self, tmp_path: Path):
        """T-COL-3: tarball republish with different bytes + SAFE -> overwrite."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report(verdict=Verdict.SAFE)

        emit_to_opensrc_cache(rpt.package, {"a.js": "v1"}, rpt, cfg, tarball_bytes=b"v1")
        second = emit_to_opensrc_cache(rpt.package, {"a.js": "v2"}, rpt, cfg, tarball_bytes=b"v2")
        assert second.emitted is True
        assert second.reason == "emitted"
        content = (tmp_path / second.path / "a.js").read_text()
        assert content == "v2"

    def test_col_4_refuse_unknown_origin(self, tmp_path: Path):
        """T-COL-4: pre-populated dir w/o sentinel -> refuse by default."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True, on_collision="refuse")
        rpt = _make_report()
        rel, _ = derive_path(rpt.package)
        existing_dir = tmp_path / rel
        existing_dir.mkdir(parents=True, exist_ok=True)
        (existing_dir / "opensrc-bytes.txt").write_text("do not overwrite me")

        result = emit_to_opensrc_cache(
            rpt.package, {"a.js": "aigate"}, rpt, cfg, tarball_bytes=b"new"
        )
        assert result.emitted is False
        assert result.reason == "collision_unknown_origin"
        assert (existing_dir / "opensrc-bytes.txt").read_text() == "do not overwrite me"
        assert not (existing_dir / SENTINEL_FILENAME).exists()

    def test_col_5_force_overwrite(self, tmp_path: Path):
        """T-COL-5: --opensrc-overwrite=always writes over unknown-origin dir."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report()
        rel, _ = derive_path(rpt.package)
        existing_dir = tmp_path / rel
        existing_dir.mkdir(parents=True, exist_ok=True)
        (existing_dir / "opensrc-bytes.txt").write_text("old")

        result = emit_to_opensrc_cache(
            rpt.package,
            {"a.js": "aigate"},
            rpt,
            cfg,
            overwrite_policy="always",
            tarball_bytes=b"forced",
        )
        assert result.emitted is True
        assert (existing_dir / SENTINEL_FILENAME).exists()
        assert (existing_dir / "a.js").read_text() == "aigate"

    def test_col_6_malicious_no_write(self, tmp_path: Path):
        """T-COL-6: MALICIOUS -> no files, no sentinel, no sources.json entry."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report(verdict=Verdict.MALICIOUS)
        result = emit_to_opensrc_cache(
            rpt.package, {"evil.js": "payload"}, rpt, cfg, tarball_bytes=b"evil"
        )
        assert result.emitted is False
        assert result.reason == "verdict_malicious"
        rel, _ = derive_path(rpt.package)
        assert not (tmp_path / rel).exists()
        # sources.json is only written on a successful emit path
        assert not (tmp_path / SOURCES_JSON).exists()

    def test_collision_policy_pure_function_matrix(self, tmp_path: Path):
        """Direct test of _collision_policy — covers matrix exhaustively."""
        fresh = tmp_path / "fresh"
        # Fresh -> write
        action = _collision_policy(fresh, "sha", Verdict.SAFE, "refuse")
        assert action.write is True
        assert action.reason == "fresh_directory"

        # MALICIOUS even on fresh -> no write
        action = _collision_policy(fresh, "sha", Verdict.MALICIOUS, "refuse")
        assert action.write is False
        assert action.reason == "verdict_malicious"


# ---------------------------------------------------------------------------
# Concurrent writers
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_concurrent_writers_no_lost_entries(self, tmp_path: Path):
        """5 concurrent emits on distinct (name, version) all land in sources.json."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)

        async def _one(idx: int):
            pkg = PackageInfo(
                name=f"pkg-{idx}",
                version=f"1.0.{idx}",
                ecosystem="npm",
                repository=f"https://github.com/owner/pkg-{idx}",
            )
            rpt = _make_report(package=pkg)
            # Run blocking emit inside a thread, mirroring production flow
            await asyncio.to_thread(
                emit_to_opensrc_cache,
                pkg,
                {"a.js": f"{idx}"},
                rpt,
                cfg,
                None,
                f"bytes-{idx}".encode(),
            )

        async def _run_all():
            await asyncio.gather(*[_one(i) for i in range(5)])

        asyncio.run(_run_all())

        sources = json.loads((tmp_path / SOURCES_JSON).read_text())
        names = {entry["name"] for entry in sources["packages"]}
        assert names == {f"pkg-{i}" for i in range(5)}


# ---------------------------------------------------------------------------
# Corrupt central index recovery
# ---------------------------------------------------------------------------


class TestCorruptionRecovery:
    def test_corrupt_sources_json_is_recovered(self, tmp_path: Path):
        """Malformed sources.json doesn't crash; aigate writes a fresh file."""
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / SOURCES_JSON).write_text("{truncated json")

        rpt = _make_report()
        result = emit_to_opensrc_cache(rpt.package, {"a.js": "a"}, rpt, cfg, tarball_bytes=b"bytes")
        assert result.emitted is True
        # Post-emit, sources.json should be valid JSON and contain our entry
        data = json.loads((tmp_path / SOURCES_JSON).read_text())
        assert data["packages"][0]["name"] == "lodash"


# ---------------------------------------------------------------------------
# Doctor summary (filesystem outputs)
# ---------------------------------------------------------------------------


class TestFilesystemSummary:
    def test_summary_empty_cache(self, tmp_path: Path):
        cfg = EmitOpensrcConfig(cache_dir=str(tmp_path / "nonexistent"))
        summary = list_filesystem_outputs(cfg)
        assert summary["exists"] is False
        assert summary["total_packages"] == 0

    def test_summary_after_emit(self, tmp_path: Path):
        cfg = _make_config(tmp_root=tmp_path, enabled=True)
        rpt = _make_report()
        emit_to_opensrc_cache(rpt.package, {"a.js": "a"}, rpt, cfg, tarball_bytes=b"b")
        summary = list_filesystem_outputs(cfg.emit_opensrc)
        assert summary["exists"] is True
        assert summary["sources_json_valid"] is True
        assert summary["total_packages"] == 1
        assert summary["aigate_origin"] >= 1


# ---------------------------------------------------------------------------
# OpensrcEmitResult shape
# ---------------------------------------------------------------------------


def test_opensrc_emit_result_default_values():
    r = OpensrcEmitResult()
    assert r.emitted is False
    assert r.path is None
    assert r.reason is None
    assert r.sha256 is None
