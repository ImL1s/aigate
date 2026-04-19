"""Integration test — opensrc emission via aigate.cli._check end-to-end.

Exercises the full CLI path: check flag -> ``_maybe_emit_opensrc`` -> disk
writes under a tmp HOME. No network: feeds pre-extracted source_files dict
directly.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aigate.cli import _maybe_emit_opensrc
from aigate.config import Config, EmitOpensrcConfig
from aigate.models import (
    AnalysisReport,
    ConsensusResult,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
    Verdict,
)
from aigate.opensrc_cache import SENTINEL_FILENAME, SOURCES_JSON


def _make_report(verdict: Verdict = Verdict.SAFE) -> AnalysisReport:
    pkg = PackageInfo(
        name="lodash",
        version="4.17.21",
        ecosystem="npm",
        repository="https://github.com/lodash/lodash",
    )
    prefilter = PrefilterResult(passed=True, reason="ok", risk_level=RiskLevel.NONE)
    consensus = ConsensusResult(final_verdict=verdict, confidence=0.9, summary="")
    return AnalysisReport(package=pkg, prefilter=prefilter, consensus=consensus)


def _make_config(tmp_root: Path) -> Config:
    cfg = Config.default()
    cfg.emit_opensrc = EmitOpensrcConfig(
        enabled=True,
        cache_dir=str(tmp_root),
        on_collision="refuse",
    )
    return cfg


def test_cli_emit_writes_sources_json_entry(tmp_path: Path):
    """After a SAFE scan with --emit-opensrc, ~/.opensrc/ should reflect it."""
    cfg = _make_config(tmp_path)
    report = _make_report()
    source_files = {
        "package.json": '{"name": "lodash", "version": "4.17.21"}',
        "lodash.js": "module.exports = {};",
    }

    async def run():
        await _maybe_emit_opensrc(
            package=report.package,
            source_files=source_files,
            report=report,
            config=cfg,
            flag_override=True,
            overwrite_policy="never",
            tarball_bytes=b"fake-tarball-bytes",
            tarball_url="https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        )

    asyncio.run(run())

    # sources.json exists with one entry
    sources = json.loads((tmp_path / SOURCES_JSON).read_text())
    assert sources["packages"], "sources.json should have an entry"
    entry = sources["packages"][0]
    assert entry["name"] == "lodash"
    assert entry["version"] == "4.17.21"
    assert entry["registry"] == "npm"
    assert entry["path"] == "repos/github.com/lodash/lodash/4.17.21"

    # Package dir exists with sentinel + source files
    pkg_dir = tmp_path / entry["path"]
    assert (pkg_dir / SENTINEL_FILENAME).exists()
    assert (pkg_dir / "package.json").exists()
    assert (pkg_dir / "lodash.js").exists()

    sentinel = json.loads((pkg_dir / SENTINEL_FILENAME).read_text())
    assert sentinel["producer"] == "aigate"
    assert sentinel["ecosystem"] == "npm"
    assert sentinel["scan_verdict"] == "safe"
    # sha256 of b"fake-tarball-bytes"
    assert len(sentinel["tarball_sha256"]) == 64

    # Report carries the result
    assert report.opensrc_emit is not None
    assert report.opensrc_emit.emitted is True
    assert report.opensrc_emit.reason == "emitted"


def test_cli_emit_flag_off_is_noop(tmp_path: Path):
    """--no-emit-opensrc explicitly disables emission even when config enables it."""
    cfg = _make_config(tmp_path)
    report = _make_report()

    async def run():
        await _maybe_emit_opensrc(
            package=report.package,
            source_files={"a.js": "a"},
            report=report,
            config=cfg,
            flag_override=False,  # --no-emit-opensrc
            overwrite_policy="never",
        )

    asyncio.run(run())

    assert not (tmp_path / SOURCES_JSON).exists()
    assert report.opensrc_emit is None


def test_cli_emit_malicious_is_noop(tmp_path: Path):
    """MALICIOUS verdict never emits even when enabled + flag set."""
    cfg = _make_config(tmp_path)
    report = _make_report(verdict=Verdict.MALICIOUS)

    async def run():
        await _maybe_emit_opensrc(
            package=report.package,
            source_files={"evil.js": "payload"},
            report=report,
            config=cfg,
            flag_override=True,
            overwrite_policy="never",
        )

    asyncio.run(run())

    assert not (tmp_path / SOURCES_JSON).exists()
    assert report.opensrc_emit is not None
    assert report.opensrc_emit.emitted is False
    assert report.opensrc_emit.reason == "verdict_malicious"
