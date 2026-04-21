"""Tests for the npm install hook — package spec parsing and command routing."""

from __future__ import annotations

import pytest

from aigate.cache import set_cached
from aigate.config import Config
from aigate.hooks import npm_hook
from aigate.hooks.npm_hook import _extract_packages, _install_commands_for, _parse_npm_spec
from aigate.models import (
    AnalysisReport,
    EnrichmentResult,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
)


class TestParseNpmSpec:
    """Test _parse_npm_spec for various npm package specifiers."""

    def test_plain_name(self):
        assert _parse_npm_spec("express") == ("express", None)

    def test_name_with_version(self):
        assert _parse_npm_spec("express@4.18.2") == ("express", "4.18.2")

    def test_name_with_range(self):
        assert _parse_npm_spec("lodash@^4.17.0") == ("lodash", "^4.17.0")

    def test_name_with_tilde(self):
        assert _parse_npm_spec("chalk@~5.0.0") == ("chalk", "~5.0.0")

    def test_name_with_latest_tag(self):
        assert _parse_npm_spec("react@latest") == ("react", "latest")

    def test_scoped_package(self):
        assert _parse_npm_spec("@angular/core") == ("@angular/core", None)

    def test_scoped_package_with_version(self):
        assert _parse_npm_spec("@angular/core@17.0.0") == ("@angular/core", "17.0.0")

    def test_scoped_package_with_range(self):
        assert _parse_npm_spec("@types/node@^20") == ("@types/node", "^20")

    def test_dotted_name(self):
        assert _parse_npm_spec("socket.io") == ("socket.io", None)

    def test_dotted_name_with_version(self):
        assert _parse_npm_spec("socket.io@4.7.0") == ("socket.io", "4.7.0")

    def test_hyphenated_name(self):
        assert _parse_npm_spec("my-package") == ("my-package", None)

    def test_underscore_name(self):
        assert _parse_npm_spec("my_package") == ("my_package", None)


class TestExtractPackages:
    """Test _extract_packages for different package managers."""

    def test_npm_single_package(self):
        args = ["install", "express"]
        result = _extract_packages(args, "npm")
        assert result == [("express", None)]

    def test_npm_multiple_packages(self):
        args = ["install", "express", "lodash@4.17.21", "@types/node@20"]
        result = _extract_packages(args, "npm")
        assert result == [
            ("express", None),
            ("lodash", "4.17.21"),
            ("@types/node", "20"),
        ]

    def test_npm_with_flags(self):
        args = ["install", "--save-dev", "typescript@5", "--save-exact"]
        result = _extract_packages(args, "npm")
        assert result == [("typescript", "5")]

    def test_npm_shorthand(self):
        args = ["i", "express"]
        result = _extract_packages(args, "npm")
        assert result == [("express", None)]

    def test_yarn_add(self):
        args = ["add", "react", "react-dom@18"]
        result = _extract_packages(args, "yarn")
        assert result == [("react", None), ("react-dom", "18")]

    def test_yarn_with_dev_flag(self):
        args = ["add", "-D", "jest@29"]
        result = _extract_packages(args, "yarn")
        assert result == [("jest", "29")]

    def test_pnpm_add(self):
        args = ["add", "vite@5"]
        result = _extract_packages(args, "pnpm")
        assert result == [("vite", "5")]

    def test_pnpm_install_shorthand(self):
        args = ["i", "zod"]
        result = _extract_packages(args, "pnpm")
        assert result == [("zod", None)]

    def test_skip_workspace_flag(self):
        args = ["install", "--workspace", "packages/app", "express"]
        result = _extract_packages(args, "npm")
        assert result == [("express", None)]

    def test_skip_registry_flag(self):
        args = ["install", "--registry", "https://my.registry.com", "express"]
        result = _extract_packages(args, "npm")
        assert result == [("express", None)]

    def test_no_packages_bare_install(self):
        """npm install with no args should return empty — just reinstalls."""
        args = ["install"]
        result = _extract_packages(args, "npm")
        assert result == []

    def test_scoped_packages_mixed(self):
        args = ["add", "@vue/cli@5", "vue@3", "@babel/core"]
        result = _extract_packages(args, "yarn")
        assert result == [
            ("@vue/cli", "5"),
            ("vue", "3"),
            ("@babel/core", None),
        ]


class TestInstallCommands:
    """Test _install_commands_for returns correct sub-commands per PM."""

    def test_npm_commands(self):
        cmds = _install_commands_for("npm")
        assert "install" in cmds
        assert "i" in cmds
        assert "add" in cmds

    def test_yarn_commands(self):
        cmds = _install_commands_for("yarn")
        assert "add" in cmds
        assert "install" in cmds

    def test_pnpm_commands(self):
        cmds = _install_commands_for("pnpm")
        assert "add" in cmds
        assert "install" in cmds
        assert "i" in cmds


def test_npm_wrapper_bypasses_with_no_aigate(monkeypatch):
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        npm_hook.sys,
        "argv",
        ["aigate-npm", "npm", "install", "--no-aigate", "react"],
    )
    monkeypatch.setattr(
        npm_hook,
        "_passthrough",
        lambda pm, args: seen.update({"pm": pm, "args": args}),
    )
    monkeypatch.setattr(
        npm_hook.asyncio,
        "run",
        lambda _: pytest.fail("npm_wrapper should bypass without invoking aigate"),
    )

    npm_hook.npm_wrapper()

    assert seen == {"pm": "npm", "args": ["install", "react"]}


@pytest.mark.asyncio
async def test_npm_check_packages_passes_enrichment_into_consensus(monkeypatch, tmp_path):
    config = Config()
    config.enrichment.enabled = True
    config.cache_dir = str(tmp_path)  # isolate from user's real ~/.aigate/cache
    package = PackageInfo(name="react", version="18.0.0", ecosystem="npm")
    seen: dict[str, object] = {}

    monkeypatch.setattr("aigate.hooks.npm_hook.Config.load", lambda: config)

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    async def fake_download_source(_: PackageInfo) -> dict[str, str]:
        return {"package.json": '{"name":"react"}'}

    def fake_run_prefilter(
        _: PackageInfo,
        __: Config,
        ___: dict[str, str] | None = None,
    ) -> PrefilterResult:
        return PrefilterResult(
            passed=False,
            reason="needs review",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["signal"],
            needs_ai_review=True,
        )

    async def fake_run_enrichment(_: PackageInfo, __: object) -> EnrichmentResult:
        return EnrichmentResult(
            library_description="UI library",
            sources_queried=["osv"],
        )

    async def fake_run_consensus(**kwargs: object):
        seen["external_intelligence"] = kwargs["external_intelligence"]
        from aigate.models import ConsensusResult, Verdict

        return ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.9,
            summary="safe",
        )

    monkeypatch.setattr("aigate.hooks.npm_hook.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.hooks.npm_hook.download_source", fake_download_source)
    monkeypatch.setattr("aigate.hooks.npm_hook.run_prefilter", fake_run_prefilter)
    monkeypatch.setattr("aigate.hooks.npm_hook.run_enrichment", fake_run_enrichment)
    monkeypatch.setattr("aigate.hooks.npm_hook.run_consensus", fake_run_consensus)

    blocked = await npm_hook._check_packages([("react", None)])

    assert blocked == []
    assert "External Intelligence" in str(seen["external_intelligence"])


@pytest.mark.asyncio
async def test_npm_hook_uses_cache_on_hit(monkeypatch, tmp_path):
    """On cache hit, skip download/prefilter/consensus entirely."""
    config = Config()
    config.cache_dir = str(tmp_path)
    monkeypatch.setattr("aigate.hooks.npm_hook.Config.load", lambda: config)

    package = PackageInfo(name="react", version="18.2.0", ecosystem="npm")

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    monkeypatch.setattr("aigate.hooks.npm_hook.resolve_package", fake_resolve_package)

    safe_report = AnalysisReport(
        package=package,
        prefilter=PrefilterResult(passed=True, reason="safe", risk_level=RiskLevel.NONE),
    )
    set_cached(package.name, package.version, "npm", safe_report, str(tmp_path))

    async def fail_download(*_args, **_kwargs):
        pytest.fail("download_source must not be called on cache hit")

    def fail_prefilter(*_args, **_kwargs):
        pytest.fail("run_prefilter must not be called on cache hit")

    async def fail_consensus(*_args, **_kwargs):
        pytest.fail("run_consensus must not be called on cache hit")

    monkeypatch.setattr("aigate.hooks.npm_hook.download_source", fail_download)
    monkeypatch.setattr("aigate.hooks.npm_hook.run_prefilter", fail_prefilter)
    monkeypatch.setattr("aigate.hooks.npm_hook.run_consensus", fail_consensus)

    blocked = await npm_hook._check_packages([("react", None)])

    assert blocked == []


@pytest.mark.asyncio
async def test_npm_hook_does_not_cache_error_verdict(monkeypatch, tmp_path):
    """A transient AI ERROR must not get cached — otherwise one timeout
    silently suppresses retry for the full TTL window."""
    from aigate.cache import _cache_key
    from aigate.models import ConsensusResult, Verdict

    config = Config()
    config.cache_dir = str(tmp_path)
    config.enrichment.enabled = False
    monkeypatch.setattr("aigate.hooks.npm_hook.Config.load", lambda: config)

    package = PackageInfo(name="slow-pkg", version="1.0.0", ecosystem="npm")

    async def fake_resolve_package(_: str, __: str | None, ___: str) -> PackageInfo:
        return package

    async def fake_download_source(_: PackageInfo) -> dict[str, str]:
        return {"index.js": "console.log('hi')"}

    def fake_run_prefilter(*_args, **_kwargs) -> PrefilterResult:
        return PrefilterResult(
            passed=False,
            reason="needs review",
            risk_level=RiskLevel.MEDIUM,
            risk_signals=["s"],
            needs_ai_review=True,
        )

    async def fake_run_consensus(**_kwargs: object) -> ConsensusResult:
        return ConsensusResult(
            final_verdict=Verdict.ERROR, confidence=0.0, summary="backend failed"
        )

    monkeypatch.setattr("aigate.hooks.npm_hook.resolve_package", fake_resolve_package)
    monkeypatch.setattr("aigate.hooks.npm_hook.download_source", fake_download_source)
    monkeypatch.setattr("aigate.hooks.npm_hook.run_prefilter", fake_run_prefilter)
    monkeypatch.setattr("aigate.hooks.npm_hook.run_consensus", fake_run_consensus)

    blocked = await npm_hook._check_packages([("slow-pkg", None)])

    assert blocked == []
    key = _cache_key("slow-pkg", "1.0.0", "npm")
    assert not (tmp_path / f"{key}.json").exists()
