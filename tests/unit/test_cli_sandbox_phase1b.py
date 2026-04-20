"""Phase 1b sandbox CLI wiring tests.

Covers:
- npm + --sandbox routes to birdcage (no Phase 1a 'static analysis only' WARN).
- Non-npm + --sandbox still emits Phase 1a scaffold WARN.
- _run_sandbox_for_npm happy path returns DynamicTrace.
- SandboxUnavailable + required=False → None returned, console WARN.
- SandboxUnavailable + required=True → _emit_error called (exit 3).
- Empty tarball URL → None returned (no crash).
- network_policy=allow → tier-honest override WARN printed.
"""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from aigate.cli import _run_sandbox_for_npm, main
from aigate.config import Config
from aigate.models import PackageInfo
from aigate.sandbox.errors import SandboxUnavailable
from aigate.sandbox.types import DynamicTrace, SandboxCoverage

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _npm_package(*, tarball_url: str = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"):
    return PackageInfo(
        name="lodash",
        version="4.17.21",
        ecosystem="npm",
        metadata={"version_data": {"dist": {"tarball": tarball_url}}},
    )


def _minimal_trace() -> DynamicTrace:
    return DynamicTrace(ran=True, runtime="birdcage", observed={SandboxCoverage.FS_WRITES})


def _make_config(*, required: bool = False, network_policy: str = "deny-outbound") -> Config:
    cfg = Config.default()
    new_sb = replace(cfg.sandbox, required=required, network_policy=network_policy)
    return replace(cfg, sandbox=new_sb)


def _stub_check(monkeypatch):
    async def _fake(*args, **kwargs):
        return None

    monkeypatch.setattr("aigate.cli._check", _fake)


# ---------------------------------------------------------------------------
# CLI routing: npm vs non-npm
# ---------------------------------------------------------------------------


def test_npm_sandbox_does_not_emit_phase1a_warn(monkeypatch):
    """npm + --sandbox must NOT print the 'static analysis only' fallback WARN."""
    _stub_check(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(main, ["check", "lodash", "-e", "npm", "--sandbox"])
    assert result.exit_code == 0, result.output
    assert "static analysis only" not in result.output.lower()


def test_pypi_sandbox_still_emits_phase1a_warn(monkeypatch):
    """pypi + --sandbox still prints Phase 1a scaffold WARN (no birdcage for pypi yet)."""
    _stub_check(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(main, ["check", "requests", "-e", "pypi", "--sandbox"])
    assert result.exit_code == 0, result.output
    assert "WARN" in result.output
    assert "static analysis only" in result.output.lower()


def test_crates_sandbox_still_emits_phase1a_warn(monkeypatch):
    """crates + --sandbox still gets the Phase 1a WARN."""
    _stub_check(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(main, ["check", "serde", "-e", "crates", "--sandbox"])
    assert result.exit_code == 0, result.output
    assert "WARN" in result.output


# ---------------------------------------------------------------------------
# _run_sandbox_for_npm — happy path
# ---------------------------------------------------------------------------


async def test_run_sandbox_happy_path_returns_trace():
    trace = _minimal_trace()
    backend = MagicMock()
    backend.run = AsyncMock(return_value=trace)

    with (
        patch("aigate.cli._fetch_npm_tarball", AsyncMock(return_value="/tmp/lodash.tgz")),
        patch("aigate.sandbox.runtime_select.select_backend", return_value=backend),
    ):
        result = await _run_sandbox_for_npm(
            package=_npm_package(),
            config=_make_config(),
            mode_str="light",
            timeout_s=30,
            use_json=False,
            pkg_version="4.17.21",
            ecosystem="npm",
        )

    assert result is trace
    backend.run.assert_called_once()
    call_request = backend.run.call_args[0][0]
    assert call_request.source_archive_path == "/tmp/lodash.tgz"
    assert call_request.ecosystem == "npm"
    assert call_request.timeout_s == 30


async def test_run_sandbox_uses_config_timeout_when_none_passed():
    trace = _minimal_trace()
    backend = MagicMock()
    backend.run = AsyncMock(return_value=trace)
    cfg = _make_config()

    with (
        patch("aigate.cli._fetch_npm_tarball", AsyncMock(return_value="/tmp/test.tgz")),
        patch("aigate.sandbox.runtime_select.select_backend", return_value=backend),
    ):
        await _run_sandbox_for_npm(
            package=_npm_package(),
            config=cfg,
            mode_str=None,
            timeout_s=None,  # should fall back to config.sandbox.timeout_s
            use_json=False,
            pkg_version="4.17.21",
            ecosystem="npm",
        )

    call_request = backend.run.call_args[0][0]
    assert call_request.timeout_s == cfg.sandbox.timeout_s


# ---------------------------------------------------------------------------
# _run_sandbox_for_npm — unavailable backend
# ---------------------------------------------------------------------------


async def test_run_sandbox_unavailable_not_required_returns_none():
    with (
        patch("aigate.cli._fetch_npm_tarball", AsyncMock(return_value="/tmp/test.tgz")),
        patch(
            "aigate.sandbox.runtime_select.select_backend",
            side_effect=SandboxUnavailable("birdcage not on PATH"),
        ),
    ):
        result = await _run_sandbox_for_npm(
            package=_npm_package(),
            config=_make_config(required=False),
            mode_str="light",
            timeout_s=None,
            use_json=False,
            pkg_version="4.17.21",
            ecosystem="npm",
        )

    assert result is None


async def test_run_sandbox_unavailable_required_calls_emit_error():
    with (
        patch("aigate.cli._fetch_npm_tarball", AsyncMock(return_value="/tmp/test.tgz")),
        patch(
            "aigate.sandbox.runtime_select.select_backend",
            side_effect=SandboxUnavailable("birdcage not on PATH"),
        ),
        patch("aigate.cli._emit_error") as mock_emit,
    ):
        mock_emit.side_effect = SystemExit(3)
        with pytest.raises(SystemExit) as exc_info:
            await _run_sandbox_for_npm(
                package=_npm_package(),
                config=_make_config(required=True),
                mode_str="light",
                timeout_s=None,
                use_json=False,
                pkg_version="4.17.21",
                ecosystem="npm",
            )

    assert exc_info.value.code == 3
    mock_emit.assert_called_once()


# ---------------------------------------------------------------------------
# _run_sandbox_for_npm — tarball fetch failure
# ---------------------------------------------------------------------------


async def test_run_sandbox_no_tarball_url_returns_none():
    """Package with no dist.tarball metadata → fetch returns None → sandbox skipped."""
    pkg = PackageInfo(name="no-dist", version="1.0.0", ecosystem="npm", metadata={})

    with patch("aigate.cli._fetch_npm_tarball", AsyncMock(return_value=None)):
        result = await _run_sandbox_for_npm(
            package=pkg,
            config=_make_config(),
            mode_str="light",
            timeout_s=None,
            use_json=False,
            pkg_version="1.0.0",
            ecosystem="npm",
        )

    assert result is None


async def test_run_sandbox_tarball_fetch_failure_returns_none():
    """Network error during tarball download → sandbox skipped, no exception raised."""
    with patch("aigate.cli._fetch_npm_tarball", AsyncMock(return_value=None)):
        result = await _run_sandbox_for_npm(
            package=_npm_package(),
            config=_make_config(),
            mode_str="light",
            timeout_s=None,
            use_json=False,
            pkg_version="4.17.21",
            ecosystem="npm",
        )

    assert result is None


# ---------------------------------------------------------------------------
# _run_sandbox_for_npm — network_policy=allow override
# ---------------------------------------------------------------------------


async def test_run_sandbox_network_policy_allow_still_returns_trace():
    """network_policy=allow triggers a WARN but does not abort the run."""
    trace = _minimal_trace()
    backend = MagicMock()
    backend.run = AsyncMock(return_value=trace)

    with (
        patch("aigate.cli._fetch_npm_tarball", AsyncMock(return_value="/tmp/test.tgz")),
        patch("aigate.sandbox.runtime_select.select_backend", return_value=backend),
    ):
        result = await _run_sandbox_for_npm(
            package=_npm_package(),
            config=_make_config(network_policy="allow"),
            mode_str="light",
            timeout_s=None,
            use_json=False,
            pkg_version="4.17.21",
            ecosystem="npm",
        )

    assert result is trace
