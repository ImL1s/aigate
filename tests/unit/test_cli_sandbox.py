"""CLI surface tests for the Phase 1a sandbox scaffold (PRD v3.1 §3.3).

These tests lock down ONLY the Phase 1a contract:
- ``--sandbox`` (and every ``--sandbox-*`` sub-flag) is accepted by
  ``check`` / ``scan`` / ``diff``.
- Selecting ``--sandbox`` emits a WARN line and falls back to static
  analysis (the static analysis itself is stubbed out).
- ``paranoid`` is accepted as a deprecated alias for ``strict`` and
  triggers a DeprecationWarning.
- ``aigate doctor --sandbox`` runs the shallow preflight without error.
- ``aigate sandbox init`` prints the default block + WARN (Phase 1a stub).

Phase 1b tests (actual Birdcage / Docker invocation, cache key shape,
cost-budget enforcement) are intentionally out of scope here.
"""

from __future__ import annotations

import warnings

from click.testing import CliRunner

from aigate.cli import (
    SANDBOX_MODE_CHOICES,
    SANDBOX_RUNTIME_CHOICES,
    _normalize_sandbox_mode,
    main,
)
from aigate.config import Config, SandboxConfig

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _stub_check_pipeline(monkeypatch):
    """Stub the async ``_check`` pipeline so invoking ``aigate check`` is
    fast AND deterministic — Phase 1a cares about CLI wiring, not runtime."""

    async def _fake_check(*args, **kwargs):  # pragma: no cover — trivial stub
        return None

    monkeypatch.setattr("aigate.cli._check", _fake_check)


def _stub_scan_pipeline(monkeypatch, tmp_path):
    async def _fake_scan(*args, **kwargs):  # pragma: no cover — trivial stub
        return None

    monkeypatch.setattr("aigate.cli._scan", _fake_scan)
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("requests==2.31.0\n")
    return lockfile


def _stub_diff_pipeline(monkeypatch):
    async def _fake_diff(*args, **kwargs):  # pragma: no cover — trivial stub
        return None

    monkeypatch.setattr("aigate.cli._diff", _fake_diff)


# ---------------------------------------------------------------------------
# Constants / unit helpers
# ---------------------------------------------------------------------------


def test_sandbox_mode_choices_expose_canonical_and_deprecated():
    # canonical
    assert "light" in SANDBOX_MODE_CHOICES
    assert "strict" in SANDBOX_MODE_CHOICES
    assert "auto" in SANDBOX_MODE_CHOICES
    # deprecated alias must still be accepted at CLI boundary
    assert "paranoid" in SANDBOX_MODE_CHOICES


def test_sandbox_runtime_choices_include_docker_only_escape_hatch():
    # GPL escape hatch (PRD §3.3)
    assert "docker-only" in SANDBOX_RUNTIME_CHOICES
    assert "docker+runsc" in SANDBOX_RUNTIME_CHOICES
    assert "birdcage" in SANDBOX_RUNTIME_CHOICES


def test_normalize_sandbox_mode_returns_none_for_none():
    assert _normalize_sandbox_mode(None) is None


def test_normalize_sandbox_mode_passes_canonical_values_through():
    assert _normalize_sandbox_mode("light") == "light"
    assert _normalize_sandbox_mode("STRICT") == "strict"
    assert _normalize_sandbox_mode("auto") == "auto"


def test_normalize_sandbox_mode_folds_paranoid_into_strict_with_warning():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert _normalize_sandbox_mode("paranoid") == "strict"
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, "paranoid alias must emit DeprecationWarning"
    assert "paranoid" in str(deprecation[0].message).lower()


# ---------------------------------------------------------------------------
# aigate check --sandbox
# ---------------------------------------------------------------------------


def test_check_accepts_sandbox_flag_and_emits_warn(monkeypatch):
    _stub_check_pipeline(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(main, ["check", "demo", "--sandbox"])
    assert result.exit_code == 0, result.output
    assert "WARN" in result.output
    # Must clearly signal we fell back to static analysis
    assert "static analysis" in result.output.lower()


def test_check_sandbox_mode_paranoid_is_accepted_as_alias(monkeypatch):
    _stub_check_pipeline(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(main, ["check", "demo", "--sandbox", "--sandbox-mode", "paranoid"])
    assert result.exit_code == 0, result.output
    # The WARN line MUST show the normalized name (strict) so UX doesn't
    # silently preserve the deprecated alias downstream.
    assert "mode=strict" in result.output


def test_check_sandbox_full_option_surface_parses(monkeypatch):
    _stub_check_pipeline(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            "demo",
            "--sandbox",
            "--sandbox-mode",
            "strict",
            "--sandbox-runtime",
            "docker+runsc",
            "--sandbox-timeout",
            "45",
            "--sandbox-eager",
            "--no-sandbox-cache",
            "--debug-trace",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "WARN" in result.output
    assert "mode=strict" in result.output
    assert "runtime=docker+runsc" in result.output


def test_check_without_sandbox_does_not_emit_warn(monkeypatch):
    _stub_check_pipeline(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(main, ["check", "demo"])
    assert result.exit_code == 0, result.output
    assert "WARN: aigate check --sandbox" not in result.output


def test_check_sandbox_timeout_out_of_range_rejected(monkeypatch):
    _stub_check_pipeline(monkeypatch)
    runner = CliRunner()
    # 5 is below the documented PRD min of 10
    result = runner.invoke(main, ["check", "demo", "--sandbox", "--sandbox-timeout", "5"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output or "out of range" in result.output.lower()


def test_check_sandbox_invalid_runtime_rejected(monkeypatch):
    _stub_check_pipeline(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(main, ["check", "demo", "--sandbox", "--sandbox-runtime", "bogus"])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# aigate scan --sandbox
# ---------------------------------------------------------------------------


def test_scan_accepts_sandbox_flag_and_emits_warn(monkeypatch, tmp_path):
    lockfile = _stub_scan_pipeline(monkeypatch, tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(lockfile), "--sandbox"])
    assert result.exit_code == 0, result.output
    assert "WARN" in result.output
    assert "scan --sandbox" in result.output


def test_scan_sandbox_eager_toggle_parses(monkeypatch, tmp_path):
    lockfile = _stub_scan_pipeline(monkeypatch, tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(lockfile), "--sandbox", "--no-sandbox-eager"])
    assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# aigate diff --sandbox
# ---------------------------------------------------------------------------


def test_diff_accepts_sandbox_flag_and_emits_warn(monkeypatch):
    _stub_diff_pipeline(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["diff", "demo", "1.0.0", "1.0.1", "--sandbox", "--sandbox-mode", "light"],
    )
    assert result.exit_code == 0, result.output
    assert "WARN" in result.output
    assert "diff --sandbox" in result.output
    assert "mode=light" in result.output


# ---------------------------------------------------------------------------
# aigate doctor --sandbox
# ---------------------------------------------------------------------------


def test_doctor_accepts_sandbox_preflight_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor", "--sandbox"])
    assert result.exit_code == 0, result.output
    # shallow section always present
    assert "Sandbox:" in result.output
    # deep preflight section appears only with --sandbox
    assert "Sandbox preflight" in result.output
    assert "Phase 1a scaffold" in result.output


def test_doctor_without_sandbox_still_shows_shallow_block():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0, result.output
    # Shallow block must always exist (PRD §3.3: "aigate doctor surfaces
    # sandbox availability" even without --sandbox).
    assert "Sandbox:" in result.output
    # Deep preflight must NOT be printed when the flag is absent.
    assert "Sandbox preflight" not in result.output


# ---------------------------------------------------------------------------
# aigate sandbox init (stub)
# ---------------------------------------------------------------------------


def test_sandbox_subcommand_init_prints_warn_and_default_block():
    runner = CliRunner()
    result = runner.invoke(main, ["sandbox", "init"])
    assert result.exit_code == 0, result.output
    assert "WARN" in result.output
    # Must actually show something users can copy-paste
    assert "sandbox:" in result.output
    assert "enabled: false" in result.output
    assert "mode: auto" in result.output


def test_sandbox_subcommand_init_force_is_accepted():
    runner = CliRunner()
    result = runner.invoke(main, ["sandbox", "init", "--force"])
    assert result.exit_code == 0, result.output


def test_sandbox_subcommand_group_help_lists_init():
    runner = CliRunner()
    result = runner.invoke(main, ["sandbox", "--help"])
    assert result.exit_code == 0, result.output
    assert "init" in result.output


# ---------------------------------------------------------------------------
# Config wiring — sanity checks that cli.py is actually consuming the
# SandboxConfig that worker #2 added. These are NOT end-to-end tests;
# they lock down the import boundary so future refactors can't silently
# decouple the CLI from the config dataclass.
# ---------------------------------------------------------------------------


def test_cli_imports_sandbox_config_from_config_module():
    # If this import path ever changes, the scaffold WARN path breaks
    # because _effective_sandbox_config instantiates SandboxConfig.
    from aigate.cli import SandboxConfig as CliSandboxConfig

    assert CliSandboxConfig is SandboxConfig


def test_cli_imports_sandbox_types_from_sandbox_module():
    # Phase 1a task #3 requires importing types from sandbox module.
    # This test locks that contract so worker #1's scaffold stays wired.
    from aigate.cli import SandboxBackend, SandboxMode, SandboxUnavailable

    assert SandboxBackend is not None
    assert SandboxMode is not None
    assert SandboxUnavailable is not None


def test_default_sandbox_config_matches_prd_opt_in_default():
    # PRD §3.4: sandbox is OPT-IN. If this default flips, doctor's
    # "enabled: yes/no" line and every CI gate has to be rechecked.
    cfg = Config.default()
    assert cfg.sandbox.enabled is False
    assert cfg.sandbox.mode == "auto"
    assert cfg.sandbox.runtime == "auto"
