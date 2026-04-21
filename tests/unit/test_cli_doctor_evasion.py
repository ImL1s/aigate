"""Tests for aigate doctor --sandbox evasion diagnostics (Phase 3 T15)."""

from __future__ import annotations

from click.testing import CliRunner

from aigate.cli import main


def test_doctor_sandbox_surfaces_evasion_counts():
    """doctor --sandbox output must include detector_count: 7."""
    runner = CliRunner()
    result = runner.invoke(main, ["doctor", "--sandbox"])
    assert result.exit_code == 0, f"doctor --sandbox exited {result.exit_code}:\n{result.output}"
    assert "detector_count: 7" in result.output, (
        f"'detector_count: 7' not found in doctor --sandbox output:\n{result.output}"
    )
