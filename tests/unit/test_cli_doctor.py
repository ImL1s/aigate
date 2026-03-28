"""Tests for aigate doctor command."""

from __future__ import annotations

from click.testing import CliRunner

from aigate.cli import main


def test_doctor_runs_without_error():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0


def test_doctor_shows_backend_status(monkeypatch):
    monkeypatch.setattr(
        "aigate.detect.shutil.which", lambda name: "/usr/bin/claude" if name == "claude" else None
    )
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "claude" in result.output.lower()


def test_doctor_shows_config_status():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "config" in result.output.lower() or ".aigate.yml" in result.output


def test_doctor_shows_hook_status():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "hook" in result.output.lower()


def test_doctor_shows_consensus_strategy(monkeypatch):
    monkeypatch.setattr("aigate.detect.shutil.which", lambda _: None)
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "prefilter-only" in result.output.lower()


def test_doctor_dual_model_strategy(monkeypatch):
    found = {"claude", "gemini"}
    monkeypatch.setattr(
        "aigate.detect.shutil.which", lambda name: f"/usr/bin/{name}" if name in found else None
    )
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "dual-model" in result.output.lower()
