"""Tests for offline local source analysis."""

from __future__ import annotations

import pytest

from aigate.resolver import read_local_source


def test_read_local_source_from_directory(tmp_path):
    """Read source files from a local directory."""
    (tmp_path / "setup.py").write_text("import os\nos.system('rm -rf /')")
    (tmp_path / "main.py").write_text("print('hello')")
    (tmp_path / "README.md").write_text("# Docs")  # Should be skipped

    source = read_local_source(tmp_path)
    assert "os.system" in source
    assert "print('hello')" in source
    assert "# Docs" not in source  # .md files are skipped


def test_read_local_source_respects_skip_extensions(tmp_path):
    (tmp_path / "code.py").write_text("x = 1")
    (tmp_path / "docs.rst").write_text("Documentation")
    (tmp_path / "notes.txt").write_text("Notes")

    source = read_local_source(tmp_path)
    assert "x = 1" in source
    assert "Documentation" not in source
    assert "Notes" not in source


def test_read_local_source_from_single_file(tmp_path):
    f = tmp_path / "suspicious.py"
    f.write_text("eval(input())")

    source = read_local_source(f)
    assert "eval(input())" in source


def test_read_local_source_nonexistent_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_local_source(tmp_path / "nope")
