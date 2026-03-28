"""Tests for AI tool instruction file generation."""

from __future__ import annotations

from pathlib import Path

from aigate.instructions import (
    AIGATE_INSTRUCTION,
    INSTRUCTION_TARGETS,
    MARKER,
    generate_instruction_files,
)


def test_generate_creates_new_files(tmp_path: Path):
    """Generates all 8 instruction files when none exist."""
    messages = generate_instruction_files(tmp_path)

    assert len(messages) == len(INSTRUCTION_TARGETS)
    for msg in messages:
        assert msg.startswith("Created ")

    for config in INSTRUCTION_TARGETS.values():
        file_path = tmp_path / config["path"]
        assert file_path.exists()
        assert file_path.read_text() == AIGATE_INSTRUCTION


def test_generate_appends_to_existing(tmp_path: Path):
    """Appends to existing file without destroying content."""
    existing_content = "# My Project\n\nSome existing rules."
    claude_md = tmp_path / "CLAUDE.md"
    claude_md.write_text(existing_content)

    generate_instruction_files(tmp_path, tools=["claude"])

    result = claude_md.read_text()
    assert result.startswith("# My Project")
    assert "Some existing rules." in result
    assert MARKER in result
    assert AIGATE_INSTRUCTION in result


def test_generate_skips_duplicate(tmp_path: Path):
    """Doesn't double-write if MARKER already exists."""
    claude_md = tmp_path / "CLAUDE.md"
    claude_md.write_text(f"# Existing\n\n{AIGATE_INSTRUCTION}")

    messages = generate_instruction_files(tmp_path, tools=["claude"])

    assert len(messages) == 1
    assert messages[0].startswith("(skip)")
    # Content should be unchanged
    assert claude_md.read_text().count(MARKER) == 1


def test_generate_specific_tools(tmp_path: Path):
    """Only generates for specified tools."""
    messages = generate_instruction_files(tmp_path, tools=["claude", "cursor"])

    assert len(messages) == 2
    assert (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / ".cursorrules").exists()
    # Others should NOT exist
    assert not (tmp_path / "GEMINI.md").exists()
    assert not (tmp_path / "AGENTS.md").exists()


def test_generate_copilot_creates_parent_dir(tmp_path: Path):
    """Creates .github/ dir if needed for copilot-instructions.md."""
    github_dir = tmp_path / ".github"
    assert not github_dir.exists()

    generate_instruction_files(tmp_path, tools=["copilot"])

    copilot_file = github_dir / "copilot-instructions.md"
    assert copilot_file.exists()
    assert MARKER in copilot_file.read_text()


def test_all_targets_have_consistent_marker(tmp_path: Path):
    """All generated files contain MARKER (single source of truth)."""
    generate_instruction_files(tmp_path)

    for config in INSTRUCTION_TARGETS.values():
        file_path = tmp_path / config["path"]
        content = file_path.read_text()
        assert MARKER in content, f"{file_path} missing MARKER"
        assert "aigate check" in content, f"{file_path} missing usage instructions"
