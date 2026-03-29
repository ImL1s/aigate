"""Tests for SKILL.md file generation for AI coding tools."""

from __future__ import annotations

from pathlib import Path

from aigate.instructions import (
    SKILL_TARGETS,
    generate_skill_files,
)
from aigate.skill_template import AIGATE_CHECK_SKILL, AIGATE_SCAN_SKILL


def test_generate_creates_skill_files(tmp_path: Path):
    """Generates skill files for all 3 tools (claude, gemini, codex)."""
    messages = generate_skill_files(tmp_path)

    # 3 tools x 2 skills = 6 files
    assert len(messages) == 6
    for msg in messages:
        assert msg.startswith("Created ")

    for tool, paths in SKILL_TARGETS.items():
        for rel_path in paths.values():
            file_path = tmp_path / rel_path
            assert file_path.exists(), f"Missing: {file_path}"


def test_generate_specific_tool(tmp_path: Path):
    """Only generates for specified tool."""
    messages = generate_skill_files(tmp_path, tools=["gemini"])

    assert len(messages) == 2
    assert (tmp_path / ".gemini/skills/aigate-check/SKILL.md").exists()
    assert (tmp_path / ".gemini/skills/aigate-scan/SKILL.md").exists()
    # Others should NOT exist
    assert not (tmp_path / ".claude/skills/aigate-check/SKILL.md").exists()
    assert not (tmp_path / ".codex/skills/aigate-check/SKILL.md").exists()


def test_skill_has_correct_frontmatter(tmp_path: Path):
    """Generated skills have name and description in frontmatter."""
    generate_skill_files(tmp_path, tools=["claude"])

    check_content = (tmp_path / ".claude/skills/aigate-check/SKILL.md").read_text()
    assert "name: aigate-check" in check_content
    assert "description:" in check_content

    scan_content = (tmp_path / ".claude/skills/aigate-scan/SKILL.md").read_text()
    assert "name: aigate-scan" in scan_content
    assert "description:" in scan_content


def test_skill_skips_duplicate(tmp_path: Path):
    """Doesn't overwrite existing skill files."""
    # First generation
    generate_skill_files(tmp_path, tools=["claude"])
    check_path = tmp_path / ".claude/skills/aigate-check/SKILL.md"
    original_content = check_path.read_text()

    # Second generation should skip
    messages = generate_skill_files(tmp_path, tools=["claude"])
    assert len(messages) == 2
    for msg in messages:
        assert msg.startswith("(skip)")

    # Content unchanged
    assert check_path.read_text() == original_content


def test_skill_content_mentions_aigate(tmp_path: Path):
    """Generated skills contain aigate check/scan instructions."""
    generate_skill_files(tmp_path, tools=["codex"])

    check_content = (tmp_path / ".codex/skills/aigate-check/SKILL.md").read_text()
    assert "aigate check" in check_content
    assert "-e pypi" in check_content
    assert "-e npm" in check_content
    assert "Exit 0" in check_content
    assert "Exit 2" in check_content

    scan_content = (tmp_path / ".codex/skills/aigate-scan/SKILL.md").read_text()
    assert "aigate scan" in scan_content
    assert "requirements.txt" in scan_content
    assert "package-lock.json" in scan_content


def test_skill_templates_match_generated(tmp_path: Path):
    """Generated files match the template constants exactly."""
    generate_skill_files(tmp_path, tools=["claude"])

    check_content = (tmp_path / ".claude/skills/aigate-check/SKILL.md").read_text()
    assert check_content == AIGATE_CHECK_SKILL

    scan_content = (tmp_path / ".claude/skills/aigate-scan/SKILL.md").read_text()
    assert scan_content == AIGATE_SCAN_SKILL
