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


# ---------------------------------------------------------------------------
# Phase 4 opensrc-integration-plan §3.5 — AIGATE_INSTRUCTION ecosystem list +
# opensrc stanza. Executor task spec: "verify AIGATE_INSTRUCTION contains
# 'crates', 'cocoapods', 'jsr', and 'opensrc' substrings; verify idempotent
# re-run via `aigate instructions` doesn't duplicate stanzas."
# ---------------------------------------------------------------------------


def test_aigate_instruction_mentions_all_six_ecosystems():
    """AIGATE_INSTRUCTION advertises pypi/npm/pub + crates/cocoapods/jsr."""
    for eco in ("pypi", "npm", "pub", "crates", "cocoapods", "jsr"):
        assert eco in AIGATE_INSTRUCTION, f"AIGATE_INSTRUCTION missing ecosystem mention: {eco}"


def test_aigate_instruction_includes_opensrc_stanza():
    """opensrc integration stanza is part of the shared instruction block."""
    assert "opensrc Integration" in AIGATE_INSTRUCTION
    assert "emit_opensrc" in AIGATE_INSTRUCTION
    assert "--emit-opensrc" in AIGATE_INSTRUCTION
    assert "aigate-provenance.json" in AIGATE_INSTRUCTION


def test_agents_md_includes_opensrc_and_new_ecosystems(tmp_path: Path):
    """AGENTS.md (codex target) inherits the enriched AIGATE_INSTRUCTION."""
    generate_instruction_files(tmp_path, tools=["codex"])
    agents_md = tmp_path / "AGENTS.md"
    assert agents_md.exists()
    content = agents_md.read_text()
    for needle in ("crates", "cocoapods", "jsr", "opensrc Integration"):
        assert needle in content, f"AGENTS.md missing {needle!r}"


def test_instructions_idempotent_rerun_no_duplicate_stanzas(tmp_path: Path):
    """Running `aigate instructions` twice must not duplicate the opensrc stanza."""
    # First pass: create the file
    generate_instruction_files(tmp_path, tools=["codex"])
    agents_md = tmp_path / "AGENTS.md"
    first = agents_md.read_text()
    assert first.count("## opensrc Integration") == 1
    assert first.count(MARKER) == 1

    # Second pass: should skip via the MARKER check, file unchanged
    messages = generate_instruction_files(tmp_path, tools=["codex"])
    assert len(messages) == 1
    assert messages[0].startswith("(skip)")
    second = agents_md.read_text()
    assert second == first
    assert second.count("## opensrc Integration") == 1
    assert second.count(MARKER) == 1
