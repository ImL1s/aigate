"""Generate AI tool instruction files for LLM-native package security."""

from __future__ import annotations

from pathlib import Path

from .skill_template import AIGATE_CHECK_SKILL, AIGATE_SCAN_SKILL

# The core instruction block — same content for all tools
AIGATE_INSTRUCTION = """\
## Package Security (aigate)

Before installing ANY package via pip, npm, yarn, or pnpm, ALWAYS run:

```
aigate check <package_name>
```

For npm packages:
```
aigate check <package_name> -e npm
```

**Interpret exit codes:**
- Exit 0 = safe, proceed with install
- Exit 1 = suspicious, warn the user before proceeding
- Exit 2 = malicious, DO NOT install. Inform the user immediately.

**For lockfile scanning:**
```
aigate scan requirements.txt
aigate scan package-lock.json
```

This is a supply chain security measure. Never skip this step.
"""

# Map of tool -> (file path relative to project root, how to inject)
INSTRUCTION_TARGETS = {
    "claude": {
        "path": "CLAUDE.md",
        "mode": "append",
    },
    "gemini": {
        "path": "GEMINI.md",
        "mode": "append",
    },
    "codex": {
        "path": "AGENTS.md",
        "mode": "append",
    },
    "cursor": {
        "path": ".cursorrules",
        "mode": "append",
    },
    "windsurf": {
        "path": ".windsurfrules",
        "mode": "append",
    },
    "cline": {
        "path": ".clinerules",
        "mode": "append",
    },
    "copilot": {
        "path": ".github/copilot-instructions.md",
        "mode": "append",
    },
    "opencode": {
        "path": "CONVENTIONS.md",
        "mode": "append",
    },
}

MARKER = "## Package Security (aigate)"


def generate_instruction_files(
    project_dir: Path,
    tools: list[str] | None = None,
) -> list[str]:
    """Generate/update AI instruction files with aigate security instructions.

    Args:
        project_dir: Project root directory.
        tools: List of tool names, or None for all.

    Returns:
        List of status messages.
    """
    messages = []
    targets = INSTRUCTION_TARGETS
    if tools:
        targets = {k: v for k, v in targets.items() if k in tools}

    for tool_name, config in targets.items():
        file_path = project_dir / config["path"]

        # Check if already has aigate instructions
        if file_path.exists():
            content = file_path.read_text()
            if MARKER in content:
                messages.append(f"(skip) {file_path} already has aigate instructions")
                continue
            # Append
            file_path.write_text(content.rstrip("\n") + "\n\n" + AIGATE_INSTRUCTION)
            messages.append(f"Updated {file_path} with aigate instructions")
        else:
            # Create parent dirs if needed (for .github/copilot-instructions.md)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(AIGATE_INSTRUCTION)
            messages.append(f"Created {file_path} with aigate instructions")

    return messages


# Skill file targets — same SKILL.md content for all tools
SKILL_TARGETS: dict[str, dict[str, str]] = {
    "claude": {
        "check": ".claude/skills/aigate-check/SKILL.md",
        "scan": ".claude/skills/aigate-scan/SKILL.md",
    },
    "gemini": {
        "check": ".gemini/skills/aigate-check/SKILL.md",
        "scan": ".gemini/skills/aigate-scan/SKILL.md",
    },
    "codex": {
        "check": ".codex/skills/aigate-check/SKILL.md",
        "scan": ".codex/skills/aigate-scan/SKILL.md",
    },
}

SKILL_MARKER = "name: aigate-check"


def generate_skill_files(
    project_dir: Path,
    tools: list[str] | None = None,
) -> list[str]:
    """Generate SKILL.md files for AI coding tools.

    Args:
        project_dir: Project root directory.
        tools: List of tool names (claude/gemini/codex), or None for all.

    Returns:
        List of status messages.
    """
    messages: list[str] = []
    targets = SKILL_TARGETS
    if tools:
        targets = {k: v for k, v in targets.items() if k in tools}

    skill_map = {
        "check": AIGATE_CHECK_SKILL,
        "scan": AIGATE_SCAN_SKILL,
    }

    for tool_name, paths in targets.items():
        for skill_kind, rel_path in paths.items():
            file_path = project_dir / rel_path
            content = skill_map[skill_kind]

            if file_path.exists():
                existing = file_path.read_text()
                if "name: aigate-" in existing:
                    messages.append(f"(skip) {file_path} already has aigate skill")
                    continue

            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            messages.append(f"Created {file_path} ({tool_name}/aigate-{skill_kind})")

    return messages
