"""Install aigate PreToolUse hooks into AI coding tool configurations."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

# The shell script that all command-based hooks invoke
HOOK_SCRIPT_REL = "scripts/pretool-hook.sh"

TOOL_CHOICES = (
    "claude",
    "gemini",
    "codex",
    "cursor",
    "windsurf",
    "aider",
    "opencode",
    "cline",
    "all",
)

# ---------------------------------------------------------------------------
# Per-tool hook generators
# ---------------------------------------------------------------------------


def _find_hook_script() -> str:
    """Return absolute path to pretool-hook.sh, or fall back to `aigate` on PATH."""
    # Try relative to this package (works in dev installs)
    pkg_dir = Path(__file__).resolve().parent.parent.parent
    candidate = pkg_dir / HOOK_SCRIPT_REL
    if candidate.is_file():
        return str(candidate)
    # Fall back to installed binary
    aigate_bin = shutil.which("aigate")
    if aigate_bin:
        return f"{aigate_bin}-hook"
    return "aigate-hook"


def _hook_script_path() -> str:
    return _find_hook_script()


# ---------------------------------------------------------------------------
# JSON merge helper
# ---------------------------------------------------------------------------


def _deep_merge_hook_json(
    settings_path: Path,
    hook_entry: dict[str, Any],
    event_key: str,
) -> tuple[bool, str]:
    """Merge a hook entry into a JSON settings file under hooks.<event_key>.

    Returns (changed, message).
    """
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    else:
        settings = {}

    if "hooks" not in settings:
        settings["hooks"] = {}
    if event_key not in settings["hooks"]:
        settings["hooks"][event_key] = []

    # Check for duplicate (match by command string in nested hooks)
    new_cmd = _extract_command(hook_entry)
    for existing in settings["hooks"][event_key]:
        if _extract_command(existing) == new_cmd and new_cmd is not None:
            return False, f"aigate hook already exists in {settings_path}"

    settings["hooks"][event_key].append(hook_entry)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return True, f"Added aigate hook to {settings_path}"


def _extract_command(entry: dict[str, Any]) -> str | None:
    """Extract the command string from a hook entry (various formats)."""
    # Claude/Gemini/Codex style: entry.hooks[0].command
    for h in entry.get("hooks", []):
        cmd = h.get("command")
        if cmd:
            return cmd
    # Cursor/Windsurf style: entry.command
    cmd = entry.get("command")
    if cmd:
        return cmd
    return None


# ---------------------------------------------------------------------------
# Tool-specific installers
# ---------------------------------------------------------------------------


def install_claude(project_dir: Path) -> list[str]:
    """Install hook into .claude/settings.json."""
    script = _hook_script_path()
    hook_entry = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": script,
                "timeout": 30,
                "statusMessage": "aigate: scanning packages...",
            }
        ],
    }
    settings_path = project_dir / ".claude" / "settings.json"
    changed, msg = _deep_merge_hook_json(settings_path, hook_entry, "PreToolUse")
    return [msg] if changed else [f"(skip) {msg}"]


def install_gemini(project_dir: Path) -> list[str]:
    """Install hook into .gemini/settings.json."""
    script = _hook_script_path()
    hook_entry = {
        "matcher": "run_shell_command",
        "sequential": True,
        "hooks": [
            {
                "type": "command",
                "command": script,
                "name": "aigate-package-validator",
                "timeout": 5000,
                "description": "Validates package installations via aigate",
            }
        ],
    }
    settings_path = project_dir / ".gemini" / "settings.json"
    changed, msg = _deep_merge_hook_json(settings_path, hook_entry, "BeforeTool")
    return [msg] if changed else [f"(skip) {msg}"]


def install_codex(project_dir: Path) -> list[str]:
    """Install hook into .codex/hooks.json."""
    script = _hook_script_path()
    hook_entry = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": script,
                "statusMessage": "aigate: scanning packages...",
                "timeout": 600,
            }
        ],
    }
    settings_path = project_dir / ".codex" / "hooks.json"
    changed, msg = _deep_merge_hook_json(settings_path, hook_entry, "PreToolUse")
    return [msg] if changed else [f"(skip) {msg}"]


def install_cursor(project_dir: Path) -> list[str]:
    """Install hook into .cursor/hooks.json."""
    script = _hook_script_path()
    hook_entry = {
        "command": script,
        "type": "command",
        "timeout": 30,
        "failClosed": True,
    }
    settings_path = project_dir / ".cursor" / "hooks.json"

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    else:
        settings = {}

    if "version" not in settings:
        settings["version"] = 1
    if "hooks" not in settings:
        settings["hooks"] = {}
    if "beforeShellExecution" not in settings["hooks"]:
        settings["hooks"]["beforeShellExecution"] = []

    # Check duplicate
    for existing in settings["hooks"]["beforeShellExecution"]:
        if existing.get("command") == script:
            return [f"(skip) aigate hook already exists in {settings_path}"]

    settings["hooks"]["beforeShellExecution"].append(hook_entry)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return [f"Added aigate hook to {settings_path}"]


def install_windsurf(project_dir: Path) -> list[str]:
    """Install hook into .windsurf/hooks.json."""
    script = _hook_script_path()
    hook_entry = {
        "command": script,
        "show_output": True,
    }
    settings_path = project_dir / ".windsurf" / "hooks.json"

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    else:
        settings = {}

    if "hooks" not in settings:
        settings["hooks"] = {}
    if "pre_run_command" not in settings["hooks"]:
        settings["hooks"]["pre_run_command"] = []

    # Check duplicate
    for existing in settings["hooks"]["pre_run_command"]:
        if existing.get("command") == script:
            return [f"(skip) aigate hook already exists in {settings_path}"]

    settings["hooks"]["pre_run_command"].append(hook_entry)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return [f"Added aigate hook to {settings_path}"]


OPENCODE_PLUGIN_TEMPLATE = """\
// aigate package security scanner plugin for OpenCode
// Auto-generated by: aigate install-hooks --tool opencode

export default function aigatePlugin(context) {
  return {
    hooks: {
      beforeToolCall: async (event) => {
        const { name, input } = event;
        if (name !== "shell" && name !== "run_shell_command") return;
        const cmd = input?.command || input?.cmd || "";
        const installPattern = /\\b(pip|npm|yarn|pnpm)\\s+install\\b/;
        if (!installPattern.test(cmd)) return;
        // Extract package names and run aigate check individually
        const { execSync } = await import("child_process");
        const parts = cmd.split(/\\s+/);
        const installIdx = parts.findIndex(p => p === "install" || p === "add");
        if (installIdx === -1) return;
        const pkgs = parts.slice(installIdx + 1).filter(s => !s.startsWith("-"));
        for (const pkg of pkgs) {
          try {
            execSync(`aigate check ${JSON.stringify(pkg)}`, { timeout: 30000 });
          } catch (e) {
            if (e.status === 2) {
              return { blocked: true, reason: "aigate: malicious package detected" };
            }
          }
        }
      },
    },
  };
};
"""


def install_opencode(project_dir: Path) -> list[str]:
    """Install aigate plugin for OpenCode."""
    plugin_dir = project_dir / ".opencode" / "plugins"
    plugin_file = plugin_dir / "aigate-scanner.mjs"

    if plugin_file.exists():
        return [f"(skip) aigate plugin already exists at {plugin_file}"]

    plugin_dir.mkdir(parents=True, exist_ok=True)
    plugin_file.write_text(OPENCODE_PLUGIN_TEMPLATE)
    return [f"Added aigate plugin to {plugin_file}"]


CLINE_RULES_BLOCK = """\

# === aigate: Supply Chain Security ===
# Before running any pip install, npm install, yarn add, or pnpm add command,
# first run: aigate check <package_name> --skip-ai
# If aigate returns exit code 2 (malicious), DO NOT install the package.
# If aigate returns exit code 1 (suspicious), warn the user before proceeding.
# === end aigate ===
"""


def install_cline(project_dir: Path) -> list[str]:
    """Install aigate rules into .clinerules."""
    rules_file = project_dir / ".clinerules"

    if rules_file.exists():
        content = rules_file.read_text()
        if "aigate" in content:
            return [f"(skip) aigate already configured in {rules_file}"]
        content += CLINE_RULES_BLOCK
    else:
        content = CLINE_RULES_BLOCK.lstrip()

    rules_file.write_text(content)
    return [f"Added aigate rules to {rules_file}"]


def install_aider(project_dir: Path) -> list[str]:
    """Install aigate lint-cmd into .aider.conf.yml."""
    conf_path = project_dir / ".aider.conf.yml"
    aigate_lint = "aigate scan requirements.txt --skip-ai"

    if conf_path.exists():
        content = conf_path.read_text()
        if "aigate" in content:
            return [f"(skip) aigate already configured in {conf_path}"]
        # Append lint-cmd
        lines = content.rstrip("\n").split("\n") if content.strip() else []
    else:
        lines = []

    # Check if lint-cmd already exists
    has_lint_cmd = any(line.strip().startswith("lint-cmd:") for line in lines)
    if has_lint_cmd:
        # lint-cmd exists but without aigate — we prepend aigate to the value
        new_lines = []
        for line in lines:
            if line.strip().startswith("lint-cmd:"):
                existing_val = line.split(":", 1)[1].strip().strip('"').strip("'")
                new_val = f"{aigate_lint} && {existing_val}" if existing_val else aigate_lint
                new_lines.append(f'lint-cmd: "{new_val}"')
            else:
                new_lines.append(line)
        lines = new_lines
    else:
        lines.append("auto-lint: true")
        lines.append(f'lint-cmd: "{aigate_lint}"')

    conf_path.write_text("\n".join(lines) + "\n")
    return [f"Added aigate lint-cmd to {conf_path}"]


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

INSTALLERS: dict[str, Any] = {
    "claude": install_claude,
    "gemini": install_gemini,
    "codex": install_codex,
    "cursor": install_cursor,
    "windsurf": install_windsurf,
    "aider": install_aider,
    "opencode": install_opencode,
    "cline": install_cline,
}


def install_hooks(tools: list[str], project_dir: Path) -> list[str]:
    """Install hooks for the given tools. Returns list of status messages."""
    messages: list[str] = []
    if "all" in tools:
        tools = list(INSTALLERS.keys())

    for tool in tools:
        installer = INSTALLERS.get(tool)
        if installer is None:
            messages.append(f"Unknown tool: {tool}")
            continue
        msgs = installer(project_dir)
        messages.extend(msgs)

    return messages


# Tools that are file-based (no CLI binary to detect) — always included in auto mode
_FILE_BASED_TOOLS = {"cline", "opencode"}


def install_hooks_auto(project_dir: Path) -> list[str]:
    """Auto-detect installed AI tools and install hooks for all found.

    Binary-based tools are detected via ``shutil.which``.  File-based tools
    (cline, opencode) are always included because they don't require an
    external binary.
    """
    messages: list[str] = []
    for tool_name, installer_fn in INSTALLERS.items():
        if tool_name in _FILE_BASED_TOOLS or shutil.which(tool_name):
            msgs = installer_fn(project_dir)
            messages.extend(msgs)
    if not messages:
        messages.append("No supported AI tools detected. Install one and try again.")
    return messages
