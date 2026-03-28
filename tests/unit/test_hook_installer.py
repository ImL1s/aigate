"""Tests for the install-hooks CLI command and hook_installer module."""

from __future__ import annotations

import json

from aigate.hook_installer import (
    install_aider,
    install_claude,
    install_cline,
    install_codex,
    install_cursor,
    install_gemini,
    install_hooks,
    install_hooks_auto,
    install_opencode,
    install_windsurf,
)

# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------


class TestInstallClaude:
    def test_creates_settings_from_scratch(self, tmp_path):
        msgs = install_claude(tmp_path)
        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.exists()
        data = json.loads(settings_path.read_text())
        assert "PreToolUse" in data["hooks"]
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert data["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
        assert any("Added" in m for m in msgs)

    def test_merges_into_existing_settings(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps({"permissions": {"allow": ["Read"]}}))

        install_claude(tmp_path)
        data = json.loads(settings_path.read_text())
        # Original key preserved
        assert data["permissions"]["allow"] == ["Read"]
        # Hook added
        assert len(data["hooks"]["PreToolUse"]) == 1

    def test_skips_duplicate(self, tmp_path):
        install_claude(tmp_path)
        msgs = install_claude(tmp_path)
        assert any("skip" in m for m in msgs)
        # Still only one hook
        data = json.loads((tmp_path / ".claude" / "settings.json").read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1

    def test_preserves_existing_hooks(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        existing = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Write", "hooks": [{"type": "command", "command": "other.sh"}]}
                ]
            }
        }
        settings_path.write_text(json.dumps(existing))

        install_claude(tmp_path)
        data = json.loads(settings_path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 2
        assert data["hooks"]["PreToolUse"][0]["matcher"] == "Write"
        assert data["hooks"]["PreToolUse"][1]["matcher"] == "Bash"


# ---------------------------------------------------------------------------
# Gemini CLI
# ---------------------------------------------------------------------------


class TestInstallGemini:
    def test_creates_settings_from_scratch(self, tmp_path):
        install_gemini(tmp_path)
        data = json.loads((tmp_path / ".gemini" / "settings.json").read_text())
        assert "BeforeTool" in data["hooks"]
        entry = data["hooks"]["BeforeTool"][0]
        assert entry["matcher"] == "run_shell_command"
        assert entry["sequential"] is True
        assert entry["hooks"][0]["name"] == "aigate-package-validator"

    def test_skips_duplicate(self, tmp_path):
        install_gemini(tmp_path)
        msgs = install_gemini(tmp_path)
        assert any("skip" in m for m in msgs)


# ---------------------------------------------------------------------------
# Codex CLI
# ---------------------------------------------------------------------------


class TestInstallCodex:
    def test_creates_hooks_json(self, tmp_path):
        install_codex(tmp_path)
        data = json.loads((tmp_path / ".codex" / "hooks.json").read_text())
        assert "PreToolUse" in data["hooks"]
        assert data["hooks"]["PreToolUse"][0]["matcher"] == "Bash"

    def test_skips_duplicate(self, tmp_path):
        install_codex(tmp_path)
        msgs = install_codex(tmp_path)
        assert any("skip" in m for m in msgs)


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


class TestInstallCursor:
    def test_creates_hooks_json_with_version(self, tmp_path):
        install_cursor(tmp_path)
        data = json.loads((tmp_path / ".cursor" / "hooks.json").read_text())
        assert data["version"] == 1
        assert "beforeShellExecution" in data["hooks"]
        entry = data["hooks"]["beforeShellExecution"][0]
        assert entry["type"] == "command"
        assert entry["failClosed"] is True

    def test_preserves_existing_version(self, tmp_path):
        settings_path = tmp_path / ".cursor" / "hooks.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps({"version": 1, "hooks": {}}))

        install_cursor(tmp_path)
        data = json.loads(settings_path.read_text())
        assert data["version"] == 1
        assert len(data["hooks"]["beforeShellExecution"]) == 1

    def test_skips_duplicate(self, tmp_path):
        install_cursor(tmp_path)
        msgs = install_cursor(tmp_path)
        assert any("skip" in m for m in msgs)


# ---------------------------------------------------------------------------
# Windsurf
# ---------------------------------------------------------------------------


class TestInstallWindsurf:
    def test_creates_hooks_json(self, tmp_path):
        install_windsurf(tmp_path)
        data = json.loads((tmp_path / ".windsurf" / "hooks.json").read_text())
        assert "pre_run_command" in data["hooks"]
        entry = data["hooks"]["pre_run_command"][0]
        assert entry["show_output"] is True

    def test_skips_duplicate(self, tmp_path):
        install_windsurf(tmp_path)
        msgs = install_windsurf(tmp_path)
        assert any("skip" in m for m in msgs)


# ---------------------------------------------------------------------------
# Aider
# ---------------------------------------------------------------------------


class TestInstallAider:
    def test_creates_conf_from_scratch(self, tmp_path):
        install_aider(tmp_path)
        content = (tmp_path / ".aider.conf.yml").read_text()
        assert "auto-lint: true" in content
        assert "aigate scan requirements.txt --skip-ai" in content

    def test_skips_if_already_configured(self, tmp_path):
        conf = tmp_path / ".aider.conf.yml"
        conf.write_text('lint-cmd: "aigate scan requirements.txt --skip-ai"\n')
        msgs = install_aider(tmp_path)
        assert any("skip" in m for m in msgs)

    def test_prepends_to_existing_lint_cmd(self, tmp_path):
        conf = tmp_path / ".aider.conf.yml"
        conf.write_text('lint-cmd: "pylint"\nauto-test: false\n')
        install_aider(tmp_path)
        content = conf.read_text()
        assert "aigate scan requirements.txt --skip-ai && pylint" in content
        assert "auto-test: false" in content


# ---------------------------------------------------------------------------
# OpenCode
# ---------------------------------------------------------------------------


class TestInstallOpencode:
    def test_creates_plugin(self, tmp_path):
        msgs = install_opencode(tmp_path)
        assert any("opencode" in m.lower() or "Added" in m for m in msgs)
        plugin_dir = tmp_path / ".opencode" / "plugins"
        assert plugin_dir.exists()
        plugin_files = list(plugin_dir.glob("aigate*"))
        assert len(plugin_files) >= 1

    def test_plugin_content(self, tmp_path):
        install_opencode(tmp_path)
        plugin_file = tmp_path / ".opencode" / "plugins" / "aigate-scanner.mjs"
        content = plugin_file.read_text()
        assert "beforeToolCall" in content
        assert "pip" in content
        assert "npm" in content
        assert "aigate check" in content

    def test_skip_duplicate(self, tmp_path):
        install_opencode(tmp_path)
        msgs = install_opencode(tmp_path)
        assert any("skip" in m.lower() for m in msgs)


# ---------------------------------------------------------------------------
# Cline
# ---------------------------------------------------------------------------


class TestInstallCline:
    def test_creates_rules_file(self, tmp_path):
        msgs = install_cline(tmp_path)
        assert any("cline" in m.lower() or "Added" in m for m in msgs)
        rules_file = tmp_path / ".clinerules"
        assert rules_file.exists()
        content = rules_file.read_text()
        assert "aigate" in content
        assert "aigate check" in content
        assert "pip install" in content
        assert "npm install" in content

    def test_appends_to_existing(self, tmp_path):
        rules_file = tmp_path / ".clinerules"
        rules_file.write_text("# Existing rules\nAlways use TypeScript.\n")
        install_cline(tmp_path)
        content = rules_file.read_text()
        assert "Existing rules" in content
        assert "Always use TypeScript." in content
        assert "aigate" in content

    def test_skip_duplicate(self, tmp_path):
        install_cline(tmp_path)
        msgs = install_cline(tmp_path)
        assert any("skip" in m.lower() for m in msgs)
        # Content should not be duplicated
        content = (tmp_path / ".clinerules").read_text()
        assert content.count("=== aigate") == 1


# ---------------------------------------------------------------------------
# Dispatcher: install_hooks()
# ---------------------------------------------------------------------------


class TestInstallHooksDispatcher:
    def test_single_tool(self, tmp_path):
        msgs = install_hooks(["claude"], tmp_path)
        assert any("Added" in m for m in msgs)
        assert (tmp_path / ".claude" / "settings.json").exists()

    def test_multiple_tools(self, tmp_path):
        install_hooks(["claude", "gemini"], tmp_path)
        assert (tmp_path / ".claude" / "settings.json").exists()
        assert (tmp_path / ".gemini" / "settings.json").exists()

    def test_all_installs_everything(self, tmp_path):
        msgs = install_hooks(["all"], tmp_path)
        assert (tmp_path / ".claude" / "settings.json").exists()
        assert (tmp_path / ".gemini" / "settings.json").exists()
        assert (tmp_path / ".codex" / "hooks.json").exists()
        assert (tmp_path / ".cursor" / "hooks.json").exists()
        assert (tmp_path / ".windsurf" / "hooks.json").exists()
        assert (tmp_path / ".aider.conf.yml").exists()
        assert (tmp_path / ".opencode" / "plugins" / "aigate-scanner.mjs").exists()
        assert (tmp_path / ".clinerules").exists()
        # Should have 8 success messages (all tools)
        added = [m for m in msgs if "Added" in m]
        assert len(added) == 8

    def test_unknown_tool(self, tmp_path):
        msgs = install_hooks(["nonexistent"], tmp_path)
        assert any("Unknown" in m for m in msgs)

    def test_idempotent(self, tmp_path):
        install_hooks(["all"], tmp_path)
        msgs = install_hooks(["all"], tmp_path)
        skipped = [m for m in msgs if "skip" in m]
        assert len(skipped) == 8


# ---------------------------------------------------------------------------
# CLI integration (via Click test runner)
# ---------------------------------------------------------------------------


class TestInstallHooksCLI:
    def test_help(self):
        from click.testing import CliRunner

        from aigate.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["install-hooks", "--help"])
        assert result.exit_code == 0
        assert "--tool" in result.output

    def test_invoke_claude(self, tmp_path):
        from click.testing import CliRunner

        from aigate.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main, ["install-hooks", "--tool", "claude", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert (tmp_path / ".claude" / "settings.json").exists()

    def test_invoke_all(self, tmp_path):
        from click.testing import CliRunner

        from aigate.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main, ["install-hooks", "--tool", "all", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert (tmp_path / ".claude" / "settings.json").exists()
        assert (tmp_path / ".gemini" / "settings.json").exists()

    def test_multiple_tools(self, tmp_path):
        from click.testing import CliRunner

        from aigate.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "install-hooks",
                "--tool",
                "cursor",
                "--tool",
                "windsurf",
                "--project-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        assert (tmp_path / ".cursor" / "hooks.json").exists()
        assert (tmp_path / ".windsurf" / "hooks.json").exists()


# ---------------------------------------------------------------------------
# install_hooks_auto()
# ---------------------------------------------------------------------------


class TestInstallHooksAuto:
    def test_detects_installed_tools(self, tmp_path, monkeypatch):
        """Auto should only install hooks for tools whose binaries are found."""
        installed = {"claude", "gemini"}
        monkeypatch.setattr(
            "aigate.hook_installer.shutil.which",
            lambda name: f"/usr/bin/{name}" if name in installed else None,
        )
        msgs = install_hooks_auto(tmp_path)
        # Binary-detected tools
        assert any("claude" in m.lower() for m in msgs)
        assert any("gemini" in m.lower() for m in msgs)
        # File-based tools always included
        assert any("clinerules" in m.lower() for m in msgs)
        assert any("opencode" in m.lower() for m in msgs)
        # Binary-based tools NOT installed should be absent
        assert not any("codex" in m.lower() for m in msgs)
        assert not any("cursor" in m.lower() for m in msgs)
        assert not any("windsurf" in m.lower() for m in msgs)
        assert not any("aider" in m.lower() for m in msgs)

    def test_no_tools_detected(self, tmp_path, monkeypatch):
        """When no binary tools are found, file-based tools still install."""
        monkeypatch.setattr(
            "aigate.hook_installer.shutil.which",
            lambda _name: None,
        )
        msgs = install_hooks_auto(tmp_path)
        # File-based tools still produce messages
        assert any("clinerules" in m.lower() for m in msgs)
        assert any("opencode" in m.lower() for m in msgs)
        # No "No supported AI tools" since file-based tools produce output
        assert not any("No supported" in m for m in msgs)

    def test_all_tools_detected(self, tmp_path, monkeypatch):
        """When all binaries are found, all hooks are installed."""
        monkeypatch.setattr(
            "aigate.hook_installer.shutil.which",
            lambda name: f"/usr/bin/{name}",
        )
        msgs = install_hooks_auto(tmp_path)
        added = [m for m in msgs if "Added" in m]
        assert len(added) == 8  # All 8 tools

    def test_idempotent(self, tmp_path, monkeypatch):
        """Running auto twice should skip everything on second run."""
        monkeypatch.setattr(
            "aigate.hook_installer.shutil.which",
            lambda name: f"/usr/bin/{name}",
        )
        install_hooks_auto(tmp_path)
        msgs = install_hooks_auto(tmp_path)
        skipped = [m for m in msgs if "skip" in m.lower()]
        assert len(skipped) == 8


# ---------------------------------------------------------------------------
# CLI integration: --auto flag
# ---------------------------------------------------------------------------


class TestInstallHooksAutoCLI:
    def test_auto_flag_help(self):
        from click.testing import CliRunner

        from aigate.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["install-hooks", "--help"])
        assert result.exit_code == 0
        assert "--auto" in result.output

    def test_auto_flag_installs_detected(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from aigate.cli import main

        monkeypatch.setattr(
            "aigate.hook_installer.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "claude" else None,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["install-hooks", "--auto", "--project-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".claude" / "settings.json").exists()
        # File-based tools always included
        assert (tmp_path / ".clinerules").exists()
        assert (tmp_path / ".opencode" / "plugins" / "aigate-scanner.mjs").exists()

    def test_no_tool_no_auto_errors(self):
        """Omitting both --tool and --auto should fail."""
        from click.testing import CliRunner

        from aigate.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["install-hooks"])
        assert result.exit_code != 0

    def test_auto_with_tool_uses_auto(self, tmp_path, monkeypatch):
        """When both --auto and --tool are given, --auto takes precedence."""
        from click.testing import CliRunner

        from aigate.cli import main

        monkeypatch.setattr(
            "aigate.hook_installer.shutil.which",
            lambda _name: None,
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["install-hooks", "--auto", "--tool", "claude", "--project-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        # --auto takes precedence; claude binary not found, so no claude hook
        assert not (tmp_path / ".claude" / "settings.json").exists()
        # But file-based tools still installed
        assert (tmp_path / ".clinerules").exists()
