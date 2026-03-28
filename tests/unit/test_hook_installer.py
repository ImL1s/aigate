"""Tests for the install-hooks CLI command and hook_installer module."""

from __future__ import annotations

import json

from aigate.hook_installer import (
    install_aider,
    install_claude,
    install_codex,
    install_cursor,
    install_gemini,
    install_hooks,
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
        # Should have 6 success messages
        added = [m for m in msgs if "Added" in m]
        assert len(added) == 6

    def test_unknown_tool(self, tmp_path):
        msgs = install_hooks(["nonexistent"], tmp_path)
        assert any("Unknown" in m for m in msgs)

    def test_idempotent(self, tmp_path):
        install_hooks(["all"], tmp_path)
        msgs = install_hooks(["all"], tmp_path)
        skipped = [m for m in msgs if "skip" in m]
        assert len(skipped) == 6


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
