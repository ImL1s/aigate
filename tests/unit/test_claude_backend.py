"""Tests for Claude Code headless backend."""

from __future__ import annotations

import asyncio

import pytest

from aigate.backends.claude import ClaudeBackend


def test_claude_backend_name():
    backend = ClaudeBackend()
    assert backend.name == "claude"


async def test_claude_binary_not_found(monkeypatch):
    monkeypatch.setattr("aigate.backends.claude.shutil.which", lambda _: None)
    backend = ClaudeBackend()
    with pytest.raises(RuntimeError, match="Claude Code CLI not found"):
        await backend.analyze("test prompt")


async def test_claude_analyze_subprocess(monkeypatch):
    """Verify subprocess command structure — uses `-p -` for stdin piping."""
    captured_cmd: list[str] = []
    captured_input: bytes | None = None

    async def fake_exec(*cmd, **kwargs):
        captured_cmd.extend(cmd)

        class FakeProc:
            returncode = 0

            async def communicate(self, input=None):
                nonlocal captured_input
                captured_input = input
                return (b'{"verdict":"safe","confidence":0.9}', b"")

        return FakeProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("aigate.backends.claude.shutil.which", lambda _: "/usr/bin/claude")

    backend = ClaudeBackend(model_id="claude-sonnet-4-6")
    await backend.analyze("test prompt")

    assert "/usr/bin/claude" in captured_cmd
    assert "-p" in captured_cmd
    assert "-" in captured_cmd
    assert "--model" in captured_cmd
    assert "claude-sonnet-4-6" in captured_cmd
    assert captured_input == b"test prompt"


async def test_claude_timeout(monkeypatch):
    """Verify timeout handling — proc.kill() and proc.wait() called."""
    killed = False
    waited = False

    async def fake_exec(*cmd, **kwargs):
        class FakeProc:
            returncode = 0

            async def communicate(self, input=None):
                await asyncio.sleep(999)
                return b"", b""

            def kill(self):
                nonlocal killed
                killed = True

            async def wait(self):
                nonlocal waited
                waited = True

        return FakeProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("aigate.backends.claude.shutil.which", lambda _: "/usr/bin/claude")

    backend = ClaudeBackend(timeout=0)
    with pytest.raises(RuntimeError, match="timed out"):
        await backend.analyze("test prompt")

    assert killed
    assert waited
