"""Tests for Gemini CLI headless backend."""

from __future__ import annotations

import asyncio

import pytest

from aigate.backends.gemini import GeminiBackend


def test_gemini_backend_name():
    backend = GeminiBackend()
    assert backend.name == "gemini"


async def test_gemini_binary_not_found(monkeypatch):
    monkeypatch.setattr("aigate.backends.gemini.shutil.which", lambda _: None)
    backend = GeminiBackend()
    with pytest.raises(RuntimeError, match="Gemini CLI not found"):
        await backend.analyze("test prompt")


async def test_gemini_analyze_subprocess(monkeypatch):
    """Verify subprocess — Gemini uses stdin pipe (no `-p` flag)."""
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
    monkeypatch.setattr("aigate.backends.gemini.shutil.which", lambda _: "/usr/bin/gemini")

    backend = GeminiBackend(model_id="gemini-2.5-pro")
    await backend.analyze("test prompt")

    assert "/usr/bin/gemini" in captured_cmd
    # Gemini backend does NOT use -p flag (unlike Claude)
    assert "-p" not in captured_cmd
    assert captured_input == b"test prompt"


async def test_gemini_timeout(monkeypatch):
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
    monkeypatch.setattr("aigate.backends.gemini.shutil.which", lambda _: "/usr/bin/gemini")

    backend = GeminiBackend(timeout=0)
    with pytest.raises(RuntimeError, match="timed out"):
        await backend.analyze("test prompt")

    assert killed
    assert waited
