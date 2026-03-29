"""Tests for Codex CLI backend."""

from __future__ import annotations

import pytest

from aigate.backends.codex import CodexBackend


def test_codex_backend_name():
    backend = CodexBackend()
    assert backend.name == "codex"


def test_codex_backend_default_model():
    backend = CodexBackend()
    assert backend.model_id == "o3"


def test_codex_backend_custom_model():
    backend = CodexBackend(model_id="codex-mini-latest")
    assert backend.model_id == "codex-mini-latest"


async def test_codex_binary_not_found(monkeypatch):
    monkeypatch.setattr("aigate.backends.codex.shutil.which", lambda _: None)
    backend = CodexBackend()
    with pytest.raises(RuntimeError, match="Codex CLI not found"):
        await backend.analyze("test prompt")


async def test_codex_analyze_calls_subprocess(monkeypatch):
    """Verify the subprocess command is constructed correctly."""
    captured_cmd = []
    captured_input = None

    async def fake_exec(*cmd, **kwargs):
        captured_cmd.extend(cmd)

        class FakeProc:
            returncode = 0

            async def communicate(self, input=None):
                nonlocal captured_input
                captured_input = input
                return (
                    b'{"verdict": "safe", "confidence": 0.9, "risk_signals": []}',
                    b"",
                )

        return FakeProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/codex")

    backend = CodexBackend(model_id="o3")
    await backend.analyze("test prompt")
    assert "/usr/bin/codex" in captured_cmd
    assert "exec" in captured_cmd
    # Prompt should NOT be in cmd args (avoids ARG_MAX); piped via stdin instead
    assert "test prompt" not in captured_cmd
    assert captured_input == b"test prompt"


async def test_codex_analyze_timeout(monkeypatch):
    """Verify timeout handling."""

    async def fake_exec(*cmd, **kwargs):
        class FakeProc:
            returncode = 0

            async def communicate(self, input=None):
                import asyncio

                await asyncio.sleep(999)
                return b"", b""

            def kill(self):
                pass

        return FakeProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/codex")

    backend = CodexBackend(model_id="o3", timeout=0)
    with pytest.raises(RuntimeError, match="timed out"):
        await backend.analyze("test prompt")


async def test_codex_analyze_nonzero_exit(monkeypatch):
    """Verify non-zero exit code raises RuntimeError."""

    async def fake_exec(*cmd, **kwargs):
        class FakeProc:
            returncode = 1

            async def communicate(self, input=None):
                return b"", b"some error"

        return FakeProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/codex")

    backend = CodexBackend()
    with pytest.raises(RuntimeError, match="Codex CLI failed"):
        await backend.analyze("test prompt")
