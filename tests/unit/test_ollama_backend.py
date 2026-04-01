"""Tests for Ollama local model backend."""

from __future__ import annotations

import httpx
import pytest

from aigate.backends.ollama import OllamaBackend


def test_ollama_backend_name():
    backend = OllamaBackend()
    assert backend.name == "ollama"


def test_ollama_default_url():
    backend = OllamaBackend()
    assert backend.base_url == "http://localhost:11434"


async def test_ollama_analyze_sends_chat(monkeypatch):
    """Verify POST to /api/chat with messages array."""
    captured_url: str = ""
    captured_payload: dict = {}

    chat_response = httpx.Response(
        200,
        json={"message": {"content": "analysis result"}},
        request=httpx.Request("POST", "http://localhost:11434/api/chat"),
    )

    async def fake_post(self, url, **kwargs):
        nonlocal captured_url, captured_payload
        captured_url = url
        captured_payload = kwargs.get("json", {})
        return chat_response

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OllamaBackend(model_id="llama3.1:8b")
    result = await backend.analyze("test prompt")

    assert captured_url == "http://localhost:11434/api/chat"
    assert captured_payload["model"] == "llama3.1:8b"
    assert captured_payload["messages"] == [{"role": "user", "content": "test prompt"}]
    assert captured_payload["stream"] is False
    assert result == "analysis result"


async def test_ollama_analyze_with_roles(monkeypatch):
    """Verify system + user messages sent correctly."""
    captured_payload: dict = {}

    chat_response = httpx.Response(
        200,
        json={"message": {"content": "role-based result"}},
        request=httpx.Request("POST", "http://localhost:11434/api/chat"),
    )

    async def fake_post(self, url, **kwargs):
        nonlocal captured_payload
        captured_payload = kwargs.get("json", {})
        return chat_response

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OllamaBackend()
    result = await backend.analyze_with_roles("system msg", "user msg")

    assert captured_payload["messages"] == [
        {"role": "system", "content": "system msg"},
        {"role": "user", "content": "user msg"},
    ]
    assert result == "role-based result"


async def test_ollama_connection_error(monkeypatch):
    """Mock ConnectError, verify RuntimeError."""

    async def fake_post(self, url, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OllamaBackend()
    with pytest.raises(RuntimeError, match="Cannot connect to Ollama"):
        await backend.analyze("test prompt")


async def test_ollama_timeout(monkeypatch):
    """Mock TimeoutException, verify RuntimeError."""

    async def fake_post(self, url, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OllamaBackend()
    with pytest.raises(RuntimeError, match="timed out"):
        await backend.analyze("test prompt")
