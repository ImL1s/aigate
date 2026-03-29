"""Tests for OpenAI-compatible generic backend."""

from __future__ import annotations

import json

import httpx
import pytest

from aigate.backends.openai_compat import OpenAICompatBackend

_FAKE_REQUEST = httpx.Request("POST", "http://fake")
_SAFE_JSON = '{"verdict":"safe","confidence":0.9,"reasoning":"ok","risk_signals":[]}'


def _ok_response(body: dict) -> httpx.Response:
    """Create an httpx.Response with a request attached so raise_for_status() works."""
    return httpx.Response(200, json=body, request=_FAKE_REQUEST)


def test_backend_name():
    backend = OpenAICompatBackend(base_url="http://localhost:11434/v1")
    assert backend.name == "openai_compat"


def test_default_model():
    backend = OpenAICompatBackend(base_url="http://localhost:11434/v1")
    assert backend.model_id == "gpt-4o"


def test_custom_model():
    backend = OpenAICompatBackend(
        base_url="http://localhost:11434/v1",
        model_id="deepseek-coder-v2",
    )
    assert backend.model_id == "deepseek-coder-v2"


def test_api_key_from_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "sk-test-123")
    backend = OpenAICompatBackend(
        base_url="https://openrouter.ai/api/v1",
        api_key_env="MY_KEY",
    )
    assert backend._api_key == "sk-test-123"


def test_api_key_env_missing():
    backend = OpenAICompatBackend(
        base_url="http://localhost:11434/v1",
        api_key_env="NONEXISTENT_KEY_XYZ",
    )
    assert backend._api_key is None


def test_trailing_slash_stripped():
    backend = OpenAICompatBackend(base_url="http://localhost:11434/v1/")
    assert backend.base_url == "http://localhost:11434/v1"


async def test_analyze_sends_correct_request(monkeypatch):
    """Verify the HTTP request is structured correctly."""
    captured_request: dict = {}

    async def fake_post(self, url, **kwargs):
        captured_request["url"] = str(url)
        captured_request["json"] = kwargs.get("json")
        captured_request["headers"] = kwargs.get("headers")
        return _ok_response(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "verdict": "safe",
                                    "confidence": 0.9,
                                    "reasoning": "ok",
                                    "risk_signals": [],
                                }
                            )
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(
        base_url="http://localhost:11434/v1",
        model_id="deepseek-coder-v2",
    )
    await backend.analyze("analyze this code")

    assert captured_request["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured_request["json"]["model"] == "deepseek-coder-v2"
    assert captured_request["json"]["messages"][0]["role"] == "user"
    assert "analyze this code" in captured_request["json"]["messages"][0]["content"]
    assert captured_request["json"]["temperature"] == 0.1
    assert captured_request["json"]["max_tokens"] == 2048


async def test_analyze_returns_content(monkeypatch):
    """Verify the response content is extracted correctly."""

    async def fake_post(self, url, **kwargs):
        return _ok_response(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "verdict": "safe",
                                    "confidence": 0.95,
                                    "reasoning": "clean",
                                    "risk_signals": [],
                                }
                            )
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(base_url="http://localhost:11434/v1")
    result = await backend.analyze("test prompt")

    parsed = json.loads(result)
    assert parsed["verdict"] == "safe"
    assert parsed["confidence"] == 0.95


async def test_analyze_with_api_key(monkeypatch):
    """Verify Authorization header is sent when api_key is set."""
    captured_headers: dict = {}

    async def fake_post(self, url, **kwargs):
        captured_headers.update(kwargs.get("headers", {}))
        return _ok_response({"choices": [{"message": {"content": _SAFE_JSON}}]})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    monkeypatch.setenv("TEST_API_KEY", "sk-secret")

    backend = OpenAICompatBackend(
        base_url="https://openrouter.ai/api/v1",
        model_id="qwen/qwen-2.5-coder",
        api_key_env="TEST_API_KEY",
    )
    await backend.analyze("test")

    assert captured_headers.get("Authorization") == "Bearer sk-secret"


async def test_analyze_no_auth_header_without_key(monkeypatch):
    """Verify no Authorization header when no api_key is configured."""
    captured_headers: dict = {}

    async def fake_post(self, url, **kwargs):
        captured_headers.update(kwargs.get("headers", {}))
        return _ok_response({"choices": [{"message": {"content": _SAFE_JSON}}]})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(base_url="http://localhost:11434/v1")
    await backend.analyze("test")

    assert "Authorization" not in captured_headers


async def test_analyze_connection_error(monkeypatch):
    async def fake_post(self, url, **kwargs):
        raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(base_url="http://localhost:9999/v1")
    with pytest.raises(RuntimeError, match="Cannot connect"):
        await backend.analyze("test")


async def test_analyze_timeout(monkeypatch):
    async def fake_post(self, url, **kwargs):
        raise httpx.TimeoutException("Timeout")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(base_url="http://localhost:11434/v1", timeout=5)
    with pytest.raises(RuntimeError, match="timed out"):
        await backend.analyze("test")


async def test_analyze_bad_response_format(monkeypatch):
    """Verify handling of unexpected response structure."""

    async def fake_post(self, url, **kwargs):
        return _ok_response({"unexpected": "format"})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(base_url="http://localhost:11434/v1")
    with pytest.raises(RuntimeError, match="Unexpected response format"):
        await backend.analyze("test")


async def test_analyze_empty_choices(monkeypatch):
    """Verify handling of empty choices array."""

    async def fake_post(self, url, **kwargs):
        return _ok_response({"choices": []})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(base_url="http://localhost:11434/v1")
    with pytest.raises(RuntimeError, match="Unexpected response format"):
        await backend.analyze("test")


async def test_analyze_with_roles_sends_system_and_user(monkeypatch):
    """Verify analyze_with_roles sends proper system + user message roles."""
    captured_request: dict = {}

    async def fake_post(self, url, **kwargs):
        captured_request["json"] = kwargs.get("json")
        return _ok_response({"choices": [{"message": {"content": _SAFE_JSON}}]})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(
        base_url="http://localhost:11434/v1",
        model_id="test-model",
    )
    await backend.analyze_with_roles(
        system="You are a security analyst.",
        user="Analyze this package.",
    )

    messages = captured_request["json"]["messages"]
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[0]["content"] == "You are a security analyst."
    assert messages[1]["role"] == "user"
    assert messages[1]["content"] == "Analyze this package."


async def test_analyze_package_uses_roles(monkeypatch):
    """Verify analyze_package routes through analyze_with_roles with separated messages."""
    captured_request: dict = {}

    async def fake_post(self, url, **kwargs):
        captured_request["json"] = kwargs.get("json")
        return _ok_response({"choices": [{"message": {"content": _SAFE_JSON}}]})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(
        base_url="http://localhost:11434/v1",
        model_id="test-model",
    )
    await backend.analyze_package(
        name="test-pkg",
        version="1.0.0",
        ecosystem="pypi",
        author="tester",
        description="a test",
        has_install_scripts=False,
        risk_signals=[],
        source_code="print('hello')",
    )

    messages = captured_request["json"]["messages"]
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    # System message has instructions, not package data
    assert "security analyst" in messages[0]["content"].lower()
    assert "Respond with ONLY" in messages[0]["content"]
    # User message has package data, not instructions
    assert "test-pkg" in messages[1]["content"]
    assert "print('hello')" in messages[1]["content"]
