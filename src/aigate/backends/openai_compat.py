"""Generic OpenAI-compatible API backend.

Supports any API that implements POST /v1/chat/completions:
- Ollama (http://localhost:11434/v1)
- OpenRouter (https://openrouter.ai/api/v1)
- vLLM, llama.cpp, text-generation-webui
- Any self-hosted OpenAI-compatible proxy
"""

from __future__ import annotations

import os

import httpx

from ..models import AnalysisLevel
from .base import AIBackend


class OpenAICompatBackend(AIBackend):
    name = "openai_compat"

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        model_id: str = "gpt-4o",
        api_key_env: str | None = None,
        timeout: int = 180,
    ):
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.timeout = timeout
        self._api_key = os.environ.get(api_key_env) if api_key_env else None

    async def analyze(self, prompt: str, level: AnalysisLevel = AnalysisLevel.L1_QUICK) -> str:
        url = f"{self.base_url}/chat/completions"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": self.model_id,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 2048,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            except httpx.ConnectError:
                raise RuntimeError(
                    f"Cannot connect to {self.base_url}. "
                    "Verify the API server is running and the URL is correct."
                )
            except httpx.TimeoutException:
                raise RuntimeError(f"OpenAI-compatible API timed out after {self.timeout}s")
            except (KeyError, IndexError) as e:
                raise RuntimeError(f"Unexpected response format from {self.base_url}: {e}")
