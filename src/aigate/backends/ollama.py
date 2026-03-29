"""Ollama local model backend."""

from __future__ import annotations

import httpx

from ..models import AnalysisLevel
from .base import AIBackend


class OllamaBackend(AIBackend):
    name = "ollama"

    def __init__(
        self,
        model_id: str = "llama3.1:8b",
        base_url: str = "http://localhost:11434",
        timeout: int = 180,
    ):
        self.model_id = model_id
        self.base_url = base_url
        self.timeout = timeout

    async def analyze(self, prompt: str, level: AnalysisLevel = AnalysisLevel.L1_QUICK) -> str:
        return await self._ollama_chat(
            messages=[{"role": "user", "content": prompt}],
        )

    async def analyze_with_roles(
        self,
        system: str,
        user: str,
        level: AnalysisLevel = AnalysisLevel.L1_QUICK,
    ) -> str:
        """Send system + user messages via Ollama chat API."""
        return await self._ollama_chat(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )

    async def _ollama_chat(
        self,
        messages: list[dict[str, str]],
    ) -> str:
        """Send messages to the Ollama /api/chat endpoint."""
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model_id,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 2048,
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data.get("message", {}).get("content", "")
            except httpx.ConnectError:
                raise RuntimeError(
                    f"Cannot connect to Ollama at {self.base_url}. "
                    "Is Ollama running? Start with: ollama serve"
                )
            except httpx.TimeoutException:
                raise RuntimeError(f"Ollama analysis timed out after {self.timeout}s")
