"""Gemini CLI headless backend."""

from __future__ import annotations

import asyncio
import shutil

from ..models import AnalysisLevel
from .base import AIBackend


class GeminiBackend(AIBackend):
    name = "gemini"

    def __init__(self, model_id: str = "gemini-2.5-pro", timeout: int = 120):
        self.model_id = model_id
        self.timeout = timeout
        self._binary = shutil.which("gemini")

    async def analyze(self, prompt: str, level: AnalysisLevel = AnalysisLevel.L1_QUICK) -> str:
        if not self._binary:
            raise RuntimeError(
                "Gemini CLI not found. Install: npm i -g @google/gemini-cli "
                "or brew install gemini-cli"
            )

        proc = await asyncio.create_subprocess_exec(
            self._binary,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=prompt.encode()), timeout=self.timeout
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(f"Gemini analysis timed out after {self.timeout}s")

        if proc.returncode != 0:
            raise RuntimeError(f"Gemini CLI failed: {stderr.decode()[:500]}")

        return stdout.decode()
