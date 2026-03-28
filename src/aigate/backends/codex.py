"""OpenAI Codex CLI headless backend."""

from __future__ import annotations

import asyncio
import shutil

from ..models import AnalysisLevel
from .base import AIBackend


class CodexBackend(AIBackend):
    name = "codex"

    def __init__(self, model_id: str = "o3", timeout: int = 120):
        self.model_id = model_id
        self.timeout = timeout
        self._binary = shutil.which("codex")

    async def analyze(self, prompt: str, level: AnalysisLevel = AnalysisLevel.L1_QUICK) -> str:
        if not self._binary:
            raise RuntimeError("Codex CLI not found. Install: npm i -g @openai/codex")

        cmd = [
            self._binary,
            "-q",
            prompt,
            "--model",
            self.model_id,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except TimeoutError:
            proc.kill()
            raise RuntimeError(f"Codex analysis timed out after {self.timeout}s")

        if proc.returncode != 0:
            raise RuntimeError(f"Codex CLI failed: {stderr.decode()[:500]}")

        return stdout.decode()
