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

        # Codex non-interactive mode: `codex exec -` reads prompt from stdin
        cmd = [
            self._binary,
            "exec",
            "-",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
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
            raise RuntimeError(f"Codex analysis timed out after {self.timeout}s")

        if proc.returncode != 0:
            raise RuntimeError(f"Codex CLI failed: {stderr.decode()[:500]}")

        return stdout.decode()
