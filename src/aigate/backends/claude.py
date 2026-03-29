"""Claude Code headless backend."""

from __future__ import annotations

import asyncio
import shutil

from ..models import AnalysisLevel
from .base import AIBackend


class ClaudeBackend(AIBackend):
    name = "claude"

    def __init__(self, model_id: str = "claude-sonnet-4-6", timeout: int = 120):
        self.model_id = model_id
        self.timeout = timeout
        self._binary = shutil.which("claude")

    async def analyze(self, prompt: str, level: AnalysisLevel = AnalysisLevel.L1_QUICK) -> str:
        if not self._binary:
            raise RuntimeError(
                "Claude Code CLI not found. Install: npm i -g @anthropic-ai/claude-code"
            )

        cmd = [
            self._binary,
            "-p",
            "-",
            "--model",
            self.model_id,
            "--output-format",
            "text",
            "--max-turns",
            "1",
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
            raise RuntimeError(f"Claude analysis timed out after {self.timeout}s")

        if proc.returncode != 0:
            raise RuntimeError(f"Claude CLI failed: {stderr.decode()[:500]}")

        return stdout.decode()
