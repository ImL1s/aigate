"""AI backend adapters for aigate."""

from .base import AIBackend
from .claude import ClaudeBackend
from .codex import CodexBackend
from .gemini import GeminiBackend
from .ollama import OllamaBackend
from .openai_compat import OpenAICompatBackend

__all__ = [
    "AIBackend",
    "ClaudeBackend",
    "CodexBackend",
    "GeminiBackend",
    "OllamaBackend",
    "OpenAICompatBackend",
]
