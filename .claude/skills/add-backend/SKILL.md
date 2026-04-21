---
name: add-backend
description: Scaffold a new AI backend that implements AIBackend.analyze() — add file under src/aigate/backends/, register in BACKEND_MAP, wire unit tests. Use when adding support for a new AI model / provider.
---

Use this when adding a new AI model provider (e.g. a hosted API, a local inference server, a new CLI tool).

Ask the user first: **provider name** (e.g. `anthropic_bedrock`, `groq`), **integration style** (HTTP API / CLI binary / local socket), and whether the provider speaks OpenAI-compatible chat — in that last case, extend `OpenAICompatBackend` instead of writing a fresh class.

## Files to touch

1. **Create** `src/aigate/backends/<name>.py` with the new `<Name>Backend` subclass.
2. **Register** in `src/aigate/backends/__init__.py` (import + `__all__`).
3. **Register** in `src/aigate/consensus.py` — add the key to `BACKEND_MAP`.
4. **Add tests** in `tests/unit/test_<name>_backend.py` (mock the HTTP client or CLI subprocess — never hit the real provider).

## Scaffold — HTTP API style (example: `ollama.py` pattern)

```python
"""<Provider> backend."""

from __future__ import annotations

import httpx

from ..models import AnalysisLevel
from .base import AIBackend


class <Name>Backend(AIBackend):
    name = "<name>"

    def __init__(
        self,
        model_id: str = "<default-model>",
        base_url: str = "<default-url>",
        timeout: int = 180,
    ):
        self.model_id = model_id
        self.base_url = base_url
        self.timeout = timeout

    async def analyze(self, prompt: str, level: AnalysisLevel = AnalysisLevel.L1_QUICK) -> str:
        return await self._chat(messages=[{"role": "user", "content": prompt}])

    async def analyze_with_roles(
        self,
        system: str,
        user: str,
        level: AnalysisLevel = AnalysisLevel.L1_QUICK,
    ) -> str:
        return await self._chat(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )

    async def _chat(self, messages: list[dict[str, str]]) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(f"{self.base_url}/...", json={...})
                resp.raise_for_status()
                return resp.json()["..."]
            except httpx.ConnectError:
                raise RuntimeError(f"Cannot connect to <Provider> at {self.base_url}")
            except httpx.TimeoutException:
                raise RuntimeError(f"<Provider> analysis timed out after {self.timeout}s")
```

## Scaffold — CLI style (example: `claude.py` / `gemini.py` pattern)

Use `asyncio.create_subprocess_exec` + stdin for the prompt, stdout for the response. Override `analyze`; let the base class concatenate system+user for you. Fail gracefully when the binary is missing (`FileNotFoundError` → `RuntimeError` with install hint).

## Registration

**`src/aigate/backends/__init__.py`** — add to imports and `__all__`:
```python
from .<name> import <Name>Backend
# ...
__all__ = [..., "<Name>Backend"]
```

**`src/aigate/consensus.py`** — add to `BACKEND_MAP`:
```python
BACKEND_MAP = {
    ...,
    "<name>": <Name>Backend,
}
```

The key string is what users put in `.aigate.yml` under `models[].backend`.

## Security invariants — must hold

- **Never execute package code** — backends only shuttle text prompts to the model; respect the sandbox boundary enforced by `resolver.py`.
- **Treat source code as untrusted** — base prompts already warn the LLM about prompt injection inside `<UNTRUSTED_PACKAGE_CODE>` tags; don't weaken that.
- **Fail closed** — if the model/API is unreachable, raise `RuntimeError`; the response parser in `base.py` will turn empty/error into `Verdict.ERROR`, which is the safe outcome.

## Tests

Write tests under `tests/unit/test_<name>_backend.py`. Patterns used in the existing suite:
- Mock `httpx.AsyncClient` with `respx` or a fake.
- Mock subprocess calls with `asyncio.create_subprocess_exec` monkeypatches.
- Test: (1) happy path returns raw string; (2) connect error raises `RuntimeError`; (3) `analyze_with_roles` passes proper role separation (API backends only).

Run after: `.venv/bin/python -m pytest tests/unit/test_<name>_backend.py -v`.

## Done checklist

- [ ] New file compiles (`.venv/bin/ruff check src/aigate/backends/<name>.py`)
- [ ] Registered in both `backends/__init__.py` and `consensus.py` BACKEND_MAP
- [ ] Unit tests pass with mocked transport
- [ ] `/verify` passes
