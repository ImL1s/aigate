# Universal Backend & Hook Integration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make aigate work for any user regardless of which AI tools they have installed — auto-detect backends, support any OpenAI-compatible API, and integrate with all major AI coding tools.

**Architecture:** New backends follow existing patterns (subprocess for CLIs, httpx for APIs). `openai_compat` backend uses the standard `/v1/chat/completions` endpoint, covering Ollama (native OpenAI mode), OpenRouter, vLLM, llama.cpp, and any self-hosted API — zero third-party dependencies. Hook installers extend the existing `hook_installer.py` pattern. `aigate init` gains auto-detection. `aigate doctor` provides diagnostics.

**Tech Stack:** Python 3.11+, httpx (already a dep), asyncio subprocess, shutil.which for detection.

---

## Task 1: Codex CLI Backend

**Files:**
- Create: `src/aigate/backends/codex.py`
- Modify: `src/aigate/backends/__init__.py`
- Modify: `src/aigate/consensus.py:25-29` (add to BACKEND_MAP)
- Modify: `src/aigate/config_validator.py` (add "codex" to VALID_BACKENDS)
- Test: `tests/unit/test_codex_backend.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_codex_backend.py
"""Tests for Codex CLI backend."""

from __future__ import annotations

import pytest

from aigate.backends.codex import CodexBackend
from aigate.models import AnalysisLevel


def test_codex_backend_name():
    backend = CodexBackend()
    assert backend.name == "codex"


def test_codex_backend_default_model():
    backend = CodexBackend()
    assert backend.model_id == "o3"


def test_codex_backend_custom_model():
    backend = CodexBackend(model_id="codex-mini-latest")
    assert backend.model_id == "codex-mini-latest"


def test_codex_binary_not_found(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    backend = CodexBackend()
    with pytest.raises(RuntimeError, match="Codex CLI not found"):
        import asyncio
        asyncio.run(backend.analyze("test prompt"))


async def test_codex_analyze_calls_subprocess(monkeypatch):
    """Verify the subprocess command is constructed correctly."""
    captured_cmd = []

    async def fake_exec(*cmd, **kwargs):
        captured_cmd.extend(cmd)

        class FakeProc:
            returncode = 0
            async def communicate(self):
                return (
                    b'{"verdict": "safe", "confidence": 0.9, "reasoning": "ok", "risk_signals": []}',
                    b"",
                )

        return FakeProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/codex")

    backend = CodexBackend(model_id="o3")
    result = await backend.analyze("test prompt")
    assert "/usr/bin/codex" in captured_cmd
    assert "-q" in captured_cmd or "--quiet" in captured_cmd
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_codex_backend.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write minimal implementation**

```python
# src/aigate/backends/codex.py
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
            raise RuntimeError(
                "Codex CLI not found. Install: npm i -g @openai/codex"
            )

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
```

**Step 4: Wire into consensus.py and __init__.py**

In `consensus.py`, add to `BACKEND_MAP`:
```python
from .backends.codex import CodexBackend
BACKEND_MAP["codex"] = CodexBackend
```

In `backends/__init__.py`, add:
```python
from .codex import CodexBackend
```

In `config_validator.py`, update:
```python
VALID_BACKENDS = {"claude", "gemini", "ollama", "codex"}
```

**Step 5: Run tests & commit**

Run: `.venv/bin/python -m pytest tests/ -v`

```bash
git add src/aigate/backends/codex.py tests/unit/test_codex_backend.py src/aigate/backends/__init__.py src/aigate/consensus.py src/aigate/config_validator.py
git commit -m "feat: add Codex CLI backend"
```

---

## Task 2: OpenAI-Compatible Generic Backend

This is the key task. One backend to cover Ollama (OpenAI mode), OpenRouter, vLLM, llama.cpp server, and any API that speaks `/v1/chat/completions`.

**Files:**
- Create: `src/aigate/backends/openai_compat.py`
- Modify: `src/aigate/backends/__init__.py`
- Modify: `src/aigate/consensus.py` (add to BACKEND_MAP)
- Modify: `src/aigate/config_validator.py` (add to VALID_BACKENDS)
- Test: `tests/unit/test_openai_compat_backend.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_openai_compat_backend.py
"""Tests for OpenAI-compatible generic backend."""

from __future__ import annotations

import json

import httpx
import pytest

from aigate.backends.openai_compat import OpenAICompatBackend
from aigate.models import AnalysisLevel


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


async def test_analyze_sends_correct_request(monkeypatch):
    """Verify the HTTP request is structured correctly."""
    captured_request = {}

    async def fake_post(self, url, **kwargs):
        captured_request["url"] = str(url)
        captured_request["json"] = kwargs.get("json")
        captured_request["headers"] = kwargs.get("headers")
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": '{"verdict":"safe","confidence":0.9,"reasoning":"ok","risk_signals":[]}'
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    backend = OpenAICompatBackend(
        base_url="http://localhost:11434/v1",
        model_id="deepseek-coder-v2",
    )
    result = await backend.analyze("analyze this code")

    assert captured_request["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured_request["json"]["model"] == "deepseek-coder-v2"
    assert captured_request["json"]["messages"][0]["role"] == "user"
    assert "analyze this code" in captured_request["json"]["messages"][0]["content"]


async def test_analyze_with_api_key(monkeypatch):
    """Verify Authorization header is sent when api_key is set."""
    captured_headers = {}

    async def fake_post(self, url, **kwargs):
        captured_headers.update(kwargs.get("headers", {}))
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"verdict":"safe","confidence":0.9,"reasoning":"ok","risk_signals":[]}'}}]},
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    monkeypatch.setenv("TEST_API_KEY", "sk-secret")

    backend = OpenAICompatBackend(
        base_url="https://openrouter.ai/api/v1",
        model_id="qwen/qwen-2.5-coder",
        api_key_env="TEST_API_KEY",
    )
    await backend.analyze("test")

    assert captured_headers.get("Authorization") == "Bearer sk-secret"


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
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_openai_compat_backend.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write implementation**

```python
# src/aigate/backends/openai_compat.py
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
                raise RuntimeError(
                    f"OpenAI-compatible API timed out after {self.timeout}s"
                )
            except (KeyError, IndexError) as e:
                raise RuntimeError(
                    f"Unexpected response format from {self.base_url}: {e}"
                )
```

**Step 4: Wire into consensus.py and config_validator.py**

In `consensus.py`:
```python
from .backends.openai_compat import OpenAICompatBackend
BACKEND_MAP["openai_compat"] = OpenAICompatBackend
```

In `backends/__init__.py`:
```python
from .openai_compat import OpenAICompatBackend
```

In `config_validator.py`:
```python
VALID_BACKENDS = {"claude", "gemini", "ollama", "codex", "openai_compat"}
```

**Step 5: Run tests & commit**

Run: `.venv/bin/python -m pytest tests/ -v`

```bash
git add src/aigate/backends/openai_compat.py tests/unit/test_openai_compat_backend.py src/aigate/backends/__init__.py src/aigate/consensus.py src/aigate/config_validator.py
git commit -m "feat: add OpenAI-compatible generic backend for any API"
```

---

## Task 3: Auto-Detect Installed Tools

**Files:**
- Create: `src/aigate/detect.py`
- Modify: `src/aigate/cli.py` (update `init` command)
- Test: `tests/unit/test_detect.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_detect.py
"""Tests for AI tool auto-detection."""

from __future__ import annotations

from aigate.detect import detect_backends, detect_hooks, DetectedBackend


def test_detect_claude_when_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}" if name == "claude" else None)
    backends = detect_backends()
    names = [b.name for b in backends]
    assert "claude" in names


def test_detect_nothing_when_nothing_installed(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    # Also mock httpx to fail for Ollama check
    backends = detect_backends()
    assert len(backends) == 0


def test_detect_multiple_tools(monkeypatch):
    installed = {"claude", "gemini", "codex"}
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}" if name in installed else None)
    backends = detect_backends()
    names = {b.name for b in backends}
    assert names == {"claude", "gemini", "codex"}


def test_detected_backend_has_install_hint():
    backends = detect_backends()
    # Even when nothing is detected, the function should return
    # We test the structure of DetectedBackend
    from aigate.detect import KNOWN_BACKENDS
    for info in KNOWN_BACKENDS:
        assert info.install_hint  # Every backend must have install instructions


def test_detect_hooks_finds_installed_tools(monkeypatch):
    installed = {"claude", "codex"}
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}" if name in installed else None)
    hooks = detect_hooks()
    tool_names = {h.tool for h in hooks}
    assert "claude" in tool_names
    assert "codex" in tool_names


def test_generate_config_from_detected(monkeypatch):
    installed = {"claude", "gemini"}
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}" if name in installed else None)
    from aigate.detect import generate_config_yaml
    yaml_str = generate_config_yaml(detect_backends())
    assert "claude" in yaml_str
    assert "gemini" in yaml_str
    assert "codex" not in yaml_str
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_detect.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write implementation**

```python
# src/aigate/detect.py
"""Auto-detect installed AI tools and generate configuration."""

from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass
class DetectedBackend:
    name: str
    backend: str
    available: bool
    binary_path: str | None
    install_hint: str
    default_model_id: str
    default_weight: float


@dataclass
class DetectedHook:
    tool: str
    available: bool
    binary_path: str | None


KNOWN_BACKENDS = [
    DetectedBackend(
        name="claude",
        backend="claude",
        available=False,
        binary_path=None,
        install_hint="npm i -g @anthropic-ai/claude-code",
        default_model_id="claude-sonnet-4-6",
        default_weight=1.0,
    ),
    DetectedBackend(
        name="gemini",
        backend="gemini",
        available=False,
        binary_path=None,
        install_hint="npm i -g @anthropic-ai/gemini-cli  OR  brew install gemini-cli",
        default_model_id="gemini-2.5-pro",
        default_weight=1.0,
    ),
    DetectedBackend(
        name="codex",
        backend="codex",
        available=False,
        binary_path=None,
        install_hint="npm i -g @openai/codex",
        default_model_id="o3",
        default_weight=1.0,
    ),
    DetectedBackend(
        name="ollama",
        backend="ollama",
        available=False,
        binary_path=None,
        install_hint="https://ollama.com/download",
        default_model_id="llama3.1:8b",
        default_weight=0.8,
    ),
]

KNOWN_HOOK_TOOLS = ["claude", "gemini", "codex", "cursor", "windsurf", "aider"]


def detect_backends() -> list[DetectedBackend]:
    """Detect which AI backends are available on this system."""
    detected = []
    for template in KNOWN_BACKENDS:
        binary_name = template.backend
        # Ollama binary is "ollama", not "ollama" backend key
        path = shutil.which(binary_name)
        if path:
            detected.append(
                DetectedBackend(
                    name=template.name,
                    backend=template.backend,
                    available=True,
                    binary_path=path,
                    install_hint=template.install_hint,
                    default_model_id=template.default_model_id,
                    default_weight=template.default_weight,
                )
            )
    return detected


def detect_hooks() -> list[DetectedHook]:
    """Detect which AI coding tools are available for hook installation."""
    detected = []
    for tool in KNOWN_HOOK_TOOLS:
        path = shutil.which(tool)
        if path:
            detected.append(DetectedHook(tool=tool, available=True, binary_path=path))
    return detected


def generate_config_yaml(backends: list[DetectedBackend]) -> str:
    """Generate .aigate.yml content from detected backends."""
    lines = [
        "# Auto-generated by aigate init",
        "# Detected backends on this system",
        "",
        "models:",
    ]
    for b in backends:
        lines.extend([
            f"  - name: {b.name}",
            f"    backend: {b.backend}",
            f"    model_id: {b.default_model_id}",
            f"    weight: {b.default_weight}",
            f"    enabled: true",
            "",
        ])

    if not backends:
        lines.extend([
            "  # No AI backends detected!",
            "  # Install at least one:",
            "",
        ])
        for template in KNOWN_BACKENDS:
            lines.append(f"  #   {template.name}: {template.install_hint}")
        lines.append("")

    # Consensus strategy comment
    count = len(backends)
    if count == 0:
        lines.append("# Strategy: prefilter-only (no AI backends found)")
    elif count == 1:
        lines.append("# Strategy: single-model (1 backend detected)")
    elif count == 2:
        lines.append("# Strategy: dual-model consensus (2 backends detected)")
    else:
        lines.append(f"# Strategy: full multi-model consensus ({count} backends detected)")

    lines.extend([
        "",
        "thresholds:",
        "  malicious: 0.6",
        "  suspicious: 0.5",
        "  disagreement: 0.4",
        "",
        "ecosystems:",
        "  - pypi",
        "  - npm",
        "  - pub",
    ])

    return "\n".join(lines) + "\n"
```

**Step 4: Update `aigate init` in cli.py**

Modify the existing `init` command to use auto-detection:

```python
# In the init command, replace static config generation with:
from aigate.detect import detect_backends, detect_hooks, generate_config_yaml

backends = detect_backends()
console.print(f"\n[bold]Detecting AI backends...[/bold]")
for template in KNOWN_BACKENDS:
    found = any(b.name == template.name for b in backends)
    icon = "✓" if found else "✗"
    style = "green" if found else "dim"
    console.print(f"  [{style}]{icon} {template.name}[/{style}]")

yaml_content = generate_config_yaml(backends)
# Write to .aigate.yml
```

**Step 5: Run tests & commit**

Run: `.venv/bin/python -m pytest tests/ -v`

```bash
git add src/aigate/detect.py tests/unit/test_detect.py src/aigate/cli.py
git commit -m "feat: auto-detect installed AI tools in aigate init"
```

---

## Task 4: Dynamic Consensus Strategy

When only 1 model is available, skip consensus voting and just use that model's result directly. When 0 models are available, return prefilter-only result with a clear message.

**Files:**
- Modify: `src/aigate/consensus.py`
- Modify: `tests/unit/test_consensus.py`

**Step 1: Write the failing test**

```python
# Append to tests/unit/test_consensus.py

async def test_single_model_skips_consensus_voting(monkeypatch):
    """With only 1 model, its result is used directly without voting."""
    from aigate.consensus import run_consensus
    from aigate.config import Config, ModelConfig
    from aigate.models import PackageInfo, Verdict

    config = Config(
        models=[ModelConfig(name="solo", backend="claude", weight=1.0)]
    )
    # Mock create_backend to return a fake backend
    from aigate.backends.base import AIBackend
    from aigate.models import AnalysisLevel, ModelResult

    class FakeBackend(AIBackend):
        name = "solo"
        async def analyze(self, prompt, level=AnalysisLevel.L1_QUICK):
            return '{"verdict":"suspicious","confidence":0.7,"reasoning":"looks odd","risk_signals":["weird_import"]}'

    monkeypatch.setattr(
        "aigate.consensus.create_backend",
        lambda mc: FakeBackend(),
    )

    result = await run_consensus(
        package=PackageInfo(name="test", version="1.0", ecosystem="pypi"),
        risk_signals=[],
        source_code="import os",
        config=config,
    )
    assert result.final_verdict == Verdict.SUSPICIOUS
    assert result.summary.startswith("Single-model")


async def test_zero_models_returns_prefilter_only_message():
    from aigate.consensus import run_consensus
    from aigate.config import Config
    from aigate.models import PackageInfo, Verdict

    config = Config(models=[])

    result = await run_consensus(
        package=PackageInfo(name="test", version="1.0", ecosystem="pypi"),
        risk_signals=[],
        source_code="import os",
        config=config,
    )
    assert result.final_verdict == Verdict.ERROR
    assert "No AI models" in result.summary
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_consensus.py::test_single_model_skips_consensus_voting -v`
Expected: FAIL — no "Single-model" prefix in summary

**Step 3: Modify consensus.py**

In `_aggregate_votes()`, add single-model fast path before the voting logic:

```python
def _aggregate_votes(results, config, model_configs):
    valid = [r for r in results if r.verdict != Verdict.ERROR]
    if not valid:
        return ConsensusResult(...)

    # Single-model fast path: no voting needed
    if len(valid) == 1:
        r = valid[0]
        return ConsensusResult(
            final_verdict=r.verdict,
            confidence=r.confidence,
            model_results=results,
            has_disagreement=False,
            summary=f"Single-model analysis: {r.model_name}={r.verdict.value}({r.confidence:.0%})",
            risk_signals=r.risk_signals,
            recommendation=recommendations.get(r.verdict, ""),
        )

    # ... existing multi-model voting logic ...
```

**Step 4: Run tests & commit**

Run: `.venv/bin/python -m pytest tests/unit/test_consensus.py -v`

```bash
git add src/aigate/consensus.py tests/unit/test_consensus.py
git commit -m "feat: dynamic consensus strategy for single/multi model"
```

---

## Task 5: OpenCode Plugin Hook

**Files:**
- Create: `src/aigate/integrations/opencode-plugin.ts` (shipped as a template, not executed by aigate)
- Modify: `src/aigate/hook_installer.py` (add `install_opencode`)
- Modify: `tests/unit/test_hook_installer.py`

**Step 1: Write the failing test**

```python
# Append to tests/unit/test_hook_installer.py

def test_install_opencode_creates_plugin(tmp_path):
    from aigate.hook_installer import install_opencode
    msgs = install_opencode(tmp_path)
    assert any("opencode" in m.lower() for m in msgs)
    plugin_dir = tmp_path / ".opencode" / "plugins"
    assert plugin_dir.exists()
    # Check that a plugin file was created
    plugin_files = list(plugin_dir.glob("aigate*"))
    assert len(plugin_files) >= 1


def test_install_opencode_skip_duplicate(tmp_path):
    from aigate.hook_installer import install_opencode
    install_opencode(tmp_path)
    msgs = install_opencode(tmp_path)
    assert any("skip" in m.lower() for m in msgs)
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_hook_installer.py::test_install_opencode_creates_plugin -v`
Expected: FAIL — `ImportError`

**Step 3: Write implementation**

Add to `hook_installer.py`:

```python
OPENCODE_PLUGIN_TEMPLATE = '''\
// aigate package security scanner plugin for OpenCode
// Auto-generated by: aigate install-hooks --tool opencode

export default function aigatePlugin(context) {
  return {
    hooks: {
      beforeToolCall: async (event) => {
        const { name, input } = event;
        if (name !== "shell" && name !== "run_shell_command") return;
        const cmd = input?.command || input?.cmd || "";
        const installPattern = /\\b(pip|npm|yarn|pnpm)\\s+install\\b/;
        if (!installPattern.test(cmd)) return;
        // Extract package names and run aigate check
        const { execSync } = await import("child_process");
        try {
          execSync(`aigate check ${cmd}`, { timeout: 30000 });
        } catch (e) {
          if (e.status === 2) {
            return { blocked: true, reason: "aigate: malicious package detected" };
          }
        }
      },
    },
  };
};
'''

def install_opencode(project_dir: Path) -> list[str]:
    """Install aigate plugin for OpenCode."""
    plugin_dir = project_dir / ".opencode" / "plugins"
    plugin_file = plugin_dir / "aigate-scanner.mjs"

    if plugin_file.exists():
        return [f"(skip) aigate plugin already exists at {plugin_file}"]

    plugin_dir.mkdir(parents=True, exist_ok=True)
    plugin_file.write_text(OPENCODE_PLUGIN_TEMPLATE)
    return [f"Added aigate plugin to {plugin_file}"]
```

Add `"opencode"` to `TOOL_CHOICES` and `INSTALLERS` dict.

**Step 4: Run tests & commit**

Run: `.venv/bin/python -m pytest tests/unit/test_hook_installer.py -v`

```bash
git add src/aigate/hook_installer.py tests/unit/test_hook_installer.py
git commit -m "feat: add OpenCode plugin hook installer"
```

---

## Task 6: Cline .clinerules Hook

**Files:**
- Modify: `src/aigate/hook_installer.py` (add `install_cline`)
- Modify: `tests/unit/test_hook_installer.py`

**Step 1: Write the failing test**

```python
# Append to tests/unit/test_hook_installer.py

def test_install_cline_creates_rules(tmp_path):
    from aigate.hook_installer import install_cline
    msgs = install_cline(tmp_path)
    assert any("cline" in m.lower() for m in msgs)
    rules_file = tmp_path / ".clinerules"
    assert rules_file.exists()
    content = rules_file.read_text()
    assert "aigate" in content


def test_install_cline_appends_to_existing(tmp_path):
    rules_file = tmp_path / ".clinerules"
    rules_file.write_text("# Existing rules\nAlways use TypeScript.\n")
    from aigate.hook_installer import install_cline
    install_cline(tmp_path)
    content = rules_file.read_text()
    assert "Existing rules" in content
    assert "aigate" in content


def test_install_cline_skip_duplicate(tmp_path):
    from aigate.hook_installer import install_cline
    install_cline(tmp_path)
    msgs = install_cline(tmp_path)
    assert any("skip" in m.lower() for m in msgs)
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_hook_installer.py::test_install_cline_creates_rules -v`

**Step 3: Write implementation**

```python
CLINE_RULES_BLOCK = """\

# === aigate: Supply Chain Security ===
# Before running any pip install, npm install, yarn add, or pnpm add command,
# first run: aigate check <package_name> --skip-ai
# If aigate returns exit code 2 (malicious), DO NOT install the package.
# If aigate returns exit code 1 (suspicious), warn the user before proceeding.
# === end aigate ===
"""

def install_cline(project_dir: Path) -> list[str]:
    """Install aigate rules into .clinerules."""
    rules_file = project_dir / ".clinerules"

    if rules_file.exists():
        content = rules_file.read_text()
        if "aigate" in content:
            return [f"(skip) aigate already configured in {rules_file}"]
        content += CLINE_RULES_BLOCK
    else:
        content = CLINE_RULES_BLOCK.lstrip()

    rules_file.write_text(content)
    return [f"Added aigate rules to {rules_file}"]
```

Add `"cline"` to `TOOL_CHOICES` and `INSTALLERS`.

**Step 4: Run tests & commit**

Run: `.venv/bin/python -m pytest tests/unit/test_hook_installer.py -v`

```bash
git add src/aigate/hook_installer.py tests/unit/test_hook_installer.py
git commit -m "feat: add Cline .clinerules hook installer"
```

---

## Task 7: `aigate install-hooks --auto`

**Files:**
- Modify: `src/aigate/cli.py` (update install-hooks command)
- Modify: `tests/unit/test_hook_installer.py`

**Step 1: Write the failing test**

```python
# Append to tests/unit/test_hook_installer.py

def test_install_hooks_auto_detects_tools(tmp_path, monkeypatch):
    """--auto should only install hooks for tools that are actually installed."""
    installed = {"claude", "gemini"}
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}" if name in installed else None)

    from aigate.hook_installer import install_hooks_auto
    msgs = install_hooks_auto(tmp_path)
    assert any("claude" in m for m in msgs)
    assert any("gemini" in m for m in msgs)
    # Should NOT try to install for tools not found
    assert not any("codex" in m for m in msgs)
```

**Step 2: Write implementation**

Add to `hook_installer.py`:

```python
def install_hooks_auto(project_dir: Path) -> list[str]:
    """Auto-detect installed AI tools and install hooks for all of them."""
    messages = []
    for tool_name, installer_fn in INSTALLERS.items():
        # Check if the tool's binary exists
        if shutil.which(tool_name):
            msgs = installer_fn(project_dir)
            messages.extend(msgs)
    if not messages:
        messages.append("No supported AI tools detected. Install one and try again.")
    return messages
```

Update CLI `install-hooks` command to accept `--auto` flag:

```python
@click.option("--auto", is_flag=True, help="Auto-detect installed tools and install all hooks.")
```

**Step 3: Run tests & commit**

Run: `.venv/bin/python -m pytest tests/ -v`

```bash
git add src/aigate/hook_installer.py src/aigate/cli.py tests/unit/test_hook_installer.py
git commit -m "feat: add --auto flag to install-hooks for auto-detection"
```

---

## Task 8: `aigate doctor` Diagnostic Command

**Files:**
- Modify: `src/aigate/cli.py` (add `doctor` command)
- Test: `tests/unit/test_cli_doctor.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_cli_doctor.py
"""Tests for aigate doctor command."""

from __future__ import annotations

from click.testing import CliRunner
from aigate.cli import main


def test_doctor_runs_without_error():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0


def test_doctor_shows_backend_status(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude" if name == "claude" else None)
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "claude" in result.output.lower()


def test_doctor_shows_config_status():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "config" in result.output.lower() or ".aigate.yml" in result.output


def test_doctor_shows_hook_status():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "hook" in result.output.lower()
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_cli_doctor.py -v`

**Step 3: Write implementation**

Add `doctor` command to cli.py:

```python
@main.command()
@click.pass_context
def doctor(ctx):
    """Diagnose aigate setup: backends, hooks, config."""
    from aigate.detect import detect_backends, detect_hooks, KNOWN_BACKENDS
    from aigate.config import Config

    console.print("\n[bold]aigate doctor[/bold]\n")

    # 1. Backends
    console.print("[bold]AI Backends:[/bold]")
    detected = detect_backends()
    detected_names = {b.name for b in detected}
    for template in KNOWN_BACKENDS:
        if template.name in detected_names:
            console.print(f"  [green]✓[/green] {template.name}")
        else:
            console.print(f"  [dim]✗ {template.name}[/dim]  ({template.install_hint})")

    # 2. Strategy
    count = len(detected)
    strategy = {0: "prefilter-only", 1: "single-model", 2: "dual-model"}.get(
        count, f"full consensus ({count} models)"
    )
    console.print(f"\n[bold]Consensus Strategy:[/bold] {strategy}")

    # 3. Config
    console.print(f"\n[bold]Config:[/bold]")
    try:
        config = Config.load()
        console.print(f"  [green]✓[/green] Loaded .aigate.yml ({len(config.models)} models configured)")
    except Exception:
        console.print("  [yellow]![/yellow] No .aigate.yml found (using defaults)")

    # 4. Hooks
    console.print(f"\n[bold]Hook Status:[/bold]")
    hooks = detect_hooks()
    if hooks:
        for h in hooks:
            console.print(f"  [green]✓[/green] {h.tool} detected")
    else:
        console.print("  [dim]No AI tools detected for hook installation[/dim]")

    console.print()
```

**Step 4: Run tests & commit**

Run: `.venv/bin/python -m pytest tests/ -v`

```bash
git add src/aigate/cli.py tests/unit/test_cli_doctor.py
git commit -m "feat: add aigate doctor diagnostic command"
```

---

## Dependency Graph

```
Task 1 (Codex Backend) ─────── independent
Task 2 (OpenAI-compat Backend) ─ independent
Task 3 (Auto-detect) ────────── independent
Task 4 (Dynamic Consensus) ──── independent
Task 5 (OpenCode Plugin) ────── independent
Task 6 (Cline Rules) ────────── independent
Task 7 (--auto hooks) ────────── depends on Task 3 (uses detect module) + Task 5 + Task 6
Task 8 (aigate doctor) ────────── depends on Task 3 (uses detect module)
```

## Execution Order

1. **Tasks 1, 2, 3, 4, 5, 6** — all parallel (independent)
2. **Tasks 7, 8** — after Task 3 (use detect module), also after 5+6 for full hook coverage
