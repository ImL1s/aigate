"""Base class for AI backends."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod

from ..models import AnalysisLevel, ModelResult, Verdict


ANALYSIS_PROMPT_TEMPLATE = """\
You are a software supply chain security analyst. Analyze the following package \
for potential malicious behavior.

## Package Information
- Name: {name}
- Version: {version}
- Ecosystem: {ecosystem}
- Author: {author}
- Description: {description}
- Has install scripts: {has_install_scripts}

## Risk Signals from Static Analysis
{risk_signals}

## Source Code to Analyze
{source_code}

## Instructions
Analyze the code above for:
1. Credential theft (reading .ssh, .aws, .env, tokens)
2. Data exfiltration (HTTP POST to unknown domains, DNS exfiltration)
3. Remote code execution (eval, exec, subprocess with external input)
4. Obfuscation (base64 encoded payloads, dynamic imports, encoded strings)
5. Unusual file system access (reading/writing outside package scope)
6. Network calls inconsistent with package's stated purpose
7. Install-time code execution (setup.py, postinstall, .pth files)
8. Cryptocurrency mining indicators

Respond with ONLY a JSON object (no markdown, no explanation outside JSON):
{{
  "verdict": "safe" | "suspicious" | "malicious",
  "confidence": 0.0 to 1.0,
  "reasoning": "Brief explanation of your analysis",
  "risk_signals": ["signal1", "signal2"]
}}
"""

DIFF_PROMPT_TEMPLATE = """\
You are a software supply chain security analyst. Analyze the following VERSION DIFF \
for potential malicious changes injected between versions.

## Package: {name} ({old_version} → {new_version})
## Ecosystem: {ecosystem}

## Changes Summary
- New imports: {new_imports}
- New network calls: {new_network_calls}
- New exec/eval calls: {new_exec_calls}
- New file access: {new_file_access}
- Install script changes: {install_script_changes}

## Diff Content
{diff_content}

## Instructions
Focus on changes that could indicate a supply chain attack:
1. New network calls to unknown domains (especially in install scripts)
2. New credential/secret reading code
3. New obfuscated or encoded strings
4. Behavioral changes inconsistent with the package's purpose
5. New .pth files or startup hooks

Respond with ONLY a JSON object:
{{
  "verdict": "safe" | "suspicious" | "malicious",
  "confidence": 0.0 to 1.0,
  "reasoning": "Brief explanation focusing on what changed and why it's concerning",
  "risk_signals": ["signal1", "signal2"]
}}
"""


class AIBackend(ABC):
    """Abstract base class for AI analysis backends."""

    name: str = "base"

    @abstractmethod
    async def analyze(
        self,
        prompt: str,
        level: AnalysisLevel = AnalysisLevel.L1_QUICK,
    ) -> str:
        """Send prompt to AI model and return raw response."""
        ...

    async def analyze_package(
        self,
        name: str,
        version: str,
        ecosystem: str,
        author: str,
        description: str,
        has_install_scripts: bool,
        risk_signals: list[str],
        source_code: str,
        level: AnalysisLevel = AnalysisLevel.L1_QUICK,
    ) -> ModelResult:
        """Analyze a package and return structured result."""
        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            name=name,
            version=version,
            ecosystem=ecosystem,
            author=author or "unknown",
            description=description or "none",
            has_install_scripts=has_install_scripts,
            risk_signals="\n".join(f"- {s}" for s in risk_signals) or "None",
            source_code=_truncate(source_code, level),
        )

        import time
        start = time.monotonic()
        raw = await self.analyze(prompt, level)
        latency = int((time.monotonic() - start) * 1000)

        return _parse_response(raw, self.name, level, latency)

    async def analyze_diff(
        self,
        name: str,
        old_version: str,
        new_version: str,
        ecosystem: str,
        new_imports: list[str],
        new_network_calls: list[str],
        new_exec_calls: list[str],
        new_file_access: list[str],
        install_script_changes: str,
        diff_content: str,
        level: AnalysisLevel = AnalysisLevel.L1_QUICK,
    ) -> ModelResult:
        """Analyze a version diff and return structured result."""
        prompt = DIFF_PROMPT_TEMPLATE.format(
            name=name,
            old_version=old_version,
            new_version=new_version,
            ecosystem=ecosystem,
            new_imports=", ".join(new_imports) or "None",
            new_network_calls=", ".join(new_network_calls) or "None",
            new_exec_calls=", ".join(new_exec_calls) or "None",
            new_file_access=", ".join(new_file_access) or "None",
            install_script_changes=install_script_changes or "None",
            diff_content=_truncate(diff_content, level),
        )

        import time
        start = time.monotonic()
        raw = await self.analyze(prompt, level)
        latency = int((time.monotonic() - start) * 1000)

        return _parse_response(raw, self.name, level, latency)


def _truncate(text: str, level: AnalysisLevel) -> str:
    """Truncate source code based on analysis level token budget."""
    limits = {
        AnalysisLevel.L1_QUICK: 4000,    # ~2K tokens
        AnalysisLevel.L2_DEEP: 16000,    # ~8K tokens
        AnalysisLevel.L3_EXPERT: 64000,  # ~32K tokens
    }
    limit = limits.get(level, 4000)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n... [truncated at {limit} chars for {level.value} analysis]"


def _parse_response(
    raw: str,
    model_name: str,
    level: AnalysisLevel,
    latency_ms: int,
) -> ModelResult:
    """Parse AI response into ModelResult."""
    try:
        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r"\{[\s\S]*\}", raw)
        if not json_match:
            raise ValueError("No JSON found in response")
        parsed = json.loads(json_match.group())

        verdict_str = parsed.get("verdict", "error").lower()
        verdict_map = {
            "safe": Verdict.SAFE,
            "suspicious": Verdict.SUSPICIOUS,
            "malicious": Verdict.MALICIOUS,
        }
        verdict = verdict_map.get(verdict_str, Verdict.ERROR)

        return ModelResult(
            model_name=model_name,
            verdict=verdict,
            confidence=float(parsed.get("confidence", 0.5)),
            reasoning=parsed.get("reasoning", ""),
            risk_signals=parsed.get("risk_signals", []),
            analysis_level=level,
            latency_ms=latency_ms,
            raw_response=raw,
        )
    except Exception as e:
        return ModelResult(
            model_name=model_name,
            verdict=Verdict.ERROR,
            confidence=0.0,
            reasoning=f"Failed to parse response: {e}",
            analysis_level=level,
            latency_ms=latency_ms,
            raw_response=raw,
        )
