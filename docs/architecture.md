# Architecture

## System Flow

```
User runs: aigate check <package>
                │
                ▼
        ┌──────────────┐
        │   CLI Layer   │  cli.py — parse args, orchestrate flow
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │   Resolver    │  resolver.py — fetch metadata + source from PyPI/npm
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  Pre-Filter   │  prefilter.py — fast static checks (no AI needed)
        │               │  • Typosquatting detection
        │               │  • Dangerous code patterns (eval, exec, base64)
        │               │  • Credential access (.ssh, .aws, .env)
        │               │  • Shannon entropy (obfuscation)
        │               │  • Metadata anomalies
        └──────┬───────┘
               │
          needs AI? ──NO──→ PASS or BLOCK (based on risk level)
               │
              YES
               │
               ▼
        ┌──────────────┐
        │  Enrichment   │  enrichment/ — optional external intelligence
        │  (optional)   │  • context7: official docs (what should it do?)
        │               │  • OSV.dev: known vulnerabilities
        │               │  • deps.dev: repository trust signals
        │               │  • Scorecard: OpenSSF score
        │               │  • Provenance: build attestations
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │ AI Consensus  │  consensus.py — parallel multi-model analysis
        │               │  • Claude Code (headless CLI)
        │               │  • Gemini CLI (headless)
        │               │  • Codex CLI (headless)
        │               │  • Ollama (local HTTP)
        │               │  • OpenAI-compat (any HTTP chat/completions API)
        │               │  • Weighted voting + disagreement detection
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │   Reporter    │  reporters/ — format and display results
        │               │  • Rich terminal (colored, tables)
        │               │  • JSON (CI/CD, machine-readable)
        └──────────────┘
```

## Module Responsibilities

| Module | File | Responsibility |
|--------|------|----------------|
| **CLI** | `cli.py` | Entry point. Commands: `check`, `diff`, `scan`, `init`, `install-hooks`, `instructions`, `doctor` |
| **Config** | `config.py` | Load `.aigate.yml` from CWD → parents → home. Merge defaults |
| **Resolver** | `resolver.py` | Fetch package metadata from PyPI/npm. Download + extract source archives (never execute) |
| **Pre-Filter** | `prefilter.py` | Static analysis. Aims to filter 80%+ of safe packages without AI |
| **Enrichment** | `enrichment/` | Optional intelligence layer. Fetches docs, CVEs, trust signals |
| **Consensus** | `consensus.py` | Run multiple AI models in parallel. Aggregate weighted votes |
| **Backends** | `backends/` | AI model adapters. Each implements `analyze(prompt) → str` |
| **Cache** | `cache.py` | File-based analysis cache. SHA256 key, configurable TTL |
| **Policy** | `policy.py` | Decision logic. Maps analysis results to verdicts + exit codes |
| **Reporters** | `reporters/` | Output formatting. Terminal (Rich) and JSON |
| **Hooks** | `hooks/` | Package manager wrappers. `aigate-pip`, `aigate-npm` |
| **Hook Installer** | `hook_installer.py` | Install PreToolUse hooks into AI tool configs |
| **Detect** | `detect.py` | Auto-detect installed AI backends and hook tools |
| **Instructions** | `instructions.py` | Generate LLM instruction files (CLAUDE.md, GEMINI.md, etc.) |
| **Config Validator** | `config_validator.py` | Validate `.aigate.yml` schema and values |
| **Rate Limiter** | `rate_limiter.py` | Per-backend rate limiting for API calls |
| **Log** | `log.py` | Structured logging configuration |

## Multi-Model Consensus

```
Package source code
        │
        ├──→ Claude Code (CLI)      ──→ {verdict, confidence, reasoning}
        │
        ├──→ Gemini CLI             ──→ {verdict, confidence, reasoning}
        │
        ├──→ Codex CLI              ──→ {verdict, confidence, reasoning}
        │
        ├──→ Ollama (HTTP)          ──→ {verdict, confidence, reasoning}
        │
        └──→ OpenAI-compat (HTTP)   ──→ {verdict, confidence, reasoning}
                                                │
                                                ▼
                                       Voting Aggregator
                                       ├─ weighted_score = model_weight × confidence
                                       ├─ normalize across verdicts
                                       ├─ check disagreement (MALICIOUS + SAFE → NEEDS_REVIEW)
                                       └─ final verdict + combined risk signals
```

**Dynamic consensus:** When only one model is enabled, aigate uses a single-model fast path — no voting needed, the result is used directly.

**System/user message separation:** API-based backends (Ollama, OpenAI-compat) send structured `system` + `user` message pairs via the chat completions API. CLI-based backends (Claude, Gemini, Codex) concatenate into a single prompt.

**Voting thresholds (configurable in `.aigate.yml`):**

Consensus uses a weighted average: each model's weight is multiplied by its confidence, scores are normalized across verdicts, then compared against flat thresholds:

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `thresholds.malicious` | 0.6 | Weighted MALICIOUS score above this → **MALICIOUS** verdict |
| `thresholds.suspicious` | 0.5 | Weighted SUSPICIOUS score above this → **SUSPICIOUS** verdict |

If any MALICIOUS and SAFE verdicts coexist among models, the result is **NEEDS_HUMAN_REVIEW** regardless of scores. When only one model returns a valid result, the single-model fast path is used — no voting needed.

## Analysis Levels

| Level | Token Budget | When Used |
|-------|-------------|-----------|
| L1 Quick | ~2K tokens | Default for `check` and hooks |
| L2 Deep | ~8K tokens | Default for `diff`, or explicit `-l l2_deep` |
| L3 Expert | ~32K tokens | Explicit `-l l3_expert`, for high-value targets |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Safe |
| 1 | Suspicious / Needs human review |
| 2 | Malicious — blocked |
| 3 | Error |

## Security: Output Validation

AI model responses are validated before being trusted. If a model returns `verdict: safe` but its reasoning text contains malicious keywords (e.g., "exfiltration", "credential theft", "backdoor"), aigate automatically upgrades the verdict to `SUSPICIOUS` and adds an `output_validation(HIGH)` risk signal. This defends against prompt injection attacks where malicious code manipulates the verdict field but cannot fully control the reasoning.
