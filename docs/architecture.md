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
        │               │  • Ollama (local HTTP)
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
| **CLI** | `cli.py` | Entry point. Commands: `check`, `diff`, `scan`, `init`, `install-hooks` |
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

## Multi-Model Consensus

```
Package source code
        │
        ├──→ Claude Code ──→ {verdict, confidence, reasoning}
        │
        ├──→ Gemini CLI  ──→ {verdict, confidence, reasoning}
        │
        └──→ Ollama       ──→ {verdict, confidence, reasoning}
                                        │
                                        ▼
                               Voting Aggregator
                               ├─ weighted_score = model_weight × confidence
                               ├─ normalize across verdicts
                               ├─ check disagreement (MALICIOUS + SAFE → NEEDS_REVIEW)
                               └─ final verdict + combined risk signals
```

**Voting thresholds (configurable):**

| Mode | MALICIOUS threshold | SUSPICIOUS threshold |
|------|--------------------|--------------------|
| Strict | Any model ≥ 0.8 | Any model ≥ 0.5 |
| Balanced (default) | Majority ≥ 0.7 | Majority ≥ 0.5 |
| Permissive | All models ≥ 0.8 | Majority ≥ 0.7 |

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
