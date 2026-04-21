# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

aigate — AI multi-model consensus engine for software supply chain security. Intercepts pip/npm install and uses multiple AI models to detect malicious packages before execution.

## Commands

```bash
# Dev install (use uv, not pip directly — PEP 668)
uv venv && uv pip install -e ".[dev]"

# Run tests (705 unit tests + 12 E2E, ~41s)
.venv/bin/python -m pytest tests/ -v

# Lint & format
.venv/bin/ruff check src/ tests/
.venv/bin/ruff format src/ tests/

# CLI
.venv/bin/aigate check <package> [--skip-ai] [-e pypi|npm] [-v version]
.venv/bin/aigate scan <lockfile>
.venv/bin/aigate init
```

## Architecture

Async-first (httpx, asyncio subprocesses). Flow: CLI → Resolver → Pre-filter → AI Consensus → Reporter.

- **prefilter.py** — Static checks (typosquat, entropy, dangerous patterns). Aims to filter 80%+ requests, only ~20% go to AI.
- **consensus.py** — Parallel multi-model analysis. Weighted votes: model_weight × confidence. Disagreement (MALICIOUS + SAFE) → NEEDS_HUMAN_REVIEW.
- **backends/** — Claude/Gemini use CLI headless (`claude -p`, `gemini -p`). Ollama uses local HTTP API. All implement `AIBackend.analyze()`.
- **resolver.py** — Downloads source archives (tar.gz/zip) and extracts text files. Never executes package code.
- **sandbox/** — Analyzes static/behavioral signals only; never runs package code. Respect this security boundary when extending.

## Skills

Pre-installed in `.claude/skills/` — invoke with `/`:

- `/verify` — lint + format check + full pytest. Run before commits.
- `aigate-check` / `aigate-scan` / `check-package` — supply chain checks; the PreToolUse hook also auto-scans pip/npm/cargo/etc. install commands.

## Code Style

- Python 3.11+ (CI matrix: 3.11 / 3.12 / 3.13 — keep compat with all three), full type hints (`from __future__ import annotations`)
- Ruff: line-length 100, rules E/F/I/N/W/UP
- Async everywhere — use `async def` + `httpx.AsyncClient`, not `requests`
- Prefilter risk signals are strings like `"dangerous_pattern(HIGH): ..."` — keep this format

## Testing

- Synthetic malware fixtures in `tests/fixtures/` — never download real malicious packages
- pytest-asyncio with `asyncio_mode = "auto"`
- Exit codes: 0=safe, 1=suspicious, 2=malicious, 3=error

## Config

`.aigate.yml` lookup: CWD → parents → `~/.aigate.yml`. Default models: Claude + Gemini.

## Gotchas

- Claude/Gemini backends require CLI binaries installed — fail gracefully if missing
- Pre-filter skips .md/.rst/.txt files to reduce false positives (e.g., `requests.get()` in docs)
- Entropy check requires line length ≥80 chars
- Blocklisted packages are blocked immediately without AI analysis

## Package Security (aigate)

Before installing ANY package via pip, npm, yarn, or pnpm, ALWAYS run:

```
aigate check <package_name>
```

For npm packages:
```
aigate check <package_name> -e npm
```

**Interpret exit codes:**
- Exit 0 = safe, proceed with install
- Exit 1 = suspicious, warn the user before proceeding
- Exit 2 = malicious, DO NOT install. Inform the user immediately.

**For lockfile scanning:**
```
aigate scan requirements.txt
aigate scan package-lock.json
```

This is a supply chain security measure. Never skip this step.
