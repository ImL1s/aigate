# aigate

> **Warning**
> This project is in **Alpha** — not production-ready. APIs may change without notice.

AI multi-model consensus engine for software supply chain security.

Intercepts `pip install` / `npm install` and uses multiple AI models to detect malicious packages **before** they run on your machine. A static pre-filter catches typosquatting, obfuscated payloads, and dangerous patterns without any AI calls — only the ~20% of packages that look suspicious are escalated to multi-model consensus.

## Features

- **AI Multi-Model Consensus** — Claude, Gemini, Ollama vote independently; weighted confidence scores with automatic disagreement detection
- **Zero-Day Detection** — Reads code intent via LLMs, not just signature databases
- **Static Pre-Filter** — Typosquatting, Shannon entropy, dangerous patterns, blocklist (no AI needed for 80%+ of checks)
- **Version Diff Analysis** — Compares two releases to spot injected malware between versions
- **Lockfile Scanning** — Batch-scan `requirements.txt`, `uv.lock`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`
- **pip/npm Hooks** — Seamless integration with your package manager
- **AI Tool Hooks** — Native integration with Claude Code, Gemini CLI, Cursor, and other AI coding tools
- **GitHub Action** — CI/CD scanning with zero configuration
- **Enrichment Pipeline** — Optional OSV, deps.dev, OpenSSF Scorecard, provenance, Context7, and web search signals

## Installation

### From PyPI (recommended)

```bash
uv pip install aigate
```

### From source

```bash
git clone https://github.com/ImL1s/aigate.git
cd aigate
uv venv && uv pip install -e ".[dev]"
```

## Quick Start

```bash
# Check a single package (static pre-filter only, no AI keys needed)
aigate check requests --skip-ai

# Check a known typosquat
aigate check crossenv --skip-ai

# Compare two versions for suspicious changes
aigate diff click 8.1.0 8.1.7 --skip-ai

# Scan an entire lockfile
aigate scan requirements.txt --skip-ai

# Full AI analysis (requires Claude/Gemini CLI installed)
aigate check litellm -v 1.82.8

# Create a default config file
aigate init
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Safe — no issues found |
| `1`  | Suspicious — needs human review |
| `2`  | Malicious — blocked |
| `3`  | Error — analysis failed |

## AI Tool Hook Integration

aigate integrates as a **PreToolUse hook** that automatically scans packages before `pip install` or `npm install` runs inside AI coding tools.

### Claude Code

#### Automatic Install

```bash
# Project-level (recommended)
./scripts/install-hooks.sh

# User-level (applies to all projects)
./scripts/install-hooks.sh --user

# Both
./scripts/install-hooks.sh --both
```

#### Manual Install

Add to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/aigate/scripts/pretool-hook.sh",
            "timeout": 30,
            "statusMessage": "Scanning packages with aigate..."
          }
        ]
      }
    ]
  }
}
```

### Gemini CLI

Add to `~/.gemini/settings.json`:

```json
{
  "preToolUse": {
    "Bash": {
      "command": "/path/to/aigate/scripts/pretool-hook.sh",
      "timeout": 30
    }
  }
}
```

### Cursor / Other AI Tools

Any AI coding tool that supports pre-execution hooks can call the aigate CLI directly:

```bash
# In your tool's hook configuration:
aigate check <package-name> -e pypi --skip-ai --json
# Exit code 2 = block, 0 = allow
```

### Hook Behavior

- **Blocks** only packages that normalize to the shared `malicious` decision
- **Allows** `needs_review` packages by default, but emits that decision in JSON output
- **Scans** `pip install -r requirements.txt` and bare `npm install` / `yarn install` / `pnpm install` when a lockfile is present
- **Skips** non-package commands, local path installs like `pip install .`, and system package upgrades (`pip`, `setuptools`, `wheel`)
- Supports explicit bypass with `--no-aigate`
- **Fail-open** — if aigate crashes or times out, the install proceeds
- Supports: `pip`, `pip3`, `python -m pip`, `uv pip`, `npm`, `yarn`, `pnpm`

## GitHub Action

Scan dependencies in CI/CD — no AI keys needed (static pre-filter by default).

```yaml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  aigate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ImL1s/aigate@main
        with:
          lockfile: requirements.txt
          fail-on: malicious    # malicious | suspicious | any
          skip-ai: "true"       # static pre-filter only (no API keys needed)
```

See [docs/github-action.md](docs/github-action.md) for full options and examples.

## Configuration

Run `aigate init` to create a `.aigate.yml` in your project root. The config is searched upward from CWD to `~/`.

```yaml
# .aigate.yml
models:
  - name: claude
    backend: claude
    model_id: claude-sonnet-4-6
    weight: 1.0
    enabled: true
    timeout_seconds: 120

  - name: gemini
    backend: gemini
    model_id: gemini-2.5-pro
    weight: 0.9
    enabled: true
    timeout_seconds: 120

  # Local analysis (no data sent to cloud):
  # - name: ollama
  #   backend: ollama
  #   model_id: llama3.1:8b
  #   weight: 0.7
  #   options:
  #     base_url: http://localhost:11434

thresholds:
  malicious: 0.6       # weighted confidence >= 0.6 → MALICIOUS
  suspicious: 0.5      # weighted confidence >= 0.5 → SUSPICIOUS
  disagreement: 0.4    # stddev >= 0.4 → NEEDS_HUMAN_REVIEW

whitelist:
  - requests
  - numpy

blocklist:
  - crossenv
  - python3-dateutil

ecosystems:
  - pypi
  - npm

cache_dir: ~/.aigate/cache
cache_ttl_hours: 168   # 7 days

enrichment:
  enabled: true
  osv:
    enabled: true
  deps_dev:
    enabled: true
  scorecard:
    enabled: true
  provenance:
    enabled: true
  context7:
    enabled: false
  web_search:
    enabled: false
```

When `--json` is enabled, single-package reports include shared policy fields:

- `decision`: `safe`, `needs_review`, or `malicious`
- `exit_code`: normalized `0/1/2/3`
- `should_block_install`: whether wrapper hooks should block locally

## Attack Type Coverage

aigate's pre-filter and AI analysis cover these real-world supply chain attack patterns:

| Attack Type | Example | Pre-filter Detection | AI Detection |
|---|---|---|---|
| **Typosquatting** | `crossenv` (npm), `torchtriton` (PyPI) | Name similarity check against top packages | Intent analysis |
| **Account Hijack** | `ua-parser-js`, `event-stream` | Dangerous patterns in install scripts | Code behavior analysis |
| **Maintainer Takeover** | `event-stream` / `flatmap-stream` | Obfuscated `eval`/`exec`, hex encoding | Encrypted payload detection |
| **Domain Expiry Hijack** | `ctx` (PyPI) | `setup.py` exec + credential file access | Exfiltration intent |
| **Protestware** | `colors.js`, `node-ipc` | Install script anomalies | Sabotage pattern detection |
| **Credential Theft** | LiteLLM backdoor, W4SP Stealer | `.ssh/`, `.aws/`, `.env`, token patterns | Data flow analysis |
| **Crypto Mining** | `ua-parser-js` variants | `subprocess`, `exec`, binary downloads | Miner signature detection |
| **Obfuscated Payloads** | W4SP Stealer | Shannon entropy > 5.5, `base64.b64decode` | Deobfuscation + intent |
| **Install-time Execution** | `torchtriton`, `ctx` | `setup.py` / `postinstall.js` code patterns | Install hook analysis |
| **Discord Token Theft** | W4SP Stealer | LevelDB file access, webhook exfiltration | Targeted theft detection |

## Architecture

```
                    CLI (check / scan / diff)
                           │
                    ┌──────▼──────┐
                    │   Resolver   │  ← Download source archive (tar.gz/zip)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Pre-filter  │  ← Typosquat, entropy, patterns, blocklist
                    └──────┬──────┘
                           │
                  ┌────────▼────────┐
                  │  80% safe → exit │
                  └────────┬────────┘
                           │ ~20% suspicious
                    ┌──────▼──────┐
                    │ Enrichment  │  ← Context7, OSV, web search (optional)
                    └──────┬──────┘
                           │
              ┌────────────▼────────────┐
              │    AI Consensus Engine   │
              │  ┌───────┐ ┌──────────┐ │
              │  │Claude │ │ Gemini   │ │  ← Parallel analysis
              │  └───┬───┘ └────┬─────┘ │
              │      │          │        │
              │  ┌───▼──────────▼───┐    │
              │  │  Weighted Vote   │    │  ← weight × confidence
              │  └────────┬────────┘    │
              │           │             │
              │  ┌────────▼────────┐    │
              │  │  Disagreement?  │    │  ← MALICIOUS + SAFE → NEEDS_HUMAN_REVIEW
              │  └────────┬────────┘    │
              └───────────┼─────────────┘
                          │
                   ┌──────▼──────┐
                   │  Reporter   │  ← Terminal (Rich) / JSON / SARIF
                   └─────────────┘
```

**Key modules:**

| Module | Responsibility |
|---|---|
| `cli.py` | Click-based CLI entry point (`check`, `scan`, `diff`, `init`) |
| `resolver.py` | Downloads source archives from PyPI/npm; never executes code |
| `prefilter.py` | Static checks: typosquat, entropy, dangerous patterns, blocklist |
| `consensus.py` | Parallel multi-model analysis with weighted voting |
| `backends/` | Claude (CLI), Gemini (CLI), Ollama (HTTP API) |
| `enrichment/` | OSV, deps.dev, Scorecard, provenance, Context7, web search |
| `reporters/` | Terminal (Rich), JSON, SARIF output formats |
| `hooks/` | pip wrapper, npm wrapper for transparent interception |
| `cache.py` | File-based result cache with configurable TTL |

## CI Layering

`aigate` is best used as the malicious-package / install-time behavior gate. For defense in depth, pair it with:

- `actions/dependency-review-action` for dependency diff gating in PRs
- `pip-audit` for Python environment CVEs
- `osv-scanner` for lockfile / SBOM vulnerability coverage

## Contributing

Contributions are welcome! Please see the [issues page](https://github.com/ImL1s/aigate/issues) for open tasks.

```bash
# Development setup
git clone https://github.com/ImL1s/aigate.git
cd aigate
uv venv && uv pip install -e ".[dev]"

# Run tests
.venv/bin/python -m pytest tests/ -v

# Lint & format
.venv/bin/ruff check src/ tests/
.venv/bin/ruff format src/ tests/
```

**Adding attack fixtures:** Create a synthetic fixture in `tests/fixtures/fake_malicious_<name>.py` following the existing pattern (document the real attack, recreate only the code patterns, never include real malware). Add corresponding test cases in `tests/unit/test_attack_fixtures.py`.

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
