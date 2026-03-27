# aigate

AI multi-model consensus engine for software supply chain security.

Intercepts `pip install` / `npm install` and uses multiple AI models to detect malicious packages **before** they run on your machine.

## Quick Start

```bash
uv pip install aigate
aigate check litellm --version 1.82.8
```

## Features

- **AI Multi-Model Consensus** — Claude, Gemini, Codex, Ollama vote independently
- **Zero-Day Detection** — Reads code intent, not just signature databases
- **Version Diff Analysis** — Compares releases to spot injected malware
- **Static Pre-Filter** — Typosquatting, entropy, dangerous patterns (no AI needed)
- **pip/npm Hooks** — Seamless integration with your package manager

## Claude Code Hook

aigate integrates as a Claude Code **PreToolUse hook** that automatically scans packages before `pip install` or `npm install` runs.

### Automatic Install

```bash
# Project-level (recommended)
./scripts/install-hooks.sh

# User-level (applies to all projects)
./scripts/install-hooks.sh --user

# Both
./scripts/install-hooks.sh --both
```

### Manual Install

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

### Behavior

- **Blocks** packages flagged as `CRITICAL` or `HIGH` risk (typosquats, blocklisted, dangerous patterns)
- **Allows** `MEDIUM`, `LOW`, or safe packages silently
- **Skips** non-package commands, `pip install -r requirements.txt`, `pip install .`, system packages (`pip`, `setuptools`, `wheel`)
- **Fail-open** -- if aigate crashes or times out, the install proceeds
- Supports: `pip`, `pip3`, `python -m pip`, `uv pip`, `npm`, `yarn`, `pnpm`

## GitHub Action

Scan dependencies in CI/CD — no AI keys needed (static pre-filter by default).

```yaml
- uses: ImL1s/aigate@main
  with:
    lockfile: requirements.txt
    fail-on: malicious
```

See [docs/github-action.md](docs/github-action.md) for full options and examples.

## License

Apache-2.0
