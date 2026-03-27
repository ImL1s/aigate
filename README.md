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
