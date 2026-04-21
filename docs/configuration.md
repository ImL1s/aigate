# Configuration Guide

aigate is configured via `.aigate.yml`. It searches: CWD → parent directories → `~/.aigate.yml`.

## Quick Start

```bash
aigate init  # creates .aigate.yml in current directory
```

`aigate init` auto-detects installed AI tools (Claude, Gemini, Codex, Ollama) and enables only the backends found on your system.

### Diagnosing Setup

```bash
aigate doctor  # detects backend binaries on PATH and reports their status
```

## Full Example

```yaml
# AI models for consensus analysis
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

  - name: ollama          # Local model — no data sent to cloud
    backend: ollama
    model_id: llama3.1:8b
    weight: 0.7
    enabled: false
    options:
      base_url: http://localhost:11434

  # - name: codex          # OpenAI Codex CLI
  #   backend: codex
  #   model_id: o3
  #   weight: 1.0
  #   enabled: false

  # - name: openai_compat  # Any OpenAI-compatible API (vLLM, Together, etc.)
  #   backend: openai_compat
  #   model_id: gpt-4o
  #   weight: 0.8
  #   enabled: false
  #   options:
  #     base_url: https://api.openai.com/v1
  #     api_key_env: OPENAI_API_KEY

# Voting thresholds
thresholds:
  malicious: 0.6       # Block if weighted malicious score > 0.6
  suspicious: 0.5      # Warn if weighted suspicious score > 0.5
  disagreement: 0.4    # Reserved — disagreement is currently detected when SAFE and MALICIOUS verdicts coexist, regardless of this value

# Skip analysis for trusted packages
whitelist:
  - requests
  - numpy
  - flask
  - django

# Block immediately without analysis
blocklist:
  - crossenv
  - python3-dateutil

# Supported ecosystems
ecosystems:
  - pypi
  - npm
  - pub       # pub.dev (Dart/Flutter)

# Cache settings
# Default TTL matches npm's 72h unpublish window — beyond that an attacker
# can publish → get cached SAFE → unpublish → republish under the same
# version. Set AIGATE_NO_CACHE=1 in the env to bypass reads and writes.
cache_dir: ~/.aigate/cache
cache_ttl_hours: 72

# Maximum AI analysis depth
max_analysis_level: l2_deep  # l1_quick | l2_deep | l3_expert

# Output format
output_format: rich     # rich | json | sarif

# Enrichment (optional intelligence gathering)
enrichment:
  enabled: false        # Set to true to enable
  timeout_seconds: 10

  # Official docs lookup
  context7:
    enabled: false
    api_key_env: CONTEXT7_API_KEY

  # Web search for security intel
  web_search:
    enabled: false
    provider: brightdata
    api_key_env: BRIGHT_DATA_API_KEY

  # Known vulnerability database (free, no key needed)
  osv:
    enabled: true

  # deps.dev repository metadata
  deps_dev:
    enabled: false

  # OpenSSF Scorecard
  scorecard:
    enabled: false

  # Build provenance verification
  provenance:
    enabled: false
```

## Preset Configurations

### Individual Developer (free)

```yaml
models:
  - name: ollama
    backend: ollama
    model_id: llama3.1:8b
    weight: 1.0
enrichment:
  enabled: true
  osv:
    enabled: true
```

### Team (standard)

```yaml
models:
  - name: claude
    backend: claude
    weight: 1.0
  - name: gemini
    backend: gemini
    weight: 0.9
  - name: ollama
    backend: ollama
    weight: 0.7
thresholds:
  malicious: 0.6
  suspicious: 0.5
enrichment:
  enabled: true
  osv:
    enabled: true
  deps_dev:
    enabled: true
  scorecard:
    enabled: true
```

### Enterprise (strict)

```yaml
models:
  - name: claude
    backend: claude
    weight: 1.0
  - name: gemini
    backend: gemini
    weight: 0.9
  - name: ollama
    backend: ollama
    model_id: llama3.1:70b
    weight: 0.8
thresholds:
  malicious: 0.4    # Lower threshold = more aggressive blocking
  suspicious: 0.3
max_analysis_level: l3_expert
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
```
