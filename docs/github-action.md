# Using aigate as a GitHub Action

Scan your project dependencies for malicious packages in CI/CD.

## Quick Start

```yaml
# .github/workflows/security.yml
name: Dependency Security

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - uses: ImL1s/aigate@main
        with:
          lockfile: requirements.txt
          fail-on: malicious
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `lockfile` | Yes | — | Path to lockfile (`requirements.txt`, `package-lock.json`, `pubspec.lock`) |
| `ecosystem` | No | `pypi` | Package ecosystem (`pypi`, `npm`) |
| `fail-on` | No | `malicious` | When to fail: `malicious`, `suspicious`, or `any` |
| `skip-ai` | No | `true` | Skip AI models, run static pre-filter only (recommended for CI) |
| `python-version` | No | `3.12` | Python version for the runner |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | aigate exit code: `0`=safe, `1`=suspicious, `2`=malicious, `3`=error |
| `report` | JSON scan report |

## Examples

### Python project (pre-filter only)

Fast static analysis without AI — catches typosquatting, suspicious patterns, blocklisted packages.

```yaml
- uses: ImL1s/aigate@main
  with:
    lockfile: requirements.txt
    fail-on: malicious
```

### Node.js project

```yaml
- uses: ImL1s/aigate@main
  with:
    lockfile: package-lock.json
    ecosystem: npm
    fail-on: suspicious
```

### Full AI analysis

Enable multi-model consensus (requires `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` in repo secrets, or CLI tools installed on runner).

```yaml
- uses: ImL1s/aigate@main
  with:
    lockfile: requirements.txt
    skip-ai: "false"
    fail-on: malicious
```

### Use scan output in subsequent steps

```yaml
- uses: ImL1s/aigate@main
  id: security
  with:
    lockfile: requirements.txt

- name: Check result
  if: steps.security.outputs.exit-code != '0'
  run: |
    echo "Security issues found!"
    echo "${{ steps.security.outputs.report }}"
```

### Block PRs with malicious dependencies

```yaml
name: Security Gate

on: pull_request

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - uses: ImL1s/aigate@main
        with:
          lockfile: requirements.txt
          fail-on: malicious
```

When `fail-on: malicious` is set, the workflow will only fail (and block merge) if a package is flagged as malicious. Suspicious packages will be reported but won't block the PR.

## How `fail-on` works

| `fail-on` value | Fails on exit 1 (suspicious) | Fails on exit 2 (malicious) |
|-----------------|------------------------------|------------------------------|
| `malicious` | No | Yes |
| `suspicious` | Yes | Yes |
| `any` | Yes | Yes |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All dependencies passed |
| 1 | Suspicious packages detected |
| 2 | Malicious packages detected |
| 3 | Scan error |

## Tips

- **CI default is `skip-ai: true`** — static pre-filter is fast (~1s) and catches known attack patterns without API keys
- Use `fail-on: malicious` for production gates, `fail-on: suspicious` for stricter security
- The action writes a summary to `$GITHUB_STEP_SUMMARY` visible in the Actions tab
- Pin to a release tag (e.g., `ImL1s/aigate@v0.1.0`) once available for reproducible builds
