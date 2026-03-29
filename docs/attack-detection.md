# Attack Detection

## Supported Attack Types

| Attack Type | Pre-Filter | AI Analysis | Enrichment | Tested Fixture |
|-------------|-----------|-------------|------------|---------------|
| Typosquatting | ✅ Name similarity | ✅ | — | crossenv, torchtriton |
| Account Takeover / Malicious Update | ✅ Dangerous patterns | ✅ Version diff | ✅ OSV.dev | LiteLLM, ua-parser-js |
| Protestware | ✅ Destructive patterns | ✅ | ✅ Web search | colors/faker |
| Credential Theft | ✅ .ssh/.aws/.env access | ✅ | — | LiteLLM, ctx, crossenv |
| Data Exfiltration | ✅ HTTP POST detection | ✅ | — | LiteLLM, ctx, torchtriton |
| Obfuscated Payloads | ✅ Shannon entropy + base64 | ✅ | — | LiteLLM, W4SP |
| Crypto Mining | ✅ exec + download patterns | ✅ | — | ua-parser-js |
| Install-time Execution | ✅ setup.py/.pth/postinstall | ✅ | — | LiteLLM, crossenv, ctx |
| Targeted Backdoor | ⚠️ Partial (obfuscation) | ✅ | — | event-stream |
| Token/Secret Theft | ✅ ENV var patterns | ✅ | — | W4SP, crossenv |

## Verified Test Cases (8 fixtures)

| # | Case | Ecosystem | Attack Type | Signals Detected |
|---|------|-----------|-------------|-----------------|
| 1 | **LiteLLM v1.82.7** | PyPI | CI/CD compromise → malicious update | .pth auto-exec, base64+exec, credential theft, HTTP exfil, token theft |
| 2 | **crossenv** | npm | Typosquatting (cross-env) | postinstall script, .npmrc theft, network exfil |
| 3 | **event-stream** (tested as flatmap-stream) | npm | Maintainer takeover → targeted backdoor | Hex-encoded require, new Function(), crypto usage |
| 4 | **colors** (tested as colors, not faker) | npm | Protestware | Infinite loop pattern, install scripts |
| 5 | **ua-parser-js** | npm | Account hijack → crypto miner | exec(), preinstall script, file download |
| 6 | **ctx** | PyPI | Domain expiry hijack | setup.py exec, .aws theft, AWS_SECRET token, HTTP exfil |
| 7 | **torchtriton** | PyPI | Typosquatting (triton) | setup.py exec, SSH key theft, system fingerprint, HTTP exfil |
| 8 | **W4SP Stealer** (tested as typesutil) | PyPI | Discord token theft | base64 obfuscation, high entropy, Discord webhook, browser cookie theft |

## Detection Layers

### Layer 1: Pre-Filter (no AI, <1s)

Static pattern matching. Catches ~80% of known attack patterns:

- **18 dangerous code patterns** (eval, exec, subprocess, base64, credential access, network calls, token env vars)
- **Typosquatting** detection via name similarity against top packages
- **Shannon entropy** for obfuscated/encoded payloads (threshold: 5.5)
- **Metadata anomalies** (no author, no repo, install scripts, low downloads)
- **Whitelist/Blocklist** enforcement

### Layer 2: AI Consensus (multi-model, 10-60s)

LLMs analyze code semantics. Catches what regex can't:

- Legitimate API usage vs malicious intent (e.g., `requests.get()` in the requests library is fine)
- Targeted backdoors with conditional triggers
- Novel attack patterns not in any signature database
- Obfuscated code that evades entropy checks

### Layer 3: Enrichment (optional, parallel)

External intelligence adds context:

- **OSV.dev**: Known CVEs for this package+version
- **deps.dev**: Repository trust signals, project activity
- **Scorecard**: OpenSSF security score
- **Provenance**: Build attestations, SLSA compliance
- **Web search**: Community reports of malicious behavior
- **context7**: Official docs (what SHOULD this package do?)

## Output Validation

AI models can be manipulated by malicious code that includes prompt injection payloads. To defend against this, aigate validates model outputs:

- If a model returns `verdict: safe` but its **reasoning** contains malicious keywords (e.g., "exfiltration", "credential theft", "backdoor", "reverse shell"), aigate automatically **upgrades the verdict to SUSPICIOUS**
- An `output_validation(HIGH)` risk signal is added to flag the contradiction
- This catches attacks where injected code manipulates the structured verdict field but cannot fully control the free-text reasoning

This is implemented in `backends/base.py` via `_validate_safe_verdict()` and runs on every model response before consensus aggregation.

## E2E Testing

aigate includes a Docker-based end-to-end test sandbox that validates detection against synthetic malicious packages in a network-isolated environment.

### Setup

- **Docker compose** with two containers: a local `pypiserver` hosting synthetic packages, and a test runner
- **Network isolation**: the runner container cannot reach the internet, only the local PyPI server
- **8 synthetic malicious packages** built from fixtures covering all major attack types (typosquatting, credential theft, data exfiltration, obfuscated payloads, etc.)

### Running E2E Tests

```bash
./scripts/run-e2e.sh
```

This script:
1. Builds synthetic malicious packages from `tests/e2e/build_packages.py`
2. Starts Docker containers (pypiserver + test runner)
3. Runs E2E tests with `AIGATE_E2E=1` inside the container
4. Tears down containers and reports results

E2E tests are **skipped** in normal `pytest` runs. They only execute when `AIGATE_E2E=1` is set (automatically done by docker compose).

## Non-Package Vector Detection

Beyond package registries, aigate detects threats from non-package install vectors. These use **warn mode** — the command is not blocked, but a warning is shown to the user.

### curl|sh Pipe Detection

Remote scripts piped to a shell (`curl ... | sh`, `wget ... | bash`) are flagged as HIGH risk. The hook extracts the URL and emits a warning.

| Pattern | Risk | Action |
|---------|:----:|--------|
| `curl <url> \| sh` | HIGH | Warn with URL |
| `curl <url> \| bash` | HIGH | Warn with URL |
| `wget <url> \| sh` | HIGH | Warn with URL |
| `wget -O- <url> \| bash` | HIGH | Warn with URL |

### Untrusted Docker Images

`docker pull` and `docker run` are checked against a trusted registry list (`gcr.io/`, `ghcr.io/`, `docker.io/library/`, `mcr.microsoft.com/`). Images from untrusted sources trigger a MEDIUM warning.

### VSCode Extension Install

`code --install-extension <id>` triggers a MEDIUM warning, alerting the user to verify the extension publisher.

## AI Agent Vector Detection

The `agent_scanner.py` module detects threats specific to AI coding agent workflows. These are particularly dangerous because they can manipulate the AI tool itself.

### MCP Server Config Scanning

When MCP config files (`.claude/settings.json`, `.cursor/mcp.json`, etc.) are modified, aigate scans the new entries for suspicious patterns:

- Reverse shell commands (`nc -e`, `nc -l`)
- Credential access (`.ssh/`, `.aws/`, `.env`)
- Shell pipe execution (`curl ... | sh`)
- Dangerous eval/exec chains

### Agent Skill File Scanning

Skill `.md` files are scanned for embedded shell commands that could be dangerous when executed by an AI agent:

- Code blocks containing `curl|sh`, `eval`, `exec`
- Reverse shell patterns
- Credential harvesting commands

### Rules File Injection Scanning

AI rules files (`.cursorrules`, `.windsurfrules`) are scanned for hidden prompt injection:

- "Ignore previous instructions" patterns
- Hardcoded URLs or endpoints
- Hidden Unicode characters used to smuggle instructions
- Directives to bypass security checks

## Known Limitations

| Limitation | Why | Mitigation |
|-----------|-----|------------|
| False positives on legitimate packages | Packages that use their own APIs (e.g., `requests.get()` in requests) trigger pattern matching | AI layer overrides; whitelist |
| Cannot detect runtime-only attacks | Code that downloads payload after install, not during | AI can flag suspicious network setup |
| Limited to text file analysis | Binary payloads, compiled extensions not scanned | Entropy check on text; future: binary analysis |
| AI prompt injection | Malicious code can try to manipulate AI verdict | `UNTRUSTED_PACKAGE_CODE` delimiters + multi-model consensus |
| Newer ecosystems use prefilter only | Cargo, Gem, Composer, Go, NuGet don't have full resolvers yet | Typosquat + blocklist detection; full resolver planned |
