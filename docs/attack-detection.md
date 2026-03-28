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
| 3 | **event-stream** | npm | Maintainer takeover → targeted backdoor | Hex-encoded require, new Function(), crypto usage |
| 4 | **colors/faker** | npm | Protestware | Infinite loop pattern, install scripts |
| 5 | **ua-parser-js** | npm | Account hijack → crypto miner | exec(), preinstall script, file download |
| 6 | **ctx** | PyPI | Domain expiry hijack | setup.py exec, .aws theft, AWS_SECRET token, HTTP exfil |
| 7 | **torchtriton** | PyPI | Typosquatting (triton) | setup.py exec, SSH key theft, system fingerprint, HTTP exfil |
| 8 | **W4SP Stealer** | PyPI | Discord token theft | base64 obfuscation, high entropy, Discord webhook, browser cookie theft |

## Detection Layers

### Layer 1: Pre-Filter (no AI, <1s)

Static pattern matching. Catches ~80% of known attack patterns:

- **17 dangerous code patterns** (eval, exec, subprocess, base64, credential access, network calls, token env vars)
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

## Known Limitations

| Limitation | Why | Mitigation |
|-----------|-----|------------|
| False positives on legitimate packages | Packages that use their own APIs (e.g., `requests.get()` in requests) trigger pattern matching | AI layer overrides; whitelist |
| Cannot detect runtime-only attacks | Code that downloads payload after install, not during | AI can flag suspicious network setup |
| Limited to text file analysis | Binary payloads, compiled extensions not scanned | Entropy check on text; future: binary analysis |
| AI prompt injection | Malicious code can try to manipulate AI verdict | `UNTRUSTED_PACKAGE_CODE` delimiters + multi-model consensus |
| No Go/Rust/Dart support yet | Resolver only supports PyPI + npm | Phase 2 roadmap |
