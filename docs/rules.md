# Rule Engine

aigate uses an extensible YAML-based rule engine for static pattern detection. Rules are loaded at startup from built-in and user directories, merged by ID, and applied during the pre-filter phase.

## Rule Format

Each YAML rule file contains a `rules` list. Every rule has these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier (e.g. `eval-call`, `ssh-access`) |
| `pattern` | string (regex) | Yes | Python regex to match against source code |
| `severity` | string | Yes | `low`, `medium`, `high`, or `critical` |
| `scope` | string | Yes | `install_script`, `source`, or `any` |
| `ecosystem` | string | No | `"*"` (default, all ecosystems), `"pypi"`, `"npm"`, etc. |
| `description` | string | No | Human-readable explanation |
| `tags` | list[string] | No | Categories for filtering and compound detection |

### Example Rule File

```yaml
rules:
  - id: exec-call
    pattern: '\bexec\s*\('
    severity: medium
    scope: any
    ecosystem: "*"
    description: "Dynamic code execution via exec()"
    tags: [execution, dynamic]

  - id: setup-py-exec
    pattern: '\bexec\s*\('
    severity: critical
    scope: install_script
    ecosystem: "*"
    description: "exec() in install script -- runs at install time"
    tags: [execution, install-time]
```

### Key Design Decisions

- **Same pattern, different severity per scope:** `exec()` in regular source is `medium`, but in `setup.py` / `postinstall.js` it is `critical`.
- **Ecosystem filtering:** A rule with `ecosystem: "npm"` only applies to npm packages. `"*"` applies to all.
- **Tags drive compound detection:** When multiple tags like `execution` + `credential_access` appear in the same file, the compound detector escalates severity.

## Built-in Rules

aigate ships with 6 built-in rule files in `src/aigate/rules/builtin/`:

| File | Category | Example Patterns |
|------|----------|-----------------|
| `dangerous_patterns.yml` | Execution | `eval`, `exec`, `__import__`, `subprocess`, `os.system` |
| `credential_access.yml` | Credential theft | `.ssh/`, `.aws/`, `.env`, `GITHUB_TOKEN`, `NPM_TOKEN` |
| `exfiltration.yml` | Network | `requests.post`, `urllib`, `socket.connect`, `dns.resolver` |
| `obfuscation.yml` | Obfuscation | `base64.b64decode`, `marshal.loads`, `webbrowser.open` |
| `install_hooks.yml` | Install-time | `process.exit`, `os._exit`, `os.kill` |
| `node_specific.yml` | Node.js | `child_process`, `new Function(`, `process.binding` |

## Custom Rules

### Where to Put Custom Rules

Place your YAML rule files in `~/.aigate/rules/`. All `.yml` files in that directory are loaded automatically.

Alternatively, configure a custom directory in `.aigate.yml`:

```yaml
rules:
  user_rules_dir: ~/my-project/security-rules/
```

### Writing a Custom Rule

Create a file like `~/.aigate/rules/my_rules.yml`:

```yaml
rules:
  # Flag references to an internal API that should never exist in third-party packages
  - id: custom-internal-api
    pattern: 'internal_secret_api\('
    severity: high
    scope: any
    ecosystem: "*"
    description: "References to internal API in third-party package"
    tags: [custom, suspicious]

  # Stricter eval check for install scripts
  - id: eval-install-strict
    pattern: '\beval\s*\('
    severity: critical
    scope: install_script
    ecosystem: "*"
    description: "eval() in install script"
    tags: [execution, install-time, custom]
```

### Overriding Built-in Rules

User rules with the same `id` as a built-in rule **replace** it. This lets you adjust severity or scope without modifying aigate source:

```yaml
rules:
  # Override: treat eval as low severity in your project
  - id: eval-call
    pattern: '\beval\s*\('
    severity: low
    scope: any
    ecosystem: "*"
    description: "eval() -- low severity in our codebase"
    tags: [execution, dynamic]
```

## Disabling Noisy Rules

If a built-in rule produces too many false positives for your project, disable it in `.aigate.yml`:

```yaml
rules:
  disable_rules:
    - eval-call        # our project legitimately uses eval
    - requests-post    # we know our deps make HTTP calls
```

Disabled rules are excluded from pattern matching entirely.

## Compound Signal Detection

Individual LOW signals are often benign. But when multiple signal categories appear in the **same file**, aigate escalates the severity:

| Compound Rule | Required Tags | Escalated Severity |
|--------------|---------------|-------------------|
| `exec-plus-cred-theft` | `execution` + `credential_access` | MEDIUM |
| `exec-plus-exfiltration` | `execution` + `exfiltration` | HIGH |
| `obfuscation-plus-exfiltration` | `obfuscation` + `exfiltration` | HIGH |
| `full-attack-chain` | `execution` + `credential_access` + `exfiltration` | CRITICAL |

Example: A single `subprocess.Popen()` in library source is LOW. But `subprocess.Popen()` + `.ssh/id_rsa` + `requests.post()` in the same file triggers `full-attack-chain` at CRITICAL.

## CLI Commands

```bash
# List all loaded rules
aigate rules list

# Filter by tag
aigate rules list --tag execution

# Show statistics
aigate rules stats

# Update popular package cache
aigate rules update-popular
```

## Auto-Updating Popular Packages

Typosquatting detection compares package names against popular package lists. These lists are cached locally and can be refreshed:

- **PyPI:** Top 1000 packages from [hugovk's dataset](https://hugovk.github.io/top-pypi-packages/)
- **npm:** Top packages from the npm registry search API
- **Cache:** `~/.aigate/cache/popular_packages.json` with 7-day TTL
- **Fallback:** If the API is unreachable, hardcoded lists are used

Run `aigate rules update-popular` to force a refresh.
