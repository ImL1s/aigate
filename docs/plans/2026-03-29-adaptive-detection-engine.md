# Adaptive Detection Engine Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the hardcoded regex prefilter with an extensible rule engine that supports external YAML rules, auto-updating popular package lists, community-contributed patterns, and compound signal detection — inspired by GuardDog 2.0's Semgrep/YARA architecture.

**Architecture:** Rules are YAML files in `src/aigate/rules/` and `~/.aigate/rules/`. Each rule has a `pattern`, `severity`, `scope` (install_script/source/any), `ecosystem`, and `description`. The engine loads rules at startup, merges built-in + user + community rules, and applies them. Popular package lists are fetched from PyPI/npm APIs and cached locally. Compound detection combines multiple LOW signals in the same file to escalate risk.

**Tech Stack:** Python 3.11+, PyYAML (already a dep), httpx (already a dep) for API fetches.

**Research basis:**
- [GuardDog 2.0: YARA + Semgrep + BYO rules](https://securitylabs.datadoghq.com/articles/guarddog-2-0-release/)
- [apiiro/malicious-code-ruleset: community Semgrep rules](https://github.com/apiiro/malicious-code-ruleset)
- [Auto-generating YARA/Semgrep rules (arxiv)](https://arxiv.org/pdf/2504.17198)
- [How GuardDog was evaded](https://medium.com/@heyyoad/how-we-evaded-datadogs-malicious-package-detection-lessons-for-better-security-e8c9b185f97e)

---

## Task 1: YAML Rule Format and Loader

Define the rule format and build a loader that reads rules from YAML files.

**Files:**
- Create: `src/aigate/rules/__init__.py`
- Create: `src/aigate/rules/loader.py`
- Create: `src/aigate/rules/builtin/dangerous_patterns.yml`
- Create: `src/aigate/rules/builtin/credential_access.yml`
- Create: `src/aigate/rules/builtin/exfiltration.yml`
- Create: `src/aigate/rules/builtin/obfuscation.yml`
- Create: `src/aigate/rules/builtin/install_hooks.yml`
- Test: `tests/unit/test_rule_loader.py`

**Rule YAML format:**

```yaml
# src/aigate/rules/builtin/dangerous_patterns.yml
rules:
  - id: exec-call
    pattern: '\bexec\s*\('
    severity: medium  # low, medium, high, critical
    scope: any        # install_script, source, any
    ecosystem: "*"    # "*" = all, or "pypi", "npm", etc.
    description: "Dynamic code execution via exec()"
    tags: [execution, dynamic]

  - id: eval-call
    pattern: '\beval\s*\('
    severity: medium
    scope: any
    ecosystem: "*"
    description: "Dynamic code execution via eval()"
    tags: [execution, dynamic]

  - id: setup-py-exec
    pattern: '\bexec\s*\('
    severity: critical
    scope: install_script  # only HIGH when in setup.py/postinstall.js
    ecosystem: "*"
    description: "exec() in install script — runs at install time"
    tags: [execution, install-time]
```

**Loader:**

```python
# src/aigate/rules/loader.py
@dataclass
class Rule:
    id: str
    pattern: re.Pattern
    severity: str  # low, medium, high, critical
    scope: str     # install_script, source, any
    ecosystem: str # "*" or specific
    description: str
    tags: list[str]

def load_rules(
    builtin_dir: Path | None = None,
    user_dir: Path | None = None,
) -> list[Rule]:
    """Load rules from builtin + user directories. User rules override builtin by ID."""
    ...
```

**Key design decisions:**
- Same pattern can have different severity per scope (exec in source = medium, exec in setup.py = critical)
- `ecosystem: "*"` applies to all; `ecosystem: "npm"` only applies to npm packages
- User rules in `~/.aigate/rules/` override builtin by matching `id`
- Rules are plain YAML — anyone can contribute without writing Python

**TDD cycle:**
1. Write test: `load_rules()` from a test YAML file returns Rule objects with correct fields
2. Write test: user rules override builtin rules by ID
3. Write test: invalid YAML is skipped with warning, not crash
4. Write test: ecosystem filtering works (npm rule not applied to pypi package)
5. Implement loader
6. Commit: `feat: add YAML rule format and loader for detection engine`

---

## Task 2: Convert Hardcoded Patterns to YAML Rules

Migrate all 32 existing `DANGEROUS_PATTERNS` regexes from `prefilter.py` into YAML rule files.

**Files:**
- Create: `src/aigate/rules/builtin/dangerous_patterns.yml` (execution, subprocess, etc.)
- Create: `src/aigate/rules/builtin/credential_access.yml` (.ssh, .aws, .env, tokens)
- Create: `src/aigate/rules/builtin/exfiltration.yml` (requests.post, urllib, socket, DNS)
- Create: `src/aigate/rules/builtin/obfuscation.yml` (base64, marshal, compile+exec)
- Create: `src/aigate/rules/builtin/install_hooks.yml` (patterns specific to install scripts)
- Create: `src/aigate/rules/builtin/node_specific.yml` (child_process, Function, process.binding)
- Modify: `src/aigate/prefilter.py` (use rule engine instead of hardcoded list)
- Test: `tests/unit/test_rule_migration.py`

**Migration mapping (32 patterns → 6 YAML files):**

```
dangerous_patterns.yml:
  - eval, exec, __import__, subprocess, os.system, os.popen
  - compile+exec, importlib, getattr(os), ctypes, marshal.loads

credential_access.yml:
  - .ssh/, .aws/, .env (with quote prefix), .npmrc, .pypirc
  - GITHUB_TOKEN, NPM_TOKEN, PYPI_TOKEN, AWS_SECRET

exfiltration.yml:
  - requests.get/post, urllib.urlopen, httpx.get/post
  - socket.*connect, socket.getaddrinfo, socket.create_connection
  - dns.resolver

obfuscation.yml:
  - base64.b64decode
  - webbrowser.open (added in S1)

install_hooks.yml:
  - process.exit, os._exit, os.kill (protestware)

node_specific.yml:
  - child_process, process.binding, .constructor.constructor
  - new Function(
```

**TDD cycle:**
1. Write test: YAML rules produce identical signals to old hardcoded patterns (regression test)
2. Write test: each YAML file loads without errors
3. Convert patterns
4. Remove hardcoded `DANGEROUS_PATTERNS` list from prefilter.py
5. Wire rule engine into `check_dangerous_patterns()`
6. Run full test suite — all 587+ tests must pass
7. Commit: `refactor: migrate hardcoded patterns to YAML rules`

---

## Task 3: Auto-Updating Popular Package Lists

Fetch top packages from PyPI/npm APIs and cache locally instead of hardcoded sets.

**Files:**
- Create: `src/aigate/rules/popular_packages.py`
- Modify: `src/aigate/prefilter.py` (use dynamic lists)
- Test: `tests/unit/test_popular_packages.py`

**Data sources:**
- PyPI: `https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json` (free, no auth)
- npm: `https://api.npmjs.org/downloads/point/last-month` (or use registry search)
- Cache in `~/.aigate/cache/popular_packages.json` with 7-day TTL

**Implementation:**

```python
# src/aigate/rules/popular_packages.py
CACHE_FILE = Path.home() / ".aigate" / "cache" / "popular_packages.json"
CACHE_TTL_DAYS = 7

async def get_popular_packages(ecosystem: str) -> set[str]:
    """Get popular package names, from cache or API."""
    cached = _read_cache(ecosystem)
    if cached:
        return cached
    if ecosystem == "pypi":
        packages = await _fetch_pypi_top()
    elif ecosystem == "npm":
        packages = await _fetch_npm_top()
    else:
        return _get_builtin_fallback(ecosystem)
    _write_cache(ecosystem, packages)
    return packages

async def _fetch_pypi_top(count: int = 1000) -> set[str]:
    """Fetch top PyPI packages from hugovk's dataset."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
        )
        data = resp.json()
        return {row["project"] for row in data["rows"][:count]}
```

**Fallback:** If API is unreachable, use the current hardcoded lists as fallback. Never crash because of a failed API call.

**TDD cycle:**
1. Write test: `get_popular_packages("pypi")` returns a set with 1000+ names (mock API)
2. Write test: cache is used when fresh, API is called when stale
3. Write test: API failure falls back to hardcoded list
4. Write test: `aigate init` triggers a cache warm-up
5. Implement
6. Commit: `feat: auto-update popular package lists from PyPI/npm APIs`

---

## Task 4: Compound Signal Detection

Multiple LOW signals in the same file that combine execution + credential access + network should escalate to MEDIUM.

**Files:**
- Create: `src/aigate/rules/compound.py`
- Modify: `src/aigate/prefilter.py` (call compound detector after pattern scan)
- Test: `tests/unit/test_compound_detection.py`

**Compound rules:**

```python
COMPOUND_RULES = [
    {
        "id": "exec-plus-cred-theft",
        "description": "Code execution + credential file access in same file",
        "requires_all": ["execution", "credential_access"],
        "min_signals": 2,
        "escalate_to": "medium",
    },
    {
        "id": "exec-plus-exfiltration",
        "description": "Code execution + network exfiltration in same file",
        "requires_all": ["execution", "exfiltration"],
        "min_signals": 2,
        "escalate_to": "high",
    },
    {
        "id": "obfuscation-plus-exfiltration",
        "description": "Obfuscated code + network call in same file",
        "requires_all": ["obfuscation", "exfiltration"],
        "min_signals": 2,
        "escalate_to": "high",
    },
    {
        "id": "full-attack-chain",
        "description": "Execution + credential access + exfiltration",
        "requires_all": ["execution", "credential_access", "exfiltration"],
        "min_signals": 3,
        "escalate_to": "critical",
    },
]
```

**How it works:** After per-file pattern scanning, group signals by file. For each file, check if the signal tags satisfy any compound rule. If yes, add a compound signal with the escalated severity.

**This is the key improvement:** A single `subprocess` in regular source is LOW (normal library code). But `subprocess` + `.ssh/` + `requests.post` in the same file = HIGH (attack chain). This is exactly what the security review asked for.

**TDD cycle:**
1. Write test: subprocess + .ssh in same file → compound escalation to medium
2. Write test: subprocess alone in a file → no compound signal
3. Write test: exec + credential + exfil in same file → critical
4. Write test: signals in different files → no compound (file-scoped)
5. Implement
6. Wire into prefilter
7. Run full suite
8. Commit: `feat: compound signal detection for multi-indicator attack chains`

---

## Task 5: User Custom Rules (`~/.aigate/rules/`)

Let users add their own YAML rules without modifying aigate source.

**Files:**
- Modify: `src/aigate/rules/loader.py` (add user dir loading)
- Modify: `src/aigate/config.py` (add `rules_dir` config option)
- Create: `src/aigate/rules/user_rules_example.yml` (shipped as example)
- Test: `tests/unit/test_user_rules.py`

**Config:**

```yaml
# .aigate.yml
rules:
  user_rules_dir: ~/.aigate/rules/  # extra YAML rules to load
  disable_rules:  # opt-out specific rule IDs
    - eval-call   # disable if too noisy for your project
```

**TDD cycle:**
1. Write test: user rule overrides builtin by ID
2. Write test: `disable_rules` config skips specified rule IDs
3. Write test: user rules dir does not exist → no crash
4. Implement
5. Commit: `feat: user custom YAML rules and rule disable config`

---

## Task 6: `aigate rules` CLI Command

Add a CLI command to list, test, and manage rules.

**Files:**
- Modify: `src/aigate/cli.py`
- Test: `tests/unit/test_cli_rules.py`

**Commands:**

```bash
# List all loaded rules
aigate rules list

# Show rules by category
aigate rules list --tag execution

# Test a rule against a file
aigate rules test credential_access.yml ./suspicious_file.py

# Update popular package cache
aigate rules update-popular

# Show rule stats
aigate rules stats
```

**TDD cycle:**
1. Write test: `aigate rules list` outputs rule IDs and descriptions
2. Write test: `aigate rules update-popular` fetches and caches
3. Implement
4. Commit: `feat: add aigate rules CLI for rule management`

---

## Task 7: Documentation and Migration Guide

**Files:**
- Create: `docs/rules.md` (rule format reference, how to write custom rules)
- Modify: `docs/architecture.md` (add rules engine)
- Modify: `docs/attack-detection.md` (update with rule-based detection)
- Modify: `README.md` (mention extensible rules)

**Commit:** `docs: add rule engine documentation and migration guide`

---

## Dependency Graph

```
Task 1 (Rule format + loader)     ← foundation
Task 2 (Migrate patterns)         ← depends on Task 1
Task 3 (Auto-update popular)      ← independent
Task 4 (Compound detection)       ← depends on Task 2 (uses rule tags)
Task 5 (User custom rules)        ← depends on Task 1
Task 6 (CLI command)              ← depends on Tasks 1, 2, 3
Task 7 (Docs)                     ← depends on all
```

## Execution Order

1. **Task 1** (Rule format + loader)
2. **Tasks 2, 3** in parallel
3. **Tasks 4, 5** after Task 2
4. **Task 6** after Tasks 1-3
5. **Task 7** last

## Why This Matters

| Before | After |
|--------|-------|
| 32 hardcoded regex | Extensible YAML rules |
| Add pattern = code change + release | Add pattern = YAML file + no release |
| Popular lists: 36 PyPI packages | Popular lists: top 1000 from API |
| Same severity everywhere | Scope-aware (install_script vs source) |
| No compound detection | Attack chain detection (exec+cred+exfil) |
| No community rules | BYO rules in `~/.aigate/rules/` |
| Can't disable noisy rules | `disable_rules` config |
