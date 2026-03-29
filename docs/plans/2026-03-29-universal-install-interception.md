# Universal Install Interception Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand aigate from intercepting only pip/npm to intercepting ALL package manager install commands, non-package vectors (curl|sh, docker), and AI agent-specific vectors (MCP servers, skills). Special focus on Flutter development workflow.

**Architecture:** The pretool-hook.sh script is the single interception point for all AI coding tools. It receives the command string via JSON stdin, parses it against patterns, and calls `aigate check` or `aigate scan`. Expanding coverage means adding more command patterns to the parser — no new infrastructure needed. For ecosystems without a dedicated resolver (cargo, gem, etc.), the hook runs `aigate check <name> --skip-ai` which uses the prefilter (typosquat + blocklist) without downloading source.

**Tech Stack:** Python 3.11+, zsh (pretool-hook.sh), regex patterns, existing aigate CLI.

**Research basis:**
- Gemini analysis: 25 install vectors across 3 categories
- Bright Data: pub.dev supply chain risks, Cargo CVE-2026-33056, Composer RAT campaign 2026/3
- Context7: Dart pub.dev package management
- ENISA Technical Advisory for Secure Use of Package Managers (Dec 2025)

---

## Complete Install Command Matrix

### Category A: Package Managers (already have or need resolver)

| Ecosystem | Commands to Intercept | Has Resolver | Priority |
|-----------|----------------------|:------------:|:--------:|
| PyPI | `pip install`, `pip3 install`, `uv pip install`, `uv add`, `python -m pip install` | ✅ | Done |
| npm | `npm install`, `npm i`, `yarn add`, `pnpm add`, `pnpm install` | ✅ | Done |
| pub.dev (Dart/Flutter) | `dart pub get`, `dart pub add`, `flutter pub get`, `flutter pub add` | ✅ | **Task 1** |
| Cargo (Rust) | `cargo add`, `cargo install` | ❌ new | **Task 2** |
| RubyGems | `gem install`, `bundle install`, `bundle add` | ❌ new | **Task 3** |
| Composer (PHP) | `composer require`, `composer install` | ❌ new | **Task 3** |
| Go | `go get`, `go install` | ❌ new | **Task 3** |
| NuGet (.NET) | `dotnet add package` | ❌ new | **Task 3** |
| Maven/Gradle (Java) | N/A (declarative, not CLI install) | ❌ | Low |
| CocoaPods | `pod install`, `pod update` | ❌ | **Task 1** (Flutter) |

### Category B: Non-Package Vectors

| Vector | Commands to Intercept | Priority |
|--------|----------------------|:--------:|
| Shell pipe | `curl ... \| sh`, `wget ... \| bash` | **Task 4** |
| Docker | `docker pull`, `docker run` (untrusted images) | **Task 5** |
| VSCode extensions | `code --install-extension` | **Task 5** |
| Git clone + build | `git clone` + `make`, `cmake` | Low |

### Category C: AI Agent Vectors

| Vector | Detection Method | Priority |
|--------|-----------------|:--------:|
| MCP server install | Check mcp.json / settings.json modifications | **Task 6** |
| Agent skill install | Scan skill .md files for `curl\|sh`, `exec`, `eval` | **Task 6** |
| Prompt injection via rules | Scan .cursorrules/.windsurfrules for injection patterns | **Task 6** |

---

## Task 1: Flutter Development Ecosystem (pub + cocoapods)

Flutter developers run these install commands constantly:
- `flutter pub get` / `flutter pub add <pkg>`
- `dart pub get` / `dart pub add <pkg>`
- `pod install` / `pod update` (iOS dependencies)
- `fvm install` (Flutter version, safe — skip)

**Files:**
- Modify: `scripts/pretool-hook.sh` (add dart/flutter/pod patterns)
- Modify: `src/aigate/hooks/pip_hook.py` → rename concept to be generic
- Create: `tests/unit/test_hook_flutter.py`

**Step 1: Add Flutter/Dart patterns to pretool-hook.sh**

In the Python parser section of pretool-hook.sh, add after the npm parser:

```python
# Dart/Flutter: dart pub add <pkg>, flutter pub add <pkg>
dart_m = re.search(
    r"(?:^|[;\s&|]+)(?:dart|flutter)\s+pub\s+(?:add|get)(?:\s+(.*))?$",
    cmd,
)
if dart_m:
    args = (dart_m.group(1) or "").strip()
    if not args or args.startswith("-"):
        # bare `flutter pub get` — scan pubspec.lock if exists
        if pathlib.Path("pubspec.lock").exists():
            emit({"mode": "scan", "ecosystem": "pub", "lockfile": "pubspec.lock"})
    else:
        # `flutter pub add http` — check specific package
        packages = [a for a in args.split() if not a.startswith("-")]
        if packages:
            emit({"mode": "check", "ecosystem": "pub", "packages": packages})
    sys.exit(0)

# CocoaPods: pod install, pod update
pod_m = re.search(r"(?:^|[;\s&|]+)pod\s+(?:install|update)", cmd)
if pod_m:
    if pathlib.Path("Podfile.lock").exists():
        emit({"mode": "scan", "ecosystem": "pub", "lockfile": "Podfile.lock"})
    sys.exit(0)
```

**Step 2: Write tests**

```python
# tests/unit/test_hook_flutter.py
def test_flutter_pub_add_detected():
    """flutter pub add http should emit check for 'http'"""
    ...

def test_flutter_pub_get_scans_lockfile():
    """bare flutter pub get should scan pubspec.lock"""
    ...

def test_dart_pub_add_detected():
    """dart pub add should work same as flutter pub add"""
    ...

def test_pod_install_scans_lockfile():
    """pod install should scan Podfile.lock"""
    ...

def test_fvm_install_ignored():
    """fvm install should NOT trigger aigate"""
    ...
```

**Step 3: Run tests & commit**

```bash
git commit -m "feat: intercept flutter pub/dart pub/pod install commands"
```

---

## Task 2: Cargo (Rust) Interception

Cargo has real attacks (CVE-2026-33056, build.rs exploits). `cargo add` and `cargo install` are the install commands.

**Files:**
- Modify: `scripts/pretool-hook.sh`
- Create: `tests/unit/test_hook_cargo.py`

**Step 1: Add Cargo patterns**

```python
# Cargo: cargo add <crate>, cargo install <crate>
cargo_m = re.search(
    r"(?:^|[;\s&|]+)cargo\s+(?:add|install)(?:\s+(.*))?$",
    cmd,
)
if cargo_m:
    args = (cargo_m.group(1) or "").strip()
    packages = []
    skip_next = False
    for tok in args.split():
        if skip_next:
            skip_next = False
            continue
        if tok in ("--git", "--path", "--registry", "--version", "--branch", "--tag", "--rev"):
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        packages.append(tok)
    if packages:
        emit({"mode": "check", "ecosystem": "cargo", "packages": packages})
    sys.exit(0)
```

**Step 2: Add "cargo" ecosystem to prefilter (typosquat only)**

Since we don't have a Cargo resolver yet, `aigate check <crate> -e cargo --skip-ai` will run prefilter only (blocklist + typosquat against popular Rust crates).

Add popular Rust crates to prefilter.py:

```python
POPULAR_CARGO: set[str] = {
    "serde", "tokio", "rand", "clap", "reqwest", "hyper", "axum",
    "actix-web", "diesel", "sqlx", "tracing", "anyhow", "thiserror",
    "chrono", "regex", "log", "env_logger", "serde_json", "futures",
    "async-trait", "bytes", "once_cell", "lazy_static",
}
```

**Step 3: Tests & commit**

```bash
git commit -m "feat: intercept cargo add/install with typosquat detection"
```

---

## Task 3: Ruby, PHP, Go, .NET Interception

Same pattern — add command patterns + popular package lists for typosquat.

**Files:**
- Modify: `scripts/pretool-hook.sh`
- Modify: `src/aigate/prefilter.py` (popular package lists)
- Create: `tests/unit/test_hook_multi_ecosystem.py`

**Commands to intercept:**

```python
# Ruby: gem install <gem>, bundle add <gem>
gem_m = re.search(r"(?:^|[;\s&|]+)(?:gem\s+install|bundle\s+(?:add|install))(?:\s+(.*))?$", cmd)

# PHP: composer require <pkg>, composer install
composer_m = re.search(r"(?:^|[;\s&|]+)composer\s+(?:require|install)(?:\s+(.*))?$", cmd)

# Go: go get <pkg>, go install <pkg>
go_m = re.search(r"(?:^|[;\s&|]+)go\s+(?:get|install)(?:\s+(.*))?$", cmd)

# .NET: dotnet add package <pkg>
dotnet_m = re.search(r"(?:^|[;\s&|]+)dotnet\s+add\s+(?:\S+\s+)?package(?:\s+(.*))?$", cmd)
```

**Popular package lists for typosquat:**

```python
POPULAR_GEM = {"rails", "rake", "bundler", "rspec", "puma", "sidekiq", "devise", "nokogiri", ...}
POPULAR_COMPOSER = {"laravel/framework", "symfony/console", "guzzlehttp/guzzle", "monolog/monolog", ...}
POPULAR_GO = {"github.com/gin-gonic/gin", "github.com/gorilla/mux", "google.golang.org/grpc", ...}
POPULAR_NUGET = {"Newtonsoft.Json", "Microsoft.Extensions.DependencyInjection", "Serilog", ...}
```

**Commit:**

```bash
git commit -m "feat: intercept gem/composer/go/dotnet install commands"
```

---

## Task 4: Shell Pipe Detection (curl | sh)

The most dangerous non-package vector. AI agents love suggesting `curl ... | sh`.

**Files:**
- Modify: `scripts/pretool-hook.sh`
- Create: `tests/unit/test_hook_shell_pipe.py`

**Step 1: Detect curl/wget pipe to shell**

```python
# Detect: curl ... | sh, curl ... | bash, wget ... | sh, wget -O- ... | bash
pipe_m = re.search(
    r"(?:curl|wget)\s+[^|]+\|\s*(?:ba)?sh",
    cmd,
)
if pipe_m:
    # Extract URL
    url_m = re.search(r"(?:curl|wget)\s+(?:-[^\s]*\s+)*(\S+)", cmd)
    url = url_m.group(1) if url_m else "unknown"
    emit({
        "mode": "warn",
        "reason": f"Piping remote script to shell is dangerous: {url}",
        "risk": "HIGH",
    })
```

The hook should WARN (not block) for curl|sh, since it's a common legitimate pattern. Let the user decide.

**Step 2: Tests & commit**

```bash
git commit -m "feat: warn on curl|sh and wget|bash pipe commands"
```

---

## Task 5: Docker & VSCode Extension Detection

**Files:**
- Modify: `scripts/pretool-hook.sh`
- Create: `tests/unit/test_hook_docker_vscode.py`

**Docker:**

```python
# docker pull/run from untrusted registry
docker_m = re.search(r"(?:^|[;\s&|]+)docker\s+(?:pull|run)\s+(\S+)", cmd)
if docker_m:
    image = docker_m.group(1)
    # Warn if not from known trusted registries
    trusted = ("gcr.io/", "ghcr.io/", "docker.io/library/", "mcr.microsoft.com/")
    if not any(image.startswith(t) for t in trusted):
        emit({"mode": "warn", "reason": f"Untrusted Docker image: {image}", "risk": "MEDIUM"})
```

**VSCode extensions:**

```python
# code --install-extension <id>
vscode_m = re.search(r"code\s+--install-extension\s+(\S+)", cmd)
if vscode_m:
    ext_id = vscode_m.group(1)
    emit({"mode": "warn", "reason": f"VSCode extension install: {ext_id}", "risk": "MEDIUM"})
```

**Commit:**

```bash
git commit -m "feat: warn on untrusted docker images and vscode extensions"
```

---

## Task 6: AI Agent Vector Detection

MCP servers, agent skills, and prompt injection via rules files.

**Files:**
- Create: `src/aigate/agent_scanner.py`
- Modify: `scripts/pretool-hook.sh`
- Create: `tests/unit/test_agent_scanner.py`

**Step 1: MCP server scanner**

When the hook detects modifications to MCP config files (`.claude/settings.json`, `.cursor/mcp.json`, etc.), scan the new MCP server entry for suspicious patterns:

```python
# agent_scanner.py
SUSPICIOUS_MCP_PATTERNS = [
    r"reverse.?shell",
    r"nc\s+-[elp]",          # netcat listeners
    r"\beval\b.*\bexec\b",
    r"curl.*\|\s*(?:ba)?sh",
    r"\.ssh/",
    r"\.aws/",
    r"\.env\b",
]

def scan_mcp_config(config_path: str) -> list[str]:
    """Scan MCP server config for suspicious patterns."""
    ...
```

**Step 2: Skill file scanner**

Scan .md skill files for embedded shell commands that look dangerous:

```python
def scan_skill_file(path: str) -> list[str]:
    """Scan agent skill .md for dangerous shell patterns."""
    # Look for code blocks containing curl|sh, eval, exec, reverse shells
    ...
```

**Step 3: Rules file injection scanner**

Scan .cursorrules/.windsurfrules for hidden prompt injection:

```python
def scan_rules_file(path: str) -> list[str]:
    """Scan AI rules files for hidden prompt injection."""
    # Look for: "ignore previous", "hardcode", "always use http://", hidden unicode
    ...
```

**Commit:**

```bash
git commit -m "feat: add AI agent vector scanning (MCP, skills, rules injection)"
```

---

## Task 7: Update Hook Response Format

Currently the hook only supports `check` and `scan` modes. Add `warn` mode for non-blocking alerts.

**Files:**
- Modify: `scripts/pretool-hook.sh` (handle warn mode)

The hook already returns `{"decision": "block"}` for malicious packages. Add:

```json
{"decision": "allow", "warning": "Piping remote script to shell is dangerous: https://example.com/install.sh"}
```

Claude Code shows warnings to the user without blocking the command.

**Commit:**

```bash
git commit -m "feat: add warn mode for non-blocking security alerts in hooks"
```

---

## Task 8: Tests & Documentation

**Files:**
- Update: `README.md` (supported ecosystems table)
- Update: `docs/ai-tool-integration.md` (new intercepted commands)
- Update: `docs/attack-detection.md` (new vectors)

**Commit:**

```bash
git commit -m "docs: update for universal install interception"
```

---

## Dependency Graph

```
Task 1 (Flutter/Dart/CocoaPods) ← independent
Task 2 (Cargo)                  ← independent
Task 3 (Ruby/PHP/Go/.NET)       ← independent
Task 4 (curl|sh)                ← independent
Task 5 (Docker/VSCode)          ← independent
Task 6 (AI agent vectors)       ← independent
Task 7 (Warn mode)              ← depends on Tasks 4,5,6 (uses warn)
Task 8 (Docs)                   ← depends on all
```

## Execution Order

1. **Tasks 1-6** in parallel (all independent, touch different parts of pretool-hook.sh)
   - But careful: all modify pretool-hook.sh, so do sequentially or merge carefully
2. **Task 7** after Tasks 4-6
3. **Task 8** last

## Flutter-Specific Coverage

| Command | What It Does | aigate Action |
|---------|-------------|---------------|
| `flutter pub get` | Resolve + download all deps | Scan `pubspec.lock` |
| `flutter pub add http` | Add specific package | Check `http` against pub.dev |
| `dart pub get` | Same as flutter pub get | Scan `pubspec.lock` |
| `pod install` | Install iOS CocoaPods deps | Scan `Podfile.lock` |
| `pod update` | Update CocoaPods deps | Scan `Podfile.lock` |
| `fvm install 3.29.0` | Install Flutter SDK version | **Skip** (safe) |
| `flutter build ios` | Build (runs pod install internally) | N/A (build, not install) |
