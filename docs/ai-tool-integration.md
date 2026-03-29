# AI Tool Integration Guide

aigate can integrate with AI coding tools in two ways: LLM instructions (passive) and PreToolUse hooks (active interception).

---

## Mode 1: LLM Instructions (recommended)

The simplest integration. `aigate init` generates instruction files that teach LLMs to run `aigate check` before installing packages. No hooks, no config files — just a markdown instruction the LLM reads.

```bash
# Generate instruction files for all known tools
aigate instructions

# Generate for specific tools only
aigate instructions --tool claude
aigate instructions --tool gemini --tool cursor
```

### Generated Files

| Tool | File | Format |
|------|------|--------|
| Claude Code | `CLAUDE.md` | Append |
| Gemini CLI | `GEMINI.md` | Append |
| Codex CLI | `AGENTS.md` | Append |
| Cursor | `.cursorrules` | Append |
| Windsurf | `.windsurfrules` | Append |
| Cline | `.clinerules` | Append |
| GitHub Copilot | `.github/copilot-instructions.md` | Append |
| OpenCode | `CONVENTIONS.md` | Append |

Each file receives a `## Package Security (aigate)` section instructing the LLM to run `aigate check <package>` before any install command and interpret exit codes (0=safe, 1=suspicious, 2=malicious).

`aigate init` also generates these instruction files automatically when creating a new project config.

---

## Mode 2: PreToolUse Hooks

Active interception — hooks run before the AI tool executes shell commands, blocking malicious packages automatically.

### Automatic Setup

```bash
# Auto-detect installed tools and install hooks
# Note: --auto always includes file-based tools (cline, opencode)
# regardless of whether their binaries are detected
aigate install-hooks --auto

# Install hooks for all known tools
aigate install-hooks --tool all

# Or specific tools
aigate install-hooks --tool claude --tool gemini
```

### Supported Tools

### Claude Code

**Hook type:** PreToolUse (matcher: Bash)
**Config file:** `.claude/settings.json`

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "/absolute/path/to/scripts/pretool-hook.sh",
        "timeout": 30,
        "statusMessage": "aigate: scanning packages..."
      }]
    }]
  }
}
```

> **Note:** `aigate install-hooks` writes the resolved absolute path automatically. The example above is illustrative.

### Gemini CLI

**Hook type:** BeforeTool (matcher: run_shell_command)
**Config file:** `.gemini/settings.json`

```json
{
  "hooks": {
    "BeforeTool": [{
      "matcher": "run_shell_command",
      "sequential": true,
      "hooks": [{
        "type": "command",
        "command": "/absolute/path/to/scripts/pretool-hook.sh",
        "name": "aigate-package-validator",
        "timeout": 5000,
        "description": "Validates package installations via aigate"
      }]
    }]
  }
}
```

> **Note:** `aigate install-hooks` writes the resolved absolute path automatically.

### Codex CLI (OpenAI)

**Hook type:** PreToolUse (matcher: Bash)
**Config file:** `.codex/hooks.json`

### Cursor

**Hook type:** beforeShellExecution
**Config file:** `.cursor/hooks.json`

### Windsurf

**Hook type:** pre_run_command
**Config file:** `.windsurf/hooks.json`

### Aider

**Integration:** lint-cmd in `.aider.conf.yml`

```yaml
auto-lint: true
lint-cmd: "aigate scan requirements.txt --skip-ai"
```

### OpenCode

**Hook type:** Plugin (JavaScript)
**Config dir:** `.opencode/plugins/`

```bash
aigate install-hooks --tool opencode
```

This generates a JavaScript plugin in `.opencode/plugins/aigate-scanner.mjs` that intercepts shell commands containing `pip install` or `npm install`.

### Cline

**Hook type:** Rules file
**Config file:** `.clinerules`

```bash
aigate install-hooks --tool cline
```

This appends package security rules to `.clinerules`, instructing Cline to run `aigate check` before installing packages.

## How It Works

1. AI tool decides to run `pip install some-package`
2. PreToolUse hook fires before execution
3. Hook script extracts package name from the command
4. Runs `aigate check <package> --skip-ai` (fast, <2s)
5. If risk is HIGH/CRITICAL → outputs `{"decision": "block"}` → command blocked
6. If risk is low → silent pass → command proceeds normally

## What Gets Intercepted

| Command | Intercepted? |
|---------|-------------|
| `pip install requests` | Yes |
| `pip install requests==2.31.0` | Yes |
| `npm install express` | Yes |
| `yarn add react` | Yes |
| `pnpm add vue` | Yes |
| `pip install -r requirements.txt` | Yes (converted to `aigate scan`) |
| `pip install .` | No (local install) |
| `pip install --upgrade pip` | No (system package) |
| `npm install` | Yes (converted to `aigate scan` if a lockfile is found) |

## Fail-Open Design

If aigate itself crashes or times out, the hook exits 0 (allow). Developer workflow is never blocked by aigate failures — only by confirmed malicious packages.
