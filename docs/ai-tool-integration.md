# AI Tool Integration Guide

aigate can intercept `pip install` / `npm install` commands inside AI coding tools, blocking malicious packages before they execute.

## Automatic Setup

```bash
# Install hooks for all detected tools
aigate install-hooks --tool all

# Or specific tools
aigate install-hooks --tool claude --tool gemini
```

## Supported Tools

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
        "command": "./scripts/pretool-hook.sh",
        "timeout": 30,
        "statusMessage": "Scanning packages with aigate..."
      }]
    }]
  }
}
```

### Gemini CLI

**Hook type:** BeforeTool (matcher: run_shell_command)
**Config file:** `.gemini/settings.json`

```json
{
  "hooks": {
    "BeforeTool": [{
      "matcher": "run_shell_command",
      "hooks": [{
        "type": "command",
        "command": "./scripts/pretool-hook.sh",
        "timeout": 30
      }]
    }]
  }
}
```

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
| `pip install -r requirements.txt` | No (lockfile, not single package) |
| `pip install .` | No (local install) |
| `pip install --upgrade pip` | No (system package) |
| `npm install` | No (bare install, no package name) |

## Fail-Open Design

If aigate itself crashes or times out, the hook exits 0 (allow). Developer workflow is never blocked by aigate failures — only by confirmed malicious packages.
