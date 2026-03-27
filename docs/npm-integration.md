# npm Integration

aigate can intercept `npm install`, `yarn add`, and `pnpm add` commands to scan packages before they are installed.

## Quick Start

```bash
# Install aigate (provides the aigate-npm command)
uv pip install -e ".[dev]"

# Use aigate-npm as a drop-in replacement
aigate-npm install express
aigate-npm install @angular/core@17 lodash@^4
```

## How It Works

`aigate-npm` sits in front of your package manager. When you run:

```
aigate-npm install some-package@1.2.3
```

It will:

1. Parse the package name(s) and version(s) from the command
2. Resolve each package from the npm registry
3. Download the tarball and run static analysis (pre-filter)
4. If suspicious, escalate to multi-model AI consensus analysis
5. **Block** the install if a package is deemed malicious (exit code 2)
6. **Proceed** with the real `npm install` if all packages pass

## Supported Package Managers

| Manager | Install commands intercepted |
|---------|----------------------------|
| npm     | `install`, `i`, `add`      |
| yarn    | `add`, `install`           |
| pnpm    | `add`, `install`, `i`      |

Pass the package manager name as the first argument if needed:

```bash
aigate-npm yarn add react react-dom
aigate-npm pnpm add -D typescript
```

By default, `aigate-npm` delegates to `npm`. If `yarn` or `pnpm` is detected as the first argument, it delegates to that instead.

## Integration with package.json

Add a `preinstall` script to your project so every `npm install` is gated automatically:

```json
{
  "scripts": {
    "preinstall": "npx aigate-npm check-lockfile || true"
  }
}
```

Or, for a stricter approach that blocks installs entirely:

```json
{
  "scripts": {
    "preinstall": "command -v aigate-npm >/dev/null 2>&1 && echo 'Use aigate-npm instead of npm install directly' && exit 1 || true"
  }
}
```

## Integration with .npmrc

You can configure npm to always ignore lifecycle scripts from third-party packages (recommended security baseline) and rely on aigate for the security gate:

```ini
# .npmrc (project or global)
ignore-scripts=true
```

Then use `aigate-npm install <pkg>` which:
1. Scans the package via aigate
2. Runs `npm install <pkg>` (which respects `ignore-scripts=true` from .npmrc)

This gives you defense-in-depth: aigate catches malicious packages, and `ignore-scripts` prevents any that slip through from executing lifecycle scripts.

## Shell Alias (Optional)

For convenience, alias your package manager in your shell profile:

```bash
# ~/.zshrc or ~/.bashrc
alias npm='aigate-npm'
alias yarn='aigate-npm yarn'
alias pnpm='aigate-npm pnpm'
```

## CI/CD Integration

In a CI pipeline, install aigate and use it as the install command:

```yaml
# GitHub Actions example
- name: Install dependencies (with security gate)
  run: |
    pip install aigate
    aigate-npm install
```

## Configuration

aigate-npm shares the same `.aigate.yml` configuration file as the main `aigate` CLI. Key settings for npm:

```yaml
# .aigate.yml
ecosystems:
  - npm

whitelist:
  - react
  - express
  - typescript

blocklist:
  - known-malicious-pkg
```

See the main [README](../README.md) for full configuration options.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | All packages safe, install proceeded |
| 1    | Suspicious packages (warning only) |
| 2    | Malicious package blocked, install aborted |

## How It Differs from `--ignore-scripts`

| Feature | `ignore-scripts` | `aigate-npm` |
|---------|------------------|--------------|
| Blocks lifecycle scripts | Yes | N/A (delegates to npm) |
| Detects typosquatting | No | Yes |
| Detects obfuscated code | No | Yes |
| AI-powered analysis | No | Yes |
| Blocks before download | No | Yes (blocks before real install) |

For maximum security, use both together.
