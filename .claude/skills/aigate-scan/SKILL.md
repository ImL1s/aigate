---
name: aigate-scan
description: >
  Scan a lockfile or requirements file for supply chain attacks.
  Use when: reviewing requirements.txt, package-lock.json, Cargo.lock,
  Gemfile.lock, composer.lock, pubspec.lock, go.sum, yarn.lock, pnpm-lock.yaml.
  Also use when auditing project dependencies or onboarding to a new codebase.
  ALWAYS run this when you see a lockfile or dependency manifest.
---

## When to trigger

You MUST run aigate scan when you encounter or are asked to review:
- `requirements.txt`, `requirements/*.txt`, `Pipfile.lock`, `poetry.lock`
- `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- `Cargo.lock`
- `Gemfile.lock`
- `composer.lock`
- `pubspec.lock`
- `go.sum`
- Any dependency manifest or lockfile

Also trigger when:
- Onboarding to a new project / cloning a repo
- Reviewing a PR that modifies dependency files
- A user asks "are my dependencies safe?"

## How to use

```bash
aigate scan <lockfile>
```

### Examples

```bash
# Python
aigate scan requirements.txt
aigate scan poetry.lock

# Node.js
aigate scan package-lock.json
aigate scan yarn.lock

# Rust
aigate scan Cargo.lock

# Multiple files
aigate scan requirements.txt && aigate scan package-lock.json
```

## Interpret exit codes

- **Exit 0** = All dependencies are SAFE.
- **Exit 1** = Some dependencies are SUSPICIOUS. Show the flagged packages.
- **Exit 2** = MALICIOUS dependencies found. **Alert the user immediately.** List all flagged packages and recommend removal.
- **Exit 3** = ERROR. Could not complete the scan.

## If aigate is not installed

```bash
pip install aigate
# or
uv pip install aigate
```

Then re-run the scan.

## Important

- For large lockfiles, the scan may take a minute. This is normal.
- Report all flagged packages, not just the first one.
- Suggest `aigate check <package> -e <ecosystem>` for deeper analysis of any suspicious package.
