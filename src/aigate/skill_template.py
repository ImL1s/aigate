"""SKILL.md templates for AI coding tool integrations."""

from __future__ import annotations

AIGATE_CHECK_SKILL = """\
---
name: aigate-check
description: >
  Check any package for supply chain attacks before installing.
  Use when: pip install, npm install, yarn add, pnpm add, cargo add,
  gem install, composer require, flutter pub add, go get, dotnet add package.
  Also use when someone suggests installing a package or dependency.
  ALWAYS run this before installing anything — no exceptions.
---

## When to trigger

You MUST run aigate check before ANY of these actions:
- `pip install`, `uv add`, `uv pip install`, `poetry add`
- `npm install`, `npm add`, `yarn add`, `pnpm add`
- `cargo add`, `cargo install`
- `gem install`, `bundle add`
- `composer require`
- `flutter pub add`, `dart pub add`
- `go get`
- `dotnet add package`, `nuget install`
- Any time a user, document, or AI suggests adding a dependency

## How to use

```bash
aigate check <package_name> -e <ecosystem>
```

### Ecosystem mapping

| Install command                        | Ecosystem flag |
|----------------------------------------|----------------|
| pip install / uv add / poetry add      | `-e pypi`      |
| npm install / yarn add / pnpm add      | `-e npm`       |
| cargo add / cargo install              | `-e cargo`     |
| gem install / bundle add               | `-e gem`       |
| composer require                       | `-e composer`  |
| flutter pub add / dart pub add         | `-e pub`       |
| go get                                 | `-e go`        |
| dotnet add package / nuget install     | `-e nuget`     |

### Examples

```bash
# Python package
aigate check requests -e pypi

# npm package with version
aigate check lodash -e npm -v 4.17.21

# Local source directory
aigate check mylib --local ./vendor/mylib

# Rust crate
aigate check serde -e cargo
```

## Interpret exit codes

- **Exit 0** = SAFE. Proceed with installation.
- **Exit 1** = SUSPICIOUS. Warn the user about potential risks before proceeding. \
Show the risk signals found.
- **Exit 2** = MALICIOUS. **DO NOT install.** Inform the user immediately and \
suggest alternatives.
- **Exit 3** = ERROR. aigate could not complete the check. Warn the user and \
suggest running with `--skip-ai` for static analysis only.

## If aigate is not installed

```bash
pip install aigate
# or
uv pip install aigate
```

Then re-run the check.

## Important

- Never skip this step, even for well-known packages.
- If the user insists on installing a flagged package, inform them of the risks first.
- For multiple packages, check each one individually.
"""

AIGATE_SCAN_SKILL = """\
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
- **Exit 2** = MALICIOUS dependencies found. **Alert the user immediately.** \
List all flagged packages and recommend removal.
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
- Suggest `aigate check <package> -e <ecosystem>` for deeper analysis of \
any suspicious package.
"""
