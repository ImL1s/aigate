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
- **Exit 1** = SUSPICIOUS. Warn the user about potential risks before proceeding. Show the risk signals found.
- **Exit 2** = MALICIOUS. **DO NOT install.** Inform the user immediately and suggest alternatives.
- **Exit 3** = ERROR. aigate could not complete the check. Warn the user and suggest running with `--skip-ai` for static analysis only.

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
