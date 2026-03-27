# Contributing to aigate

Thanks for your interest in contributing! This guide covers the essentials.

## Getting Started

```bash
# Fork and clone
git clone https://github.com/<your-username>/aigate.git
cd aigate

# Set up dev environment
uv venv && uv pip install -e ".[dev]"
```

## Development Workflow

### Run tests and lint

```bash
# Tests (41+ tests, <1s)
.venv/bin/python -m pytest tests/ -v

# Lint
.venv/bin/ruff check src/ tests/

# Format
.venv/bin/ruff format src/ tests/
```

### TDD Required

We follow test-driven development. For every change:

1. Write a failing test first
2. Implement the minimal code to pass
3. Refactor if needed
4. Ensure all existing tests still pass

### Pull Request Process

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Use [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation only
   - `test:` adding or updating tests
   - `refactor:` code change that neither fixes a bug nor adds a feature
3. Ensure `ruff check` and `pytest` pass with zero errors
4. Open a PR against `main` with a clear description of *what* and *why*

### Code Style

- Python 3.11+, full type hints (`from __future__ import annotations`)
- Ruff enforced: line-length 100, rules E/F/I/N/W/UP
- Async everywhere: use `async def` + `httpx.AsyncClient`

## Code of Conduct

Be respectful and constructive. We follow the spirit of the
[Contributor Covenant](https://www.contributor-covenant.org/) -- treat
everyone with empathy, assume good intent, and focus on what is best for
the project.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
