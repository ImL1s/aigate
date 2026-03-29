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
# Tests (587 unit + 12 E2E, ~41s)
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

## E2E Tests

aigate has a Docker-based end-to-end test suite that runs detection against synthetic malicious packages in a network-isolated sandbox.

### Running E2E Tests

```bash
./scripts/run-e2e.sh
```

This builds synthetic packages, starts a local `pypiserver` in Docker, and runs the E2E test suite inside a container with `AIGATE_E2E=1`.

### Why E2E Tests Are Skipped in Normal Runs

E2E tests require Docker and are gated by the `AIGATE_E2E=1` environment variable. Running `pytest tests/` without this variable will **skip** all E2E tests automatically (via `tests/e2e/conftest.py`).

### Adding New Attack Fixtures

1. Create a new synthetic package directory under `tests/e2e/` with the malicious pattern you want to test
2. Add a build step in `tests/e2e/build_packages.py` to package it as a `.tar.gz`
3. Add a test case in `tests/e2e/test_e2e_detection.py` that asserts the expected verdict and risk signals
4. Run `./scripts/run-e2e.sh` to verify the fixture is detected correctly

### Docker Sandbox Architecture

- **pypiserver**: serves synthetic malicious packages on port 8080
- **runner**: installs aigate and runs `pytest tests/e2e/` with `AIGATE_E2E=1` and `AIGATE_E2E_PYPI_URL=http://pypi:8080/simple/`
- **Network isolation**: the runner cannot reach the internet, only the local PyPI server

## Code of Conduct

Be respectful and constructive. We follow the spirit of the
[Contributor Covenant](https://www.contributor-covenant.org/) -- treat
everyone with empathy, assume good intent, and focus on what is best for
the project.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
