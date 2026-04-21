---
name: e2e
description: Run only the E2E test suite (no full 705-test unit battery). Two modes — Docker-sandboxed (scripts/run-e2e.sh) or direct pytest (tests/e2e/).
---

Use this when you want fast signal on E2E changes without running the full `pytest tests/` suite.

## Mode 1 — Docker sandbox (full isolation, matches CI)

```bash
cd "$CLAUDE_PROJECT_DIR"
./scripts/run-e2e.sh
```

Builds synthetic malicious packages, spins up `docker compose`, runs the suite inside a network-isolated container, and cleans up. Slower but matches CI.

## Mode 2 — Direct pytest (fast local iteration)

```bash
cd "$CLAUDE_PROJECT_DIR"
.venv/bin/python -m pytest tests/e2e/ -v
```

No Docker, no network isolation — only use when iterating on a specific E2E test and you've already verified Mode 1 works.

## When to use which

- **Before commits / PRs** → Mode 1 (matches CI).
- **Iterating on a single test** → Mode 2, then re-run Mode 1 before marking done.

## Reporting

Report: passed/failed counts, any failures with file:line, and total wall time. If Mode 1 fails but Mode 2 passes, that usually points at network isolation or fixture-build bugs — flag it explicitly.
