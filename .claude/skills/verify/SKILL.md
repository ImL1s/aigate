---
name: verify
description: Run lint, format check, and all tests to verify code quality before committing.
---

Run the following checks in order. Stop at the first failure:

```bash
cd "$CLAUDE_PROJECT_DIR"
.venv/bin/ruff format --check src/ tests/
.venv/bin/ruff check src/ tests/
.venv/bin/python -m pytest tests/ -v
```

Report: pass count, any failures with file:line, and total time.
