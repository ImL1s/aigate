---
name: release
description: Cut a new PyPI release — bump version in pyproject.toml, run scripts/publish.sh, tag, and hand off the final `uv publish` step to the user.
disable-model-invocation: true
---

Release flow for aigate. Ask the user for the new version first (e.g. `0.2.0`) — never pick it yourself.

## Steps

1. **Confirm target version** with the user. Current version lives in `pyproject.toml` under `[project] version`.

2. **Bump version** in `pyproject.toml`:
   ```bash
   # Edit pyproject.toml — change the `version = "X.Y.Z"` line only
   ```
   Nothing else is version-pinned; no other files need updating.

3. **Run the pre-publish check** (tests + lint + format + build):
   ```bash
   cd "$CLAUDE_PROJECT_DIR"
   ./scripts/publish.sh
   ```
   This runs pytest, ruff check, ruff format --check, and `uv build`. Stop on any failure — do not proceed.

4. **Commit and tag**:
   ```bash
   git add pyproject.toml
   git commit -m "release: vX.Y.Z"
   git tag "vX.Y.Z"
   ```

5. **Stop and hand off.** Report:
   - Build artifacts in `dist/`
   - The exact commands the user must run manually:
     ```bash
     git push && git push --tags
     uv publish --token $PYPI_TOKEN
     ```

Never run `uv publish` or `git push` yourself — the user owns those.
