#!/usr/bin/env bash
set -euo pipefail

echo "=== aigate release ==="
echo "1. Running tests..."
python -m pytest tests/ -v --tb=short
echo ""
echo "2. Running linter..."
ruff check src/ tests/
echo ""
echo "3. Checking format..."
ruff format --check src/ tests/
echo ""
echo "4. Building..."
rm -rf dist/
uv build
echo ""
echo "5. Checking build..."
ls -la dist/
echo ""
echo "Ready to publish. Run:"
echo "  uv publish --token \$PYPI_TOKEN"
