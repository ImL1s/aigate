#!/usr/bin/env bash
# scripts/run-e2e.sh — Run E2E tests in Docker sandbox
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
E2E_DIR="$PROJECT_DIR/tests/e2e"

echo "=== aigate E2E Sandbox Tests ==="
echo ""

# Step 1: Build synthetic packages (needed for pypiserver volume)
echo "1. Building synthetic malicious packages..."
cd "$PROJECT_DIR"
.venv/bin/python tests/e2e/build_packages.py
echo ""

# Step 2: Build and run Docker containers
echo "2. Starting Docker sandbox..."
cd "$E2E_DIR"
docker compose build --quiet
echo ""

echo "3. Running E2E tests (network-isolated)..."
docker compose run --rm runner
EXIT_CODE=$?

# Step 3: Cleanup
echo ""
echo "4. Cleaning up..."
docker compose down --volumes --remove-orphans 2>/dev/null

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "=== All E2E tests passed ==="
else
    echo ""
    echo "=== E2E tests FAILED (exit $EXIT_CODE) ==="
fi

exit $EXIT_CODE
