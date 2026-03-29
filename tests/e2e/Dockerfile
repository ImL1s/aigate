FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project
COPY . .

# Install aigate using system Python (no venv needed in container)
RUN uv pip install --system -e ".[dev]"

# Build synthetic packages
RUN python tests/e2e/build_packages.py

# Default command: run E2E tests
CMD ["python", "-m", "pytest", "tests/e2e/", "-v", "--tb=short"]
