FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install uv

# Copy project
COPY . .

# Install aigate in the container
RUN uv venv && uv pip install -e ".[dev]"

# Build synthetic packages
RUN .venv/bin/python tests/e2e/build_packages.py

# Default command: run E2E tests
CMD [".venv/bin/python", "-m", "pytest", "tests/e2e/", "-v", "--tb=short"]
