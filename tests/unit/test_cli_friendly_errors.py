"""Tests for user-friendly CLI error messages (U2)."""

from __future__ import annotations

import json

import httpx
from click.testing import CliRunner

from aigate.cli import main
from aigate.config import Config


def test_missing_package_shows_friendly_message(monkeypatch):
    """aigate check nonexistent-xyz-pkg --skip-ai should show a user-friendly message."""
    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve(name, version, ecosystem):
        response = httpx.Response(404, request=httpx.Request("GET", "https://pypi.org/pypi/x/json"))
        raise httpx.HTTPStatusError("Not Found", request=response.request, response=response)

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve)

    result = CliRunner().invoke(main, ["check", "nonexistent-xyz-pkg", "--skip-ai"])
    assert result.exit_code == 3
    # Should NOT contain raw HTTP error class name
    assert "HTTPStatusError" not in result.output
    # Should contain a user-friendly "not found" message with the package name
    lower_out = result.output.lower()
    assert "not found" in lower_out
    assert "nonexistent-xyz-pkg" in lower_out


def test_missing_package_json_friendly(monkeypatch):
    """JSON mode should also show friendly error for missing packages."""
    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config())

    async def fake_resolve(name, version, ecosystem):
        response = httpx.Response(404, request=httpx.Request("GET", "https://pypi.org/pypi/x/json"))
        raise httpx.HTTPStatusError("Not Found", request=response.request, response=response)

    monkeypatch.setattr("aigate.cli.resolve_package", fake_resolve)

    result = CliRunner().invoke(main, ["check", "nonexistent-xyz-pkg", "--skip-ai", "--json"])
    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["decision"] == "error"
    # Must contain friendly "not found" with package name, not raw HTTP error
    assert "not found" in payload["error"].lower()
    assert "nonexistent-xyz-pkg" in payload["error"].lower()
