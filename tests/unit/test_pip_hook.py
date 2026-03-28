"""Tests for the pip install hook wrapper."""

import pytest

from aigate.hooks import pip_hook


def test_pip_wrapper_bypasses_with_no_aigate(monkeypatch):
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        pip_hook.sys,
        "argv",
        ["aigate-pip", "install", "--no-aigate", "requests"],
    )
    monkeypatch.setattr(
        pip_hook,
        "_passthrough_pip",
        lambda args: seen.update({"args": args}),
    )
    monkeypatch.setattr(
        pip_hook.asyncio,
        "run",
        lambda _: pytest.fail("pip_wrapper should bypass without invoking aigate"),
    )

    pip_hook.pip_wrapper()

    assert seen == {"args": ["install", "requests"]}
