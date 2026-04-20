"""Unit tests for aigate.sandbox.errors.

Locks the exception hierarchy so policy code can ``except SandboxError``
and catch every sandbox failure mode without listing them individually.
"""

from __future__ import annotations

import pytest

from aigate.sandbox import (
    SandboxError,
    SandboxEscape,
    SandboxTimeout,
    SandboxUnavailable,
)


@pytest.mark.parametrize(
    "cls",
    [SandboxUnavailable, SandboxTimeout, SandboxEscape],
)
def test_every_sandbox_exception_inherits_from_base(cls: type[Exception]):
    assert issubclass(cls, SandboxError)
    # Must also be a real Exception — not a SystemExit / BaseException
    # subclass — so ``except Exception`` in CLI code still catches them.
    assert issubclass(cls, Exception)


def test_raise_and_catch_as_base():
    for cls in (SandboxUnavailable, SandboxTimeout, SandboxEscape):
        with pytest.raises(SandboxError):
            raise cls("boom")


def test_exception_message_roundtrip():
    err = SandboxTimeout("sandbox exceeded 60s budget")
    assert str(err) == "sandbox exceeded 60s budget"


def test_distinct_subclasses_are_not_conflated():
    # ``isinstance`` narrowing must still work — a SandboxTimeout
    # must NOT be caught by ``except SandboxEscape``.
    err = SandboxTimeout("timeout")
    assert isinstance(err, SandboxTimeout)
    assert not isinstance(err, SandboxEscape)
    assert not isinstance(err, SandboxUnavailable)
