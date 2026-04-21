"""Tests for select_linux_observer() integration with Observer ABC (Task 2.4).

Focused on the bridge between runtime_select and the Observer hierarchy:
- select_linux_observer() returns an Observer instance (or None gracefully).
- The returned Observer satisfies the ABC contract from Task 2.1.
- strace-present path yields an Observer with name="strace" and sink_kind="fifo".
- bpftrace-present path returns None (Phase 2.5 scope).
- No-observer path returns None without raising.
"""

from __future__ import annotations

import sys

import pytest

from aigate.sandbox.runtime_select import select_linux_observer

# ---------------------------------------------------------------------------
# No observer available
# ---------------------------------------------------------------------------


def test_returns_none_when_no_binary_present(monkeypatch) -> None:
    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", lambda _: None)
    assert select_linux_observer() is None


def test_returns_none_for_bpftrace_only(monkeypatch) -> None:
    """bpftrace is Phase 2.5 — select_linux_observer always returns None for it."""

    def _which(name: str) -> str | None:
        return "/usr/bin/bpftrace" if name == "bpftrace" else None

    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", _which)
    assert select_linux_observer() is None


# ---------------------------------------------------------------------------
# strace present path
# ---------------------------------------------------------------------------


def test_returns_none_gracefully_when_strace_module_missing(monkeypatch) -> None:
    """If StraceObserver is not yet importable (Task 2.2 not landed), returns None."""

    def _which(name: str) -> str | None:
        return "/usr/bin/strace" if name == "strace" else None

    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", _which)

    strace_key = "aigate.sandbox.observers.strace"
    had_module = strace_key in sys.modules
    saved = sys.modules.get(strace_key)
    # Block import so ImportError is triggered inside select_linux_observer
    sys.modules[strace_key] = None  # type: ignore[assignment]

    try:
        result = select_linux_observer()
        assert result is None
    finally:
        if had_module and saved is not None:
            sys.modules[strace_key] = saved
        else:
            sys.modules.pop(strace_key, None)


def test_strace_observer_satisfies_abc_contract_when_importable(monkeypatch) -> None:
    """If StraceObserver is importable, the returned instance satisfies Observer ABC."""
    from aigate.sandbox.observers.base import Observer

    def _which(name: str) -> str | None:
        return "/usr/bin/strace" if name == "strace" else None

    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", _which)

    result = select_linux_observer()

    if result is None:
        pytest.skip("StraceObserver not yet available (Task 2.2 pending)")

    # ABC contract checks
    assert isinstance(result, Observer)
    assert result.name == "strace"
    assert result.sink_kind == "fifo"
    assert isinstance(result.coverage, frozenset)
    assert isinstance(result.check_available(), bool)


# ---------------------------------------------------------------------------
# Return type is always Observer | None — never raises
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "which_fn",
    [
        lambda _: None,
        lambda n: "/usr/bin/strace" if n == "strace" else None,
        lambda n: "/usr/bin/bpftrace" if n == "bpftrace" else None,
    ],
    ids=["no-observer", "strace", "bpftrace"],
)
def test_never_raises_regardless_of_which(monkeypatch, which_fn) -> None:
    """select_linux_observer() must never raise — always Observer | None."""
    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", which_fn)

    # Also block strace import to exercise the graceful fallback path
    strace_key = "aigate.sandbox.observers.strace"
    had_module = strace_key in sys.modules
    saved = sys.modules.get(strace_key)
    sys.modules[strace_key] = None  # type: ignore[assignment]

    try:
        result = select_linux_observer()
        assert result is None or hasattr(result, "name")
    finally:
        if had_module and saved is not None:
            sys.modules[strace_key] = saved
        else:
            sys.modules.pop(strace_key, None)
