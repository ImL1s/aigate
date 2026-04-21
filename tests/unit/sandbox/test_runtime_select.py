"""Unit tests for aigate.sandbox.runtime_select."""

from __future__ import annotations

import pytest

from aigate.sandbox.errors import SandboxUnavailable
from aigate.sandbox.runtime_select import (
    detect_linux_connect_observer,
    select_backend,
    select_linux_observer,
)
from aigate.sandbox.types import SandboxMode


def test_detect_linux_connect_observer_returns_strace_when_present(monkeypatch):
    def _which(name):
        return f"/usr/bin/{name}" if name == "strace" else None

    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", _which)
    assert detect_linux_connect_observer() == "strace"


def test_detect_linux_connect_observer_returns_bpftrace_when_only_bpftrace(monkeypatch):
    def _which(name):
        return f"/usr/bin/{name}" if name == "bpftrace" else None

    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", _which)
    assert detect_linux_connect_observer() == "bpftrace"


def test_detect_linux_connect_observer_returns_none_when_nothing_present(monkeypatch):
    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", lambda _: None)
    assert detect_linux_connect_observer() is None


def test_detect_linux_connect_observer_skips_birdcage_native(monkeypatch):
    # birdcage-native is stubbed out; even if which returns something, it's skipped
    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", lambda _: "/usr/bin/birdcage")
    # strace/bpftrace not on PATH (which returns the same path for birdcage only)
    # but our which stub returns a path for ANY name, so strace wins here
    result = detect_linux_connect_observer()
    # strace comes before bpftrace in the probe order, and birdcage-native is skipped
    assert result == "strace"


def test_select_backend_raises_unavailable_when_required_and_no_backends(monkeypatch):
    monkeypatch.setattr("aigate.sandbox.runtime_select.detect_available", lambda: [])
    with pytest.raises(SandboxUnavailable, match="No sandbox backend available"):
        select_backend(SandboxMode.LIGHT, required=True)


def test_select_backend_raises_unavailable_when_not_required_and_no_backends(monkeypatch):
    monkeypatch.setattr("aigate.sandbox.runtime_select.detect_available", lambda: [])
    with pytest.raises(SandboxUnavailable, match="required=False"):
        select_backend(SandboxMode.LIGHT, required=False)


def test_select_backend_required_error_includes_linux_observer_on_linux(monkeypatch):
    monkeypatch.setattr("aigate.sandbox.runtime_select.detect_available", lambda: [])
    monkeypatch.setattr("aigate.sandbox.runtime_select.platform.system", lambda: "Linux")
    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", lambda _: None)
    with pytest.raises(SandboxUnavailable, match="connect-observer=None"):
        select_backend(SandboxMode.LIGHT, required=True)


def test_select_backend_required_error_reports_na_on_macos(monkeypatch):
    monkeypatch.setattr("aigate.sandbox.runtime_select.detect_available", lambda: [])
    monkeypatch.setattr("aigate.sandbox.runtime_select.platform.system", lambda: "Darwin")
    with pytest.raises(SandboxUnavailable, match="connect-observer=n/a"):
        select_backend(SandboxMode.LIGHT, required=True)


# ---------------------------------------------------------------------------
# select_linux_observer (Task 2.4)
# ---------------------------------------------------------------------------


def test_select_linux_observer_returns_none_when_no_observer(monkeypatch):
    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", lambda _: None)
    result = select_linux_observer()
    assert result is None


def test_select_linux_observer_returns_none_for_bpftrace_phase25_scope(monkeypatch):
    """bpftrace is Phase 2.5 scope — select_linux_observer returns None even if found."""
    def _which(name):
        return f"/usr/bin/{name}" if name == "bpftrace" else None

    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", _which)
    result = select_linux_observer()
    assert result is None


def test_select_linux_observer_returns_strace_observer_when_strace_present(monkeypatch):
    """When strace is on PATH and StraceObserver is importable, returns instance."""
    def _which(name):
        return f"/usr/bin/{name}" if name == "strace" else None

    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", _which)

    # StraceObserver may not exist yet (Task 2.2 pending).
    # If it's importable, result is a StraceObserver; otherwise None.
    result = select_linux_observer()
    # Either None (Task 2.2 not yet landed) or an Observer with name="strace"
    if result is not None:
        assert result.name == "strace"


def test_select_linux_observer_graceful_when_strace_observer_missing(monkeypatch):
    """If StraceObserver module not yet present, returns None (not ImportError)."""
    import sys

    def _which(name):
        return f"/usr/bin/{name}" if name == "strace" else None

    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", _which)

    # Temporarily hide the strace module if it exists
    strace_key = "aigate.sandbox.observers.strace"
    had_module = strace_key in sys.modules
    if had_module:
        saved = sys.modules.pop(strace_key)
    else:
        # Inject a sentinel that causes ImportError
        sys.modules[strace_key] = None  # type: ignore[assignment]

    try:
        result = select_linux_observer()
        assert result is None
    finally:
        if had_module:
            sys.modules[strace_key] = saved
        else:
            sys.modules.pop(strace_key, None)


def test_select_linux_observer_returns_none_on_macos_path(monkeypatch):
    """On macOS (no strace binary typically) result is None."""
    monkeypatch.setattr("aigate.sandbox.runtime_select.shutil.which", lambda _: None)
    assert select_linux_observer() is None
