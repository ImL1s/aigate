"""Unit tests for aigate.sandbox.runtime_select."""
from __future__ import annotations

import pytest

from aigate.sandbox.errors import SandboxUnavailable
from aigate.sandbox.runtime_select import (
    detect_linux_connect_observer,
    select_backend,
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
