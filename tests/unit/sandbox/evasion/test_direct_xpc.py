"""Unit tests for DirectXPCDetector (Phase 3 T6)."""

from __future__ import annotations

import pathlib

import pytest

from aigate.models import RiskLevel
from aigate.sandbox.evasion.direct_xpc import DirectXPCDetector
from aigate.sandbox.types import DynamicTrace, DynamicTraceEvent

FIXTURE_DIR = (
    pathlib.Path(__file__).parent.parent.parent.parent / "fixtures" / "evasion" / "direct_xpc"
)


def _load(name: str) -> str:
    return (FIXTURE_DIR / name).read_text()


@pytest.fixture()
def detector() -> DirectXPCDetector:
    return DirectXPCDetector()


# ---------------------------------------------------------------------------
# Positive fixtures — detector MUST fire
# ---------------------------------------------------------------------------


def test_pos_1_xpc_connection_create_mach_service(detector: DirectXPCDetector) -> None:
    signals = detector.detect_static({"pos_1.m": _load("pos_1.m")})
    assert len(signals) >= 1
    assert all(s.category == "direct_xpc" for s in signals)
    assert all(s.severity == RiskLevel.MEDIUM for s in signals)


def test_pos_2_nsxpcconnection_swift(detector: DirectXPCDetector) -> None:
    signals = detector.detect_static({"pos_2.swift": _load("pos_2.swift")})
    assert len(signals) >= 1
    assert all(s.category == "direct_xpc" for s in signals)
    assert all(s.severity == RiskLevel.MEDIUM for s in signals)


def test_pos_3_dbus_session_bus(detector: DirectXPCDetector) -> None:
    signals = detector.detect_static({"pos_3.py": _load("pos_3.py")})
    assert len(signals) >= 1
    assert all(s.category == "direct_xpc" for s in signals)
    assert all(s.severity == RiskLevel.MEDIUM for s in signals)


# ---------------------------------------------------------------------------
# Mutation fixtures
# ---------------------------------------------------------------------------


def test_pos_mutation_whitespace_fires(detector: DirectXPCDetector) -> None:
    """Regex handles extra whitespace — xpc_connection_create_mach_service with spaces."""
    signals = detector.detect_static({"ws.m": _load("pos_mutation_whitespace.m")})
    assert len(signals) >= 1, "expected signal for whitespace variant"
    assert signals[0].category == "direct_xpc"


def test_pos_mutation_concat_is_documented_limitation(detector: DirectXPCDetector) -> None:
    """Concatenated D-Bus call ('dbus.' + 'SessionBus()') is NOT caught by regex.

    This is a documented limitation: the static regex cannot resolve string
    concatenation.  An AST-aware pass will handle this in a future phase.
    This test asserts the CURRENT behaviour (zero signals) so any unintentional
    change is caught.
    """
    signals = detector.detect_static({"concat.py": _load("pos_mutation_concat.py")})
    # Intentionally zero — regex can't see through string concat.
    assert signals == [], (
        "If this assertion fails, the regex has become AST-aware; "
        "remove the xfail note and promote to a positive assertion."
    )


# ---------------------------------------------------------------------------
# Negative fixtures — detector MUST NOT fire
# ---------------------------------------------------------------------------


def test_neg_1_comment_only_is_silent(detector: DirectXPCDetector) -> None:
    signals = detector.detect_static({"neg_1.py": _load("neg_1.py")})
    assert signals == []


def test_neg_2_string_literal_reference_is_silent(detector: DirectXPCDetector) -> None:
    signals = detector.detect_static({"neg_2.js": _load("neg_2.js")})
    assert signals == []


def test_neg_3_unused_import_is_silent(detector: DirectXPCDetector) -> None:
    signals = detector.detect_static({"neg_3.py": _load("neg_3.py")})
    assert signals == []


def test_neg_real_electron_is_silent(detector: DirectXPCDetector) -> None:
    """Real-world Electron-style source (no raw XPC calls) produces no signals."""
    signals = detector.detect_static({"neg_real_electron.js": _load("neg_real_electron.js")})
    assert signals == []


# ---------------------------------------------------------------------------
# Dynamic detection
# ---------------------------------------------------------------------------


def test_detect_dynamic_dbus_connect_fires(detector: DirectXPCDetector) -> None:
    """connect event targeting /run/dbus/system_bus_socket triggers the category."""
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        events=[
            DynamicTraceEvent(
                kind="connect",
                ts_ms=0,
                pid=1,
                process="python",
                target="/run/dbus/system_bus_socket",
            )
        ],
    )
    result = detector.detect_dynamic(trace)
    assert result == ["direct_xpc"]


def test_detect_dynamic_no_dbus_returns_empty(detector: DirectXPCDetector) -> None:
    trace = DynamicTrace(
        ran=True,
        runtime="birdcage",
        events=[
            DynamicTraceEvent(
                kind="connect",
                ts_ms=0,
                pid=1,
                process="python",
                target="/run/user/1000/pulse/native",
            )
        ],
    )
    result = detector.detect_dynamic(trace)
    assert result == []


def test_detect_dynamic_empty_trace_returns_empty(detector: DirectXPCDetector) -> None:
    trace = DynamicTrace(ran=True, runtime="birdcage")
    result = detector.detect_dynamic(trace)
    assert result == []


# ---------------------------------------------------------------------------
# Multiple files — signals tagged with correct path
# ---------------------------------------------------------------------------


def test_multiple_files_signals_reference_correct_paths(detector: DirectXPCDetector) -> None:
    source_files = {
        "evil.m": _load("pos_1.m"),
        "clean.py": _load("neg_1.py"),
        "ipc.py": _load("pos_3.py"),
    }
    signals = detector.detect_static(source_files)
    described_paths = {s.description.split(" in ")[1] for s in signals}
    assert "evil.m" in described_paths
    assert "ipc.py" in described_paths
    assert "clean.py" not in described_paths
