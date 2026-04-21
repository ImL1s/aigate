"""Unit tests for BuildHooksDetector (Phase 3 T4)."""

from __future__ import annotations

from aigate.models import RiskLevel
from aigate.sandbox.evasion.build_hooks import BuildHooksDetector
from aigate.sandbox.types import DynamicTrace, DynamicTraceEvent

# ---------------------------------------------------------------------------
# Fixtures helpers
# ---------------------------------------------------------------------------

FIXTURE_DIR = __file__[: __file__.rfind("tests/unit")] + "tests/fixtures/evasion/build_hooks"


def _load(filename: str) -> str:
    with open(f"{FIXTURE_DIR}/{filename}") as f:
        return f.read()


def _make_trace(*events: DynamicTraceEvent) -> DynamicTrace:
    return DynamicTrace(ran=True, runtime="test", events=list(events))


def _exec_event(target: str = "") -> DynamicTraceEvent:
    return DynamicTraceEvent(kind="exec", ts_ms=0, pid=1, process="node", target=target)


def _connect_event() -> DynamicTraceEvent:
    return DynamicTraceEvent(kind="connect", ts_ms=1, pid=1, process="node", target="evil.io:80")


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------


def test_instantiation() -> None:
    d = BuildHooksDetector()
    assert d.CATEGORY == "build_hooks"
    assert d.SEVERITY == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Static — positive cases
# ---------------------------------------------------------------------------


def test_static_pos1_postinstall_package_json() -> None:
    """Detects postinstall hook in package.json."""
    d = BuildHooksDetector()
    content = _load("pos_1_package.json")
    signals = d.detect_static({"package.json": content})
    assert len(signals) == 1
    assert signals[0].category == "build_hooks"
    assert "postinstall" in signals[0].description


def test_static_pos2_setup_py_subprocess() -> None:
    """Detects subprocess.run in setup.py."""
    d = BuildHooksDetector()
    content = _load("pos_2_setup.py")
    signals = d.detect_static({"setup.py": content})
    assert len(signals) == 1
    assert "setup.py" in signals[0].description


def test_static_pos3_build_rs() -> None:
    """Detects presence of Rust build.rs."""
    d = BuildHooksDetector()
    content = _load("pos_3_build.rs")
    signals = d.detect_static({"build.rs": content})
    assert len(signals) == 1
    assert "build.rs" in signals[0].description


def test_static_pos_mutation_whitespace_package_json() -> None:
    """Detects postinstall even with extra whitespace in JSON."""
    d = BuildHooksDetector()
    content = _load("pos_mutation_whitespace_package.json")
    signals = d.detect_static({"package.json": content})
    assert len(signals) == 1
    assert "postinstall" in signals[0].description


def test_static_pos_mutation_preinstall_package_json() -> None:
    """Detects preinstall hook (different lifecycle key)."""
    d = BuildHooksDetector()
    content = _load("pos_mutation_preinstall_package.json")
    signals = d.detect_static({"package.json": content})
    assert len(signals) == 1
    assert "preinstall" in signals[0].description


# ---------------------------------------------------------------------------
# Static — negative cases
# ---------------------------------------------------------------------------


def test_static_neg1_safe_scripts() -> None:
    """No signal for test/build scripts without lifecycle hooks."""
    d = BuildHooksDetector()
    content = _load("neg_1_package.json")
    signals = d.detect_static({"package.json": content})
    assert signals == []


def test_static_neg2_setup_py_no_subprocess() -> None:
    """No signal for setup.py that doesn't call subprocess."""
    d = BuildHooksDetector()
    content = _load("neg_2_setup.py")
    signals = d.detect_static({"setup.py": content})
    assert signals == []


def test_static_neg3_text_file() -> None:
    """No signal for a plain text file."""
    d = BuildHooksDetector()
    content = _load("neg_3.txt")
    signals = d.detect_static({"README.txt": content})
    assert signals == []


def test_static_neg_real_npm_left_pad() -> None:
    """No signal for left-pad package.json (only test script)."""
    d = BuildHooksDetector()
    content = _load("neg_real_npm_package.json")
    signals = d.detect_static({"package.json": content})
    assert signals == []


# ---------------------------------------------------------------------------
# Static — path key matters (setup.py vs other .py)
# ---------------------------------------------------------------------------


def test_static_subprocess_in_non_setup_py_is_ignored() -> None:
    """subprocess.run in a non-setup.py file is not flagged by this detector."""
    d = BuildHooksDetector()
    signals = d.detect_static({"utils.py": "subprocess.run(['ls'])"})
    assert signals == []


def test_static_invalid_json_package_json_skipped() -> None:
    """Invalid JSON in package.json does not raise — just skipped."""
    d = BuildHooksDetector()
    signals = d.detect_static({"package.json": "{broken json"})
    assert signals == []


# ---------------------------------------------------------------------------
# Static — severity
# ---------------------------------------------------------------------------


def test_static_severity_is_medium() -> None:
    """All static build_hooks signals are MEDIUM severity."""
    d = BuildHooksDetector()
    content = _load("pos_1_package.json")
    signals = d.detect_static({"package.json": content})
    assert all(s.severity == RiskLevel.MEDIUM for s in signals)


# ---------------------------------------------------------------------------
# Dynamic — positive (exec postinstall + connect)
# ---------------------------------------------------------------------------


def test_dynamic_exec_postinstall_with_connect_returns_category() -> None:
    """Returns category when postinstall exec + connect both present."""
    d = BuildHooksDetector()
    trace = _make_trace(
        _exec_event(target="npm run postinstall"),
        _connect_event(),
    )
    result = d.detect_dynamic(trace)
    assert result == ["build_hooks"]


# ---------------------------------------------------------------------------
# Dynamic — negative
# ---------------------------------------------------------------------------


def test_dynamic_exec_postinstall_without_connect_returns_empty() -> None:
    """No connect → no escalation."""
    d = BuildHooksDetector()
    trace = _make_trace(_exec_event(target="npm run postinstall"))
    assert d.detect_dynamic(trace) == []


def test_dynamic_connect_without_postinstall_exec_returns_empty() -> None:
    """Connect without postinstall exec → no escalation."""
    d = BuildHooksDetector()
    trace = _make_trace(_connect_event())
    assert d.detect_dynamic(trace) == []


def test_dynamic_empty_trace_returns_empty() -> None:
    """Empty trace → no escalation."""
    d = BuildHooksDetector()
    trace = _make_trace()
    assert d.detect_dynamic(trace) == []


def test_dynamic_non_postinstall_exec_with_connect_returns_empty() -> None:
    """Exec event not related to postinstall + connect → no escalation."""
    d = BuildHooksDetector()
    trace = _make_trace(
        _exec_event(target="npm run test"),
        _connect_event(),
    )
    assert d.detect_dynamic(trace) == []
