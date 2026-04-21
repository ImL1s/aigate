"""Unit tests for ParserPartialDriftDetector (Phase 3 T8)."""

from __future__ import annotations

from aigate.sandbox.evasion.parser_partial_drift import ParserPartialDriftDetector
from aigate.sandbox.types import DynamicTrace, SandboxCoverage


def _trace(**kwargs) -> DynamicTrace:  # type: ignore[no-untyped-def]
    defaults: dict = dict(ran=True, runtime="birdcage")
    defaults.update(kwargs)
    return DynamicTrace(**defaults)


# ---------------------------------------------------------------------------
# Dynamic detection
# ---------------------------------------------------------------------------


def test_parser_drift_in_skipped_unexpected_fires_dynamic() -> None:
    """Trace with PARSER_PARTIAL_DRIFT in skipped_unexpected → ['parser_partial_drift']."""
    detector = ParserPartialDriftDetector()
    trace = _trace(skipped_unexpected={SandboxCoverage.PARSER_PARTIAL_DRIFT})
    result = detector.detect_dynamic(trace)
    assert result == ["parser_partial_drift"]


def test_clean_trace_no_signal() -> None:
    """Trace without drift → empty list."""
    detector = ParserPartialDriftDetector()
    trace = _trace()
    result = detector.detect_dynamic(trace)
    assert result == []


def test_other_unexpected_coverage_does_not_fire() -> None:
    """Only PARSER_PARTIAL_DRIFT triggers; other unexpected gaps do not."""
    detector = ParserPartialDriftDetector()
    trace = _trace(skipped_unexpected={SandboxCoverage.NETWORK_CAPTURE})
    result = detector.detect_dynamic(trace)
    assert result == []


# ---------------------------------------------------------------------------
# Static detection — always empty (drift is runtime only)
# ---------------------------------------------------------------------------


def test_static_always_empty() -> None:
    """detect_static returns [] regardless of source content."""
    detector = ParserPartialDriftDetector()
    source_files = {
        "setup.py": "import sys\nprint('26874 openat(AT_FDCWD, /etc/passwd, O_RDONLY) = 3')",
        "install.js": "process.stdout.write('strace-like output here')",
    }
    result = detector.detect_static(source_files)
    assert result == []


def test_static_empty_for_empty_source() -> None:
    """detect_static returns [] for empty source map."""
    detector = ParserPartialDriftDetector()
    assert detector.detect_static({}) == []
