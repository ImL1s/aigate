"""Unit tests for EnvMutationDetector (Phase 3 T2)."""

from __future__ import annotations

import pathlib

import pytest

from aigate.models import RiskLevel
from aigate.sandbox.evasion.env_mutation import EnvMutationDetector

FIXTURE_DIR = (
    pathlib.Path(__file__).parent.parent.parent.parent / "fixtures" / "evasion" / "env_mutation"
)


def _load(name: str) -> str:
    return (FIXTURE_DIR / name).read_text()


@pytest.fixture()
def detector() -> EnvMutationDetector:
    return EnvMutationDetector()


# ---------------------------------------------------------------------------
# Positive fixtures — detector MUST fire
# ---------------------------------------------------------------------------


def test_pos_1_ssh_auth_sock(detector: EnvMutationDetector) -> None:
    signals = detector.detect_static({"pos_1.py": _load("pos_1.txt")})
    assert len(signals) >= 1
    assert all(s.category == "env_mutation" for s in signals)
    assert all(s.severity == RiskLevel.HIGH for s in signals)


def test_pos_2_ld_preload(detector: EnvMutationDetector) -> None:
    signals = detector.detect_static({"pos_2.py": _load("pos_2.txt")})
    assert len(signals) >= 1
    assert all(s.category == "env_mutation" for s in signals)
    assert all(s.severity == RiskLevel.HIGH for s in signals)


def test_pos_3_aws_secret(detector: EnvMutationDetector) -> None:
    signals = detector.detect_static({"pos_3.py": _load("pos_3.txt")})
    assert len(signals) >= 1
    assert all(s.category == "env_mutation" for s in signals)
    assert all(s.severity == RiskLevel.HIGH for s in signals)


# ---------------------------------------------------------------------------
# Mutation fixtures
# ---------------------------------------------------------------------------


def test_pos_mutation_whitespace_fires(detector: EnvMutationDetector) -> None:
    """Regex handles extra whitespace around the assignment operator."""
    signals = detector.detect_static({"ws.py": _load("pos_mutation_whitespace.txt")})
    assert len(signals) >= 1, "expected signal for whitespace variant"
    assert signals[0].category == "env_mutation"


def test_pos_mutation_concat_is_documented_limitation(detector: EnvMutationDetector) -> None:
    """Concatenated key ('LD_' + 'PRELOAD') is NOT caught by the simple regex.

    This is a documented limitation: the static regex detector cannot resolve
    string concatenation.  An AST-aware detector will handle this in a future
    phase.  This test asserts the CURRENT behaviour (zero signals) so that any
    unintentional change is caught.
    """
    signals = detector.detect_static({"concat.py": _load("pos_mutation_concat.txt")})
    # Intentionally zero — regex can't see through string concat.
    assert signals == [], (
        "If this assertion fails, the regex has become AST-aware; "
        "remove the xfail note and promote to a positive assertion."
    )


# ---------------------------------------------------------------------------
# Negative fixtures — detector MUST NOT fire
# ---------------------------------------------------------------------------


def test_neg_1_env_get_is_silent(detector: EnvMutationDetector) -> None:
    signals = detector.detect_static({"neg_1.py": _load("neg_1.txt")})
    assert signals == []


def test_neg_2_read_in_dict_literal_is_silent(detector: EnvMutationDetector) -> None:
    signals = detector.detect_static({"neg_2.py": _load("neg_2.txt")})
    assert signals == []


def test_neg_3_setdefault_is_silent(detector: EnvMutationDetector) -> None:
    signals = detector.detect_static({"neg_3.py": _load("neg_3.txt")})
    assert signals == []


def test_neg_real_npm_is_silent(detector: EnvMutationDetector) -> None:
    """Real-world npm source (read-only env access) produces no signals."""
    signals = detector.detect_static({"neg_real_npm.js": _load("neg_real_npm.txt")})
    assert signals == []


# ---------------------------------------------------------------------------
# Dynamic detection (stub — deferred to future phase)
# ---------------------------------------------------------------------------


def test_detect_dynamic_returns_empty_list(detector: EnvMutationDetector) -> None:
    """detect_dynamic always returns [] until strace env_write events are emitted."""
    from aigate.sandbox.types import DynamicTrace

    trace = DynamicTrace(ran=True, runtime="birdcage")
    result = detector.detect_dynamic(trace)
    assert result == []


# ---------------------------------------------------------------------------
# Multiple files — signals tagged with correct path
# ---------------------------------------------------------------------------


def test_multiple_files_signals_reference_correct_paths(detector: EnvMutationDetector) -> None:
    source_files = {
        "setup.py": _load("pos_1.txt"),
        "clean.py": _load("neg_1.txt"),
        "install.py": _load("pos_2.txt"),
    }
    signals = detector.detect_static(source_files)
    paths_with_signals = {
        s.description.split("sensitive env mutation in ")[1].split(":")[0] for s in signals
    }
    assert "setup.py" in paths_with_signals
    assert "install.py" in paths_with_signals
    assert "clean.py" not in paths_with_signals
