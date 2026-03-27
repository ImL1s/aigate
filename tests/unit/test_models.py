"""Tests for data models."""

from aigate.models import (
    ConsensusResult,
    ModelResult,
    PackageInfo,
    Verdict,
)


def test_verdict_values():
    assert Verdict.SAFE.value == "safe"
    assert Verdict.MALICIOUS.value == "malicious"
    assert Verdict.SUSPICIOUS.value == "suspicious"


def test_package_info_defaults():
    pkg = PackageInfo(name="test", version="1.0", ecosystem="pypi")
    assert pkg.author == ""
    assert pkg.dependencies == []
    assert pkg.has_install_scripts is False


def test_model_result():
    r = ModelResult(
        model_name="claude",
        verdict=Verdict.SAFE,
        confidence=0.95,
        reasoning="No issues found",
    )
    assert r.model_name == "claude"
    assert r.confidence == 0.95


def test_consensus_result():
    r = ConsensusResult(
        final_verdict=Verdict.SAFE,
        confidence=0.9,
        summary="All models agree: safe",
    )
    assert not r.has_disagreement
    assert r.model_results == []
