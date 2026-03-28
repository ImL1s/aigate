"""Tests for SARIF output reporter."""

from __future__ import annotations

import json

from aigate.models import (
    AnalysisReport,
    ConsensusResult,
    ModelResult,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
    Verdict,
)
from aigate.reporters.sarif_reporter import SarifReporter


def _make_report(verdict: Verdict = Verdict.MALICIOUS) -> AnalysisReport:
    return AnalysisReport(
        package=PackageInfo(name="evil-pkg", version="1.0.0", ecosystem="pypi"),
        prefilter=PrefilterResult(
            passed=False,
            reason="dangerous pattern detected",
            risk_signals=["dangerous_pattern(HIGH): eval() with network input"],
            risk_level=RiskLevel.HIGH,
        ),
        consensus=ConsensusResult(
            final_verdict=verdict,
            confidence=0.95,
            model_results=[
                ModelResult(
                    model_name="claude",
                    verdict=verdict,
                    confidence=0.95,
                    reasoning="Credential theft detected",
                    risk_signals=["credential_theft"],
                    analysis_level="l1_quick",
                    latency_ms=1200,
                ),
            ],
            has_disagreement=False,
            summary="Malicious credential theft package",
            risk_signals=["credential_theft"],
        ),
    )


def test_sarif_valid_json():
    reporter = SarifReporter()
    output = reporter.to_sarif(_make_report())
    sarif = json.loads(output)
    assert sarif["$schema"] == (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
        "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    )
    assert sarif["version"] == "2.1.0"


def test_sarif_has_run_with_tool():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report()))
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "aigate"


def test_sarif_malicious_has_error_level():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report(Verdict.MALICIOUS)))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"


def test_sarif_suspicious_has_warning_level():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report(Verdict.SUSPICIOUS)))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "warning"


def test_sarif_safe_has_note_level():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report(Verdict.SAFE)))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "note"


def test_sarif_needs_review_has_warning_level():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report(Verdict.NEEDS_HUMAN_REVIEW)))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "warning"


def test_sarif_error_has_none_level():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report(Verdict.ERROR)))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "none"


def test_sarif_result_has_risk_signals():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report()))
    result = sarif["runs"][0]["results"][0]
    assert "credential_theft" in result["message"]["text"]


def test_sarif_result_has_rule_id():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report()))
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "aigate/supply-chain-risk"


def test_sarif_result_properties_contain_verdict():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report(Verdict.MALICIOUS)))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["verdict"] == "malicious"
    assert props["confidence"] == 0.95
    assert props["ecosystem"] == "pypi"


def test_sarif_prefilter_only_report():
    """Report without consensus should use prefilter risk signals."""
    report = AnalysisReport(
        package=PackageInfo(name="sketchy-pkg", version="0.1.0", ecosystem="npm"),
        prefilter=PrefilterResult(
            passed=False,
            reason="typosquat detected",
            risk_signals=["typosquat(HIGH): similar to 'sketch'"],
            risk_level=RiskLevel.HIGH,
        ),
    )
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(report))
    result = sarif["runs"][0]["results"][0]
    assert "typosquat" in result["message"]["text"]
    assert result["level"] == "note"  # no consensus → defaults to SAFE


def test_sarif_print_report(capsys):
    """print_report writes SARIF JSON to stdout."""
    reporter = SarifReporter()
    reporter.print_report(_make_report())
    captured = capsys.readouterr()
    sarif = json.loads(captured.out)
    assert sarif["version"] == "2.1.0"


def test_sarif_tool_has_rules():
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif(_make_report()))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 1
    assert rules[0]["id"] == "aigate/supply-chain-risk"


def test_sarif_multi_empty():
    """to_sarif_multi with empty list produces valid SARIF with no results."""
    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif_multi([]))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


def test_sarif_multi_multiple_reports():
    """to_sarif_multi merges multiple reports into one SARIF document."""
    report_a = _make_report(Verdict.MALICIOUS)
    report_b = AnalysisReport(
        package=PackageInfo(name="good-pkg", version="2.0.0", ecosystem="npm"),
        prefilter=PrefilterResult(
            passed=True,
            reason="no issues",
            risk_signals=[],
            risk_level=RiskLevel.LOW,
        ),
        consensus=ConsensusResult(
            final_verdict=Verdict.SAFE,
            confidence=0.99,
            model_results=[
                ModelResult(
                    model_name="gemini",
                    verdict=Verdict.SAFE,
                    confidence=0.99,
                    reasoning="Looks safe",
                    risk_signals=[],
                    analysis_level="l1_quick",
                    latency_ms=800,
                ),
            ],
            has_disagreement=False,
            summary="Safe package",
            risk_signals=[],
        ),
    )

    reporter = SarifReporter()
    sarif = json.loads(reporter.to_sarif_multi([report_a, report_b]))

    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["level"] == "error"  # MALICIOUS
    assert results[1]["level"] == "note"  # SAFE
    assert "evil-pkg" in results[0]["message"]["text"]
    assert "good-pkg" in results[1]["message"]["text"]


def test_sarif_single_delegates_to_multi():
    """to_sarif() and to_sarif_multi([report]) produce identical output."""
    reporter = SarifReporter()
    report = _make_report()
    assert reporter.to_sarif(report) == reporter.to_sarif_multi([report])
