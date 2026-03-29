"""SARIF 2.1.0 output reporter for GitHub Security tab integration."""

from __future__ import annotations

import json
import sys

from .. import __version__
from ..models import AnalysisReport, Verdict
from ..policy import decision_from_report

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

VERDICT_TO_LEVEL: dict[Verdict, str] = {
    Verdict.MALICIOUS: "error",
    Verdict.SUSPICIOUS: "warning",
    Verdict.NEEDS_HUMAN_REVIEW: "warning",
    Verdict.SAFE: "note",
    Verdict.ERROR: "none",
}


class SarifReporter:
    """Produce SARIF 2.1.0 JSON from an AnalysisReport.

    Uses plain dicts + json.dumps — no external SARIF library required.
    """

    @staticmethod
    def _result_entry(report: AnalysisReport) -> dict:
        """Build a single SARIF result dict from an AnalysisReport."""
        decision = decision_from_report(report)
        verdict = report.consensus.final_verdict if report.consensus else Verdict.SAFE
        risk_signals = (
            report.consensus.risk_signals if report.consensus else report.prefilter.risk_signals
        )
        return {
            "ruleId": "aigate/supply-chain-risk",
            "level": VERDICT_TO_LEVEL.get(verdict, "none"),
            "message": {
                "text": (
                    f"Package {report.package.name}@{report.package.version} "
                    f"({report.package.ecosystem}): {decision.reason}. "
                    f"Risk signals: {', '.join(risk_signals) if risk_signals else 'none'}"
                ),
            },
            "properties": {
                "verdict": str(verdict),
                "confidence": (report.consensus.confidence if report.consensus else 0.0),
                "ecosystem": report.package.ecosystem,
            },
        }

    def to_sarif_multi(self, reports: list[AnalysisReport]) -> str:
        """Convert multiple AnalysisReports to a single SARIF 2.1.0 JSON string."""
        results_list = [self._result_entry(report) for report in reports]

        sarif: dict = {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "aigate",
                            "version": __version__,
                            "informationUri": "https://github.com/ImL1s/aigate",
                            "rules": [
                                {
                                    "id": "aigate/supply-chain-risk",
                                    "shortDescription": {
                                        "text": "AI-powered supply chain risk detection",
                                    },
                                },
                            ],
                        },
                    },
                    "results": results_list,
                },
            ],
        }

        return json.dumps(sarif, indent=2)

    def to_sarif(self, report: AnalysisReport) -> str:
        """Convert an AnalysisReport to a SARIF 2.1.0 JSON string."""
        return self.to_sarif_multi([report])

    def print_report(self, report: AnalysisReport) -> None:
        """Print SARIF JSON to stdout."""
        sys.stdout.write(self.to_sarif(report))
        sys.stdout.write("\n")
