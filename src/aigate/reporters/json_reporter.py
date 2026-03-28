"""JSON output reporter."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from ..models import AnalysisReport
from ..policy import decision_from_report


class JsonReporter:
    def print_report(self, report: AnalysisReport) -> None:
        data = asdict(report)
        decision = decision_from_report(report)
        data["decision"] = decision.outcome
        data["exit_code"] = decision.exit_code
        data["should_block_install"] = decision.should_block_install
        json.dump(data, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
