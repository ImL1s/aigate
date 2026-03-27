"""JSON output reporter."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from ..models import AnalysisReport


class JsonReporter:
    def print_report(self, report: AnalysisReport) -> None:
        data = asdict(report)
        json.dump(data, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
