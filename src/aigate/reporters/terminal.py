"""Rich terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import AnalysisReport, Verdict

VERDICT_STYLES = {
    Verdict.SAFE: ("bold green", "SAFE"),
    Verdict.SUSPICIOUS: ("bold yellow", "SUSPICIOUS"),
    Verdict.MALICIOUS: ("bold red", "MALICIOUS"),
    Verdict.NEEDS_HUMAN_REVIEW: ("bold magenta", "NEEDS REVIEW"),
    Verdict.ERROR: ("bold red", "ERROR"),
}


class TerminalReporter:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def print_report(self, report: AnalysisReport) -> None:
        pkg = report.package

        # Header
        style, label = VERDICT_STYLES.get(
            report.consensus.final_verdict if report.consensus else Verdict.SAFE,
            ("white", "UNKNOWN"),
        )

        if report.consensus:
            verdict = report.consensus.final_verdict
        elif report.prefilter.passed:
            verdict = Verdict.SAFE
            style, label = VERDICT_STYLES[Verdict.SAFE]
        else:
            verdict = Verdict.MALICIOUS
            style, label = VERDICT_STYLES[Verdict.MALICIOUS]

        header = Text()
        header.append("aigate ", style="bold cyan")
        header.append(f"{pkg.name}=={pkg.version} ", style="bold white")
        header.append(f"[{label}]", style=style)

        self.console.print()
        self.console.print(Panel(header, border_style=style.replace("bold ", "")))

        # Prefilter results
        pf = report.prefilter
        self.console.print(f"\n  Pre-filter: {pf.reason}", style="dim")
        if pf.risk_signals:
            self.console.print(f"  Risk signals: {len(pf.risk_signals)}", style="dim")
            for sig in pf.risk_signals[:5]:
                self.console.print(f"    - {sig}", style="yellow")

        # AI consensus results
        if report.consensus:
            c = report.consensus
            self.console.print(f"\n  AI Consensus: {c.summary}")

            if c.model_results:
                table = Table(show_header=True, header_style="bold")
                table.add_column("Model", style="cyan")
                table.add_column("Verdict")
                table.add_column("Confidence")
                table.add_column("Latency")

                for mr in c.model_results:
                    v_style, v_label = VERDICT_STYLES.get(mr.verdict, ("white", "?"))
                    table.add_row(
                        mr.model_name,
                        Text(v_label, style=v_style),
                        f"{mr.confidence:.0%}",
                        f"{mr.latency_ms}ms",
                    )
                self.console.print(table)

            if c.risk_signals:
                self.console.print("\n  Combined risk signals:", style="bold")
                for sig in c.risk_signals:
                    self.console.print(f"    - {sig}", style="yellow")

            if c.recommendation:
                rec_style = "green" if verdict == Verdict.SAFE else "red bold"
                self.console.print(f"\n  Recommendation: {c.recommendation}", style=rec_style)

            if c.has_disagreement:
                self.console.print(
                    "\n  ⚠ Models disagree — manual review recommended",
                    style="magenta bold",
                )
        elif report.cached:
            self.console.print("\n  (cached result)", style="dim")

        # Timing
        if report.total_latency_ms:
            self.console.print(f"\n  Total time: {report.total_latency_ms}ms", style="dim")

        self.console.print()
