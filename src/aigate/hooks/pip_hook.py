"""pip install hook — wraps pip to intercept installs."""

from __future__ import annotations

import asyncio
import re
import subprocess
import sys

from rich.console import Console

from ..cache import get_cached, report_from_cached, set_cached
from ..config import Config
from ..consensus import run_consensus
from ..enrichment import run_enrichment
from ..models import AnalysisLevel, AnalysisReport, EnrichmentResult
from ..policy import PolicyOutcome, decision_from_report
from ..prefilter import run_prefilter
from ..reporters.terminal import TerminalReporter
from ..resolver import download_source, resolve_package

console = Console()


def pip_wrapper():
    """Entry point for `aigate-pip` wrapper command."""
    args = sys.argv[1:]

    if "--no-aigate" in args:
        _passthrough_pip([arg for arg in args if arg != "--no-aigate"])
        return

    # Only intercept `install` commands
    if not args or args[0] != "install":
        _passthrough_pip(args)
        return

    # Extract package names from args
    packages = _extract_packages(args)
    if not packages:
        _passthrough_pip(args)
        return

    console.print(f"[cyan]aigate[/cyan] intercepting pip install for {len(packages)} package(s)")

    blocked = asyncio.run(_check_packages(packages))
    if blocked:
        console.print(
            f"\n[red bold]BLOCKED: {len(blocked)} malicious package(s) detected![/red bold]"
        )
        for name in blocked:
            console.print(f"  [red]- {name}[/red]")
        console.print("\nTo override, use: pip install --no-aigate <package>")
        sys.exit(2)

    # All clear — proceed with real pip
    console.print("[green]All packages passed security check. Proceeding with install...[/green]\n")
    _passthrough_pip(args)


async def _check_packages(packages: list[tuple[str, str | None]]) -> list[str]:
    """Check all packages, return list of blocked package names."""
    config = Config.load()
    blocked: list[str] = []

    for name, version in packages:
        try:
            package = await resolve_package(name, version, "pypi")
            cached = get_cached(
                package.name,
                package.version,
                "pypi",
                config.cache_dir,
                config.cache_ttl_hours,
            )
            if cached:
                report = report_from_cached(cached, fallback_package=package, total_latency_ms=0)
            else:
                source_files = await download_source(package)
                prefilter = run_prefilter(package, config, source_files)
                consensus = None
                enrichment_result = None
                if prefilter.needs_ai_review:
                    if config.enrichment.enabled:
                        try:
                            enrichment_result = await run_enrichment(package, config.enrichment)
                        except Exception as e:
                            enrichment_result = EnrichmentResult(errors=[f"enrichment: {e}"])

                    source_text = "\n".join(
                        f"### {p}\n```\n{c}\n```" for p, c in source_files.items()
                    )
                    consensus = await run_consensus(
                        package=package,
                        risk_signals=prefilter.risk_signals,
                        source_code=source_text,
                        config=config,
                        level=AnalysisLevel.L1_QUICK,
                        external_intelligence=(
                            enrichment_result.to_prompt_section() if enrichment_result else ""
                        ),
                    )

                report = AnalysisReport(
                    package=package,
                    prefilter=prefilter,
                    consensus=consensus,
                    enrichment=enrichment_result,
                )
            decision = decision_from_report(report)
            if not cached and decision.outcome != PolicyOutcome.ERROR:
                set_cached(package.name, package.version, "pypi", report, config.cache_dir)
            if decision.should_block_install:
                blocked.append(name)
                TerminalReporter(console).print_report(report)
            elif decision.outcome == PolicyOutcome.ERROR:
                console.print(
                    f"[yellow]Warning: AI analysis returned an error for {name}: "
                    f"{decision.reason}[/yellow]"
                )
        except Exception as e:
            console.print(f"[yellow]Warning: Could not check {name}: {e}[/yellow]")

    return blocked


def _extract_packages(args: list[str]) -> list[tuple[str, str | None]]:
    """Extract package names and versions from pip install args."""
    packages = []
    skip_next = False
    for arg in args[1:]:  # Skip 'install'
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            if arg in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable"):
                skip_next = True
            continue
        # Parse name==version or name>=version or just name
        match = re.match(r"^([a-zA-Z0-9_.-]+)(?:[=<>!~]+(.+))?$", arg)
        if match:
            packages.append((match.group(1), match.group(2)))
    return packages


def _passthrough_pip(args: list[str]):
    """Run real pip with original args."""
    result = subprocess.run([sys.executable, "-m", "pip", *args])
    sys.exit(result.returncode)
