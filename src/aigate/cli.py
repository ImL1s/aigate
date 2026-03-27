"""CLI entry point for aigate."""

from __future__ import annotations

import asyncio
import sys
import time

import click
from rich.console import Console

from . import __version__
from .cache import get_cached, set_cached
from .config import Config
from .consensus import run_consensus
from .models import AnalysisLevel, AnalysisReport, PrefilterResult, RiskLevel, Verdict
from .prefilter import run_prefilter
from .reporters.json_reporter import JsonReporter
from .reporters.terminal import TerminalReporter
from .resolver import download_source, resolve_package

console = Console()


@click.group()
@click.version_option(version=__version__)
def main():
    """aigate — AI multi-model consensus for supply chain security."""
    pass


@main.command()
@click.argument("package")
@click.option("--version", "-v", "pkg_version", default=None, help="Package version")
@click.option(
    "--ecosystem",
    "-e",
    default="pypi",
    type=click.Choice(["pypi", "npm"]),
    help="Package ecosystem",
)
@click.option("--json", "use_json", is_flag=True, help="Output as JSON")
@click.option(
    "--level",
    "-l",
    default="l1_quick",
    type=click.Choice(["l1_quick", "l2_deep", "l3_expert"]),
    help="Analysis depth",
)
@click.option("--skip-ai", is_flag=True, help="Only run static pre-filter, skip AI analysis")
def check(
    package: str,
    pkg_version: str | None,
    ecosystem: str,
    use_json: bool,
    level: str,
    skip_ai: bool,
):
    """Analyze a single package for security risks.

    Example: aigate check litellm -v 1.82.8
    """
    asyncio.run(_check(package, pkg_version, ecosystem, use_json, level, skip_ai))


async def _check(
    package_name: str,
    pkg_version: str | None,
    ecosystem: str,
    use_json: bool,
    level_str: str,
    skip_ai: bool,
):
    config = Config.load()
    level = AnalysisLevel(level_str)
    start = time.monotonic()

    # 1. Resolve package
    with console.status(f"Resolving {package_name}..."):
        try:
            package = await resolve_package(package_name, pkg_version, ecosystem)
        except Exception as e:
            console.print(f"[red]Failed to resolve package: {e}[/red]")
            sys.exit(1)

    # 1.5 Check cache
    cached = get_cached(
        package.name,
        package.version,
        ecosystem,
        config.cache_dir,
        config.cache_ttl_hours,
    )
    if cached and skip_ai:
        total_ms = int((time.monotonic() - start) * 1000)
        console.print("[dim](cached result)[/dim]")
        report = AnalysisReport(
            package=package,
            prefilter=PrefilterResult(
                passed=cached.get("prefilter", {}).get("passed", True),
                reason=cached.get("prefilter", {}).get("reason", "cached"),
                risk_level=RiskLevel(cached.get("prefilter", {}).get("risk_level", "none")),
            ),
            cached=True,
            total_latency_ms=total_ms,
        )
        reporter = JsonReporter() if use_json else TerminalReporter(console)
        reporter.print_report(report)
        return

    # 2. Download source
    with console.status(f"Downloading {package.name}=={package.version}..."):
        try:
            source_files = await download_source(package)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not download source: {e}[/yellow]")
            source_files = {}

    # 3. Static pre-filter
    prefilter_result = run_prefilter(package, config, source_files)

    # 4. AI analysis (if needed and not skipped)
    consensus_result = None
    if not skip_ai and prefilter_result.needs_ai_review:
        source_text = _format_source_for_ai(source_files)
        with console.status("Running AI analysis..."):
            try:
                consensus_result = await run_consensus(
                    package=package,
                    risk_signals=prefilter_result.risk_signals,
                    source_code=source_text,
                    config=config,
                    level=level,
                )
            except Exception as e:
                console.print(f"[yellow]AI analysis failed: {e}[/yellow]")
    elif not skip_ai and not prefilter_result.passed:
        pass
    elif skip_ai and prefilter_result.risk_signals:
        console.print("[dim]AI analysis skipped (--skip-ai)[/dim]")

    total_ms = int((time.monotonic() - start) * 1000)

    report = AnalysisReport(
        package=package,
        prefilter=prefilter_result,
        consensus=consensus_result,
        total_latency_ms=total_ms,
    )

    # 5. Cache result
    set_cached(package.name, package.version, ecosystem, report, config.cache_dir)

    # 6. Output
    reporter = JsonReporter() if use_json else TerminalReporter(console)
    reporter.print_report(report)

    # Exit code: 0=safe, 1=suspicious/review, 2=malicious, 3=error
    if consensus_result:
        exit_codes = {
            Verdict.SAFE: 0,
            Verdict.SUSPICIOUS: 1,
            Verdict.NEEDS_HUMAN_REVIEW: 1,
            Verdict.MALICIOUS: 2,
            Verdict.ERROR: 3,
        }
        sys.exit(exit_codes.get(consensus_result.final_verdict, 0))
    elif not prefilter_result.passed:
        sys.exit(2)


@main.command()
@click.argument("lockfile", type=click.Path(exists=True))
@click.option("--json", "use_json", is_flag=True, help="Output as JSON")
@click.option("--skip-ai", is_flag=True, help="Only run static pre-filter")
def scan(lockfile: str, use_json: bool, skip_ai: bool):
    """Scan all dependencies in a lockfile.

    Example: aigate scan requirements.txt
    """
    asyncio.run(_scan(lockfile, use_json, skip_ai))


async def _scan(lockfile: str, use_json: bool, skip_ai: bool):
    ecosystem = _infer_ecosystem(lockfile)
    packages = _parse_lockfile(lockfile)
    if not packages:
        console.print("[yellow]No packages found in lockfile[/yellow]")
        return

    config = Config.load()
    console.print(f"Scanning {len(packages)} packages from {lockfile} ({ecosystem})...")
    flagged = 0

    for name, version in packages:
        try:
            package = await resolve_package(name, version, ecosystem)
            prefilter = run_prefilter(package, config)
            if prefilter.risk_signals:
                flagged += 1
                status = (
                    "[yellow]REVIEW[/yellow]" if prefilter.needs_ai_review else "[dim]LOW[/dim]"
                )
                console.print(f"  {status} {name}=={version}: {prefilter.reason}")
            else:
                console.print(f"  [green]OK[/green] {name}=={version}")
        except Exception as e:
            console.print(f"  [red]ERROR[/red] {name}: {e}")

    console.print(f"\nScanned {len(packages)} packages, {flagged} flagged for review.")


@main.command()
@click.argument("package")
@click.argument("old_version")
@click.argument("new_version")
@click.option(
    "--ecosystem",
    "-e",
    default="pypi",
    type=click.Choice(["pypi", "npm"]),
    help="Package ecosystem",
)
@click.option("--json", "use_json", is_flag=True, help="Output as JSON")
@click.option("--skip-ai", is_flag=True, help="Only run static pre-filter")
def diff(
    package: str,
    old_version: str,
    new_version: str,
    ecosystem: str,
    use_json: bool,
    skip_ai: bool,
):
    """Compare two versions of a package for suspicious changes.

    Example: aigate diff litellm 1.82.6 1.82.8
    """
    asyncio.run(_diff(package, old_version, new_version, ecosystem, use_json, skip_ai))


async def _diff(
    package_name: str,
    old_ver: str,
    new_ver: str,
    ecosystem: str,
    use_json: bool,
    skip_ai: bool,
):
    config = Config.load()
    start = time.monotonic()

    # Resolve and download both versions in parallel
    with console.status(f"Downloading {package_name} {old_ver} and {new_ver}..."):
        try:
            old_pkg = await resolve_package(package_name, old_ver, ecosystem)
            new_pkg = await resolve_package(package_name, new_ver, ecosystem)
            old_files, new_files = await asyncio.gather(
                download_source(old_pkg),
                download_source(new_pkg),
            )
        except Exception as e:
            console.print(f"[red]Failed: {e}[/red]")
            sys.exit(1)

    # Compute diff: files only in new or changed
    added_files: dict[str, str] = {}
    changed_files: dict[str, str] = {}
    for path, content in new_files.items():
        # Normalize paths (strip version prefix)
        norm = _strip_version_prefix(path)
        old_norm = {_strip_version_prefix(k): v for k, v in old_files.items()}
        if norm not in old_norm:
            added_files[path] = content
        elif old_norm[norm] != content:
            changed_files[path] = content

    diff_files = {**added_files, **changed_files}
    console.print(f"  {len(added_files)} new files, {len(changed_files)} changed files")

    # Run prefilter on diff files only
    prefilter_result = run_prefilter(new_pkg, config, diff_files)

    # AI analysis on diff
    consensus_result = None
    if not skip_ai and prefilter_result.needs_ai_review:
        source_text = _format_source_for_ai(diff_files)
        with console.status("Running AI diff analysis..."):
            try:
                consensus_result = await run_consensus(
                    package=new_pkg,
                    risk_signals=prefilter_result.risk_signals,
                    source_code=source_text,
                    config=config,
                    level=AnalysisLevel.L2_DEEP,
                )
            except Exception as e:
                console.print(f"[yellow]AI analysis failed: {e}[/yellow]")

    total_ms = int((time.monotonic() - start) * 1000)
    report = AnalysisReport(
        package=new_pkg,
        prefilter=prefilter_result,
        consensus=consensus_result,
        total_latency_ms=total_ms,
    )

    reporter = JsonReporter() if use_json else TerminalReporter(console)
    reporter.print_report(report)

    if consensus_result:
        exit_codes = {
            Verdict.SAFE: 0,
            Verdict.SUSPICIOUS: 1,
            Verdict.NEEDS_HUMAN_REVIEW: 1,
            Verdict.MALICIOUS: 2,
            Verdict.ERROR: 3,
        }
        sys.exit(exit_codes.get(consensus_result.final_verdict, 0))
    elif not prefilter_result.passed:
        sys.exit(2)


def _strip_version_prefix(path: str) -> str:
    """Strip 'package-version/' prefix from archive paths."""
    parts = path.split("/", 1)
    return parts[1] if len(parts) > 1 else path


@main.command()
def init():
    """Create a default .aigate.yml configuration file."""
    from pathlib import Path

    config_path = Path.cwd() / ".aigate.yml"
    if config_path.exists():
        console.print(f"[yellow]{config_path} already exists[/yellow]")
        return

    default_config = """\
# aigate configuration
# Docs: https://github.com/anthropics/aigate

models:
  - name: claude
    backend: claude
    model_id: claude-sonnet-4-6
    weight: 1.0
    enabled: true
    timeout_seconds: 120

  - name: gemini
    backend: gemini
    model_id: gemini-2.5-pro
    weight: 0.9
    enabled: true
    timeout_seconds: 120

  # Uncomment for local analysis (no data sent to cloud):
  # - name: ollama
  #   backend: ollama
  #   model_id: llama3.1:8b
  #   weight: 0.7
  #   enabled: true
  #   timeout_seconds: 180
  #   options:
  #     base_url: http://localhost:11434

thresholds:
  malicious: 0.6
  suspicious: 0.5
  disagreement: 0.4

whitelist:
  # Packages you trust unconditionally:
  # - requests
  # - numpy

blocklist:
  # Known malicious packages:
  # - crossenv
  # - python3-dateutil

ecosystems:
  - pypi
  - npm

cache_dir: ~/.aigate/cache
cache_ttl_hours: 168  # 7 days
max_analysis_level: l2_deep
output_format: rich  # rich | json | sarif
"""
    config_path.write_text(default_config)
    console.print(f"[green]Created {config_path}[/green]")


def _format_source_for_ai(source_files: dict[str, str]) -> str:
    """Format source files for AI prompt, prioritizing risky files."""
    priority_patterns = [
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "package.json",
        "postinstall",
        "preinstall",
        ".pth",
        "__init__.py",
    ]

    prioritized = []
    rest = []
    for path, content in source_files.items():
        if any(p in path for p in priority_patterns):
            prioritized.append((path, content))
        else:
            rest.append((path, content))

    parts = []
    for path, content in prioritized + rest:
        parts.append(f"### {path}\n```\n{content}\n```\n")

    return "\n".join(parts)


def _infer_ecosystem(path: str) -> str:
    """Infer package ecosystem from lockfile name."""
    from pathlib import Path as FilePath

    name = FilePath(path).name.lower()
    if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        return "npm"
    if name == "pubspec.lock":
        return "pub"
    return "pypi"


def _parse_lockfile(path: str) -> list[tuple[str, str]]:
    """Parse requirements.txt or package-lock.json into (name, version) pairs."""
    import json as json_mod
    from pathlib import Path as FilePath

    p = FilePath(path)
    packages = []

    if p.name == "requirements.txt" or p.suffix == ".txt":
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "==" in line:
                name, ver = line.split("==", 1)
                packages.append((name.strip(), ver.strip()))
            elif ">=" in line:
                name = line.split(">=")[0].strip()
                packages.append((name, ""))
            else:
                packages.append((line, ""))
    elif p.name == "package-lock.json":
        data = json_mod.loads(p.read_text())
        for name, info in data.get("packages", {}).items():
            if name and "node_modules/" in name:
                pkg_name = name.split("node_modules/")[-1]
                packages.append((pkg_name, info.get("version", "")))
    elif p.name == "pubspec.lock":
        # Basic pubspec.lock parser
        current_name = None
        for line in p.read_text().splitlines():
            stripped = line.strip()
            if line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
                current_name = stripped.rstrip(":")
            elif "version:" in stripped and current_name:
                ver = stripped.split("version:")[1].strip().strip('"')
                packages.append((current_name, ver))
                current_name = None

    return packages


if __name__ == "__main__":
    main()
