"""CLI entry point for aigate."""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import asdict

import click
from rich.console import Console

from . import __version__
from .cache import get_cached, set_cached
from .config import Config
from .consensus import run_consensus
from .models import AnalysisLevel, AnalysisReport, PackageInfo, PrefilterResult, RiskLevel, Verdict
from .policy import PolicyOutcome, aggregate_decisions, decision_from_error, decision_from_report
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

    # 3.5 Enrichment (optional — adds context to AI prompt)
    enrichment_result = None
    if config.enrichment.enabled and not skip_ai and prefilter_result.needs_ai_review:
        from .enrichment import run_enrichment

        with console.status("Gathering external intelligence..."):
            try:
                enrichment_result = await run_enrichment(package, config.enrichment)
            except Exception as e:
                console.print(f"[dim]Enrichment failed: {e}[/dim]")

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
                    external_intelligence=(
                        enrichment_result.to_prompt_section() if enrichment_result else ""
                    ),
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
        enrichment=enrichment_result,
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
@click.option(
    "--ecosystem",
    "-e",
    default=None,
    type=click.Choice(["pypi", "npm", "pub"]),
    help="Override package ecosystem",
)
@click.option("--json", "use_json", is_flag=True, help="Output as JSON")
@click.option("--skip-ai", is_flag=True, help="Only run static pre-filter")
def scan(lockfile: str, ecosystem: str | None, use_json: bool, skip_ai: bool):
    """Scan all dependencies in a lockfile.

    Example: aigate scan requirements.txt
    """
    asyncio.run(_scan(lockfile, use_json, skip_ai, ecosystem))


async def _scan(
    lockfile: str,
    use_json: bool,
    skip_ai: bool,
    ecosystem_override: str | None = None,
):
    ecosystem = ecosystem_override or _infer_ecosystem(lockfile)
    packages = _parse_lockfile(lockfile)
    if not packages:
        payload = {
            "lockfile": lockfile,
            "ecosystem": ecosystem,
            "packages": [],
            "summary": {
                "total": 0,
                "safe": 0,
                "suspicious": 0,
                "malicious": 0,
                "errors": 0,
            },
            "exit_code": 0,
        }
        if use_json:
            _print_json(payload)
        else:
            console.print("[yellow]No packages found in lockfile[/yellow]")
        return

    config = Config.load()
    if not use_json:
        console.print(f"Scanning {len(packages)} packages from {lockfile} ({ecosystem})...")

    results = []
    for name, version in packages:
        result = await _scan_dependency(name, version, ecosystem, config, skip_ai)
        results.append(result)
        if not use_json:
            _print_scan_result(result)

    decisions = [result["decision"] for result in results]
    summary = _scan_summary(decisions)
    aggregate = aggregate_decisions(decisions)
    payload = {
        "lockfile": lockfile,
        "ecosystem": ecosystem,
        "packages": [_scan_result_payload(result) for result in results],
        "summary": summary,
        "decision": aggregate.outcome,
        "exit_code": aggregate.exit_code,
    }

    if use_json:
        _print_json(payload)
    else:
        console.print(
            f"\nScanned {summary['total']} packages, "
            f"{summary['suspicious'] + summary['malicious']} flagged for review."
        )

    if aggregate.exit_code != 0:
        sys.exit(aggregate.exit_code)


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
    old_norm = {_strip_version_prefix(k): v for k, v in old_files.items()}
    for path, content in new_files.items():
        norm = _strip_version_prefix(path)
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


@main.command("install-hooks")
@click.option(
    "--tool",
    "-t",
    "tools",
    multiple=True,
    required=True,
    type=click.Choice(["claude", "gemini", "codex", "cursor", "windsurf", "aider", "all"]),
    help="AI tool to install hooks for (repeatable, or 'all')",
)
@click.option(
    "--project-dir",
    "-d",
    default=".",
    type=click.Path(exists=True, file_okay=False),
    help="Project directory (default: current directory)",
)
def install_hooks(tools: tuple[str, ...], project_dir: str):
    """Install aigate PreToolUse hooks into AI coding tool configs.

    Example: aigate install-hooks --tool claude --tool gemini
    """
    from pathlib import Path

    from .hook_installer import install_hooks as _install

    target = Path(project_dir).resolve()
    messages = _install(list(tools), target)
    for msg in messages:
        if msg.startswith("(skip)"):
            console.print(f"[yellow]{msg}[/yellow]")
        elif msg.startswith("Unknown"):
            console.print(f"[red]{msg}[/red]")
        else:
            console.print(f"[green]{msg}[/green]")


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
# Docs: https://github.com/ImL1s/aigate

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

enrichment:
  enabled: false
  timeout_seconds: 10
  osv:
    enabled: true
  deps_dev:
    enabled: false
  scorecard:
    enabled: false
  provenance:
    enabled: false
  context7:
    enabled: false
  web_search:
    enabled: false
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
    if name == "uv.lock":
        return "pypi"
    if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        return "npm"
    if name == "pubspec.lock":
        return "pub"
    return "pypi"


def _parse_lockfile(path: str) -> list[tuple[str, str]]:
    """Parse a lockfile into unique (name, version) pairs."""
    import json as json_mod
    import tomllib
    from pathlib import Path as FilePath

    import yaml

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
    elif p.name == "uv.lock":
        data = tomllib.loads(p.read_text())
        for package in data.get("package", []):
            name = str(package.get("name", "")).strip()
            version = str(package.get("version", "")).strip()
            if name:
                packages.append((name, version))
    elif p.name == "package-lock.json":
        data = json_mod.loads(p.read_text())
        if data.get("packages"):
            for name, info in data.get("packages", {}).items():
                if name and "node_modules/" in name:
                    pkg_name = name.split("node_modules/")[-1]
                    packages.append((pkg_name, info.get("version", "")))
        else:
            for name, info in data.get("dependencies", {}).items():
                packages.append((name, info.get("version", "")))
    elif p.name == "pnpm-lock.yaml":
        data = yaml.safe_load(p.read_text()) or {}
        for key in data.get("packages") or {}:
            parsed = _parse_pnpm_package_key(key)
            if parsed:
                packages.append(parsed)
    elif p.name == "yarn.lock":
        packages.extend(_parse_yarn_lock(p.read_text()))
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

    return _dedupe_packages(packages)


async def _scan_dependency(
    name: str,
    version: str,
    ecosystem: str,
    config: Config,
    skip_ai: bool,
) -> dict:
    start = time.monotonic()
    package = PackageInfo(name=name, version=version, ecosystem=ecosystem)

    try:
        package = await resolve_package(name, version, ecosystem)
        source_files = await download_source(package)
    except Exception as e:
        report = AnalysisReport(
            package=package,
            prefilter=PrefilterResult(
                passed=False,
                reason="Package scan failed before analysis",
            ),
            total_latency_ms=int((time.monotonic() - start) * 1000),
        )
        return {
            "report": report,
            "decision": decision_from_error(str(e)),
            "error": str(e),
        }

    prefilter = run_prefilter(package, config, source_files)
    consensus = None
    enrichment_result = None
    error = ""

    if not skip_ai and prefilter.needs_ai_review:
        if config.enrichment.enabled:
            try:
                from .enrichment import run_enrichment

                enrichment_result = await run_enrichment(package, config.enrichment)
            except Exception as e:
                error = f"Enrichment failed: {e}"

        source_text = _format_source_for_ai(source_files)
        if not error:
            try:
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
            except Exception as e:
                error = f"AI analysis failed: {e}"

    report = AnalysisReport(
        package=package,
        prefilter=prefilter,
        consensus=consensus,
        enrichment=enrichment_result,
        total_latency_ms=int((time.monotonic() - start) * 1000),
    )
    decision = decision_from_error(error) if error else decision_from_report(report)
    return {
        "report": report,
        "decision": decision,
        "error": error,
    }


def _scan_summary(decisions: list) -> dict[str, int]:
    summary = {
        "total": len(decisions),
        "safe": 0,
        "suspicious": 0,
        "malicious": 0,
        "errors": 0,
    }
    for decision in decisions:
        if decision.outcome == PolicyOutcome.ERROR:
            summary["errors"] += 1
        elif decision.outcome == PolicyOutcome.MALICIOUS:
            summary["malicious"] += 1
        elif decision.outcome == PolicyOutcome.NEEDS_REVIEW:
            summary["suspicious"] += 1
        else:
            summary["safe"] += 1
    return summary


def _scan_result_payload(result: dict) -> dict:
    payload = asdict(result["report"])
    payload["decision"] = result["decision"].outcome
    payload["exit_code"] = result["decision"].exit_code
    payload["error"] = result["error"]
    return payload


def _print_scan_result(result: dict) -> None:
    report: AnalysisReport = result["report"]
    decision = result["decision"]
    package = report.package
    if decision.outcome == PolicyOutcome.ERROR:
        console.print(f"  [red]ERROR[/red] {package.name}=={package.version}: {result['error']}")
        return

    if decision.outcome == PolicyOutcome.MALICIOUS:
        status = "[red]MALICIOUS[/red]"
    elif decision.outcome == PolicyOutcome.NEEDS_REVIEW:
        status = "[yellow]REVIEW[/yellow]"
    else:
        status = "[green]OK[/green]"
    console.print(f"  {status} {package.name}=={package.version}: {report.prefilter.reason}")


def _print_json(payload: dict) -> None:
    import json as json_mod

    json_mod.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def _dedupe_packages(packages: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: dict[tuple[str, str], None] = {}
    for name, version in packages:
        key = (name.strip(), version.strip())
        if key[0]:
            seen.setdefault(key, None)
    return list(seen)


def _parse_pnpm_package_key(key: str) -> tuple[str, str] | None:
    normalized = str(key).strip().strip("'").strip('"').lstrip("/")
    normalized = normalized.split("(", 1)[0]
    if "@" not in normalized[1:]:
        return None
    name, version = normalized.rsplit("@", 1)
    if not name or not version:
        return None
    return name, version


def _parse_yarn_lock(contents: str) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    current_names: list[str] = []

    for line in contents.splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            current_names = _parse_yarn_selector_line(line)
            continue
        stripped = line.strip()
        if stripped.startswith("version ") and current_names:
            version = stripped.split('"', 2)[1]
            packages.extend((name, version) for name in current_names)

    return packages


def _parse_yarn_selector_line(line: str) -> list[str]:
    selectors = line.rstrip(":")
    names = []
    for selector in selectors.split(","):
        spec = selector.strip().strip('"').strip("'")
        if not spec:
            continue
        if spec.startswith("@"):
            name = spec.rsplit("@", 1)[0]
        else:
            name = spec.split("@", 1)[0]
        if name:
            names.append(name)
    return names


if __name__ == "__main__":
    main()
