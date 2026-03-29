"""CLI entry point for aigate."""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import asdict

import click
import httpx
from rich.console import Console

from . import __version__
from .cache import get_cached, set_cached
from .config import Config
from .consensus import run_consensus
from .models import (
    AnalysisLevel,
    AnalysisReport,
    ConsensusResult,
    EnrichmentResult,
    KnownVulnerability,
    ModelResult,
    PackageInfo,
    PrefilterResult,
    ProvenanceInfo,
    RiskLevel,
    ScorecardCheck,
    ScorecardResult,
    SecurityMention,
    Verdict,
)
from .policy import (
    PolicyOutcome,
    aggregate_decisions,
    decision_from_error,
    decision_from_report,
)
from .prefilter import run_prefilter
from .reporters.json_reporter import JsonReporter
from .reporters.sarif_reporter import SarifReporter
from .reporters.terminal import TerminalReporter
from .resolver import download_source, read_local_source, resolve_package

console = Console()


@click.group()
@click.version_option(version=__version__)
@click.option("--verbose", "-V", is_flag=True, help="Enable debug logging.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output.")
@click.pass_context
def main(ctx, verbose, quiet):
    """aigate — AI multi-model consensus for supply chain security."""
    from .log import setup_logging

    setup_logging(verbose=verbose, quiet=quiet)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet


def _apply_global_flags(ctx, verbose, quiet):
    """Apply -V/-q flags that were passed after the subcommand."""
    from .log import setup_logging

    if verbose and not ctx.obj.get("verbose"):
        ctx.obj["verbose"] = True
        setup_logging(verbose=True, quiet=ctx.obj.get("quiet", False))
    if quiet and not ctx.obj.get("quiet"):
        ctx.obj["quiet"] = True
        setup_logging(verbose=ctx.obj.get("verbose", False), quiet=True)


@main.command()
@click.argument("package")
@click.option("--version", "-v", "pkg_version", default=None, help="Package version")
@click.option(
    "--ecosystem",
    "-e",
    default="pypi",
    type=click.Choice(["pypi", "npm", "pub"]),
    help="Package ecosystem",
)
@click.option("--json", "use_json", is_flag=True, help="Output as JSON")
@click.option("--sarif", "use_sarif", is_flag=True, help="Output as SARIF 2.1.0")
@click.option(
    "--level",
    "-l",
    default="l1_quick",
    type=click.Choice(["l1_quick", "l2_deep", "l3_expert"]),
    help="Analysis depth",
)
@click.option("--skip-ai", is_flag=True, help="Only run static pre-filter, skip AI analysis")
@click.option(
    "--local",
    "local_path",
    type=click.Path(exists=True),
    default=None,
    help="Analyze local source path instead of downloading from registry.",
)
@click.option("--verbose", "-V", is_flag=True, help="Enable debug logging.", hidden=True)
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output.", hidden=True)
@click.pass_context
def check(
    ctx,
    package: str,
    pkg_version: str | None,
    ecosystem: str,
    use_json: bool,
    use_sarif: bool,
    level: str,
    skip_ai: bool,
    local_path: str | None,
    verbose: bool,
    quiet: bool,
):
    """Analyze a single package for security risks.

    Example: aigate check litellm -v 1.82.8
    """
    _apply_global_flags(ctx, verbose, quiet)
    asyncio.run(
        _check(package, pkg_version, ecosystem, use_json, use_sarif, level, skip_ai, local_path)
    )


async def _check(
    package_name: str,
    pkg_version: str | None,
    ecosystem: str,
    use_json: bool,
    use_sarif: bool,
    level_str: str,
    skip_ai: bool,
    local_path: str | None = None,
):
    config = Config.load()
    level = AnalysisLevel(level_str)
    start = time.monotonic()

    if local_path:
        # Offline mode: skip registry, read local source directly
        from pathlib import Path as FilePath

        package = PackageInfo(
            name=package_name,
            version=pkg_version or "local",
            ecosystem=ecosystem,
        )
        local_source = read_local_source(FilePath(local_path))
        source_files = {"local": local_source}
    else:
        # 1. Resolve package
        with console.status(f"Resolving {package_name}..."):
            try:
                package = await resolve_package(package_name, pkg_version, ecosystem)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    msg = (
                        f"Package '{package_name}' not found on {ecosystem}. "
                        "Check the package name and ecosystem are correct."
                    )
                else:
                    msg = (
                        f"Registry returned HTTP {e.response.status_code} "
                        f"for '{package_name}' on {ecosystem}."
                    )
                _emit_error(
                    use_json=use_json,
                    package_name=package_name,
                    package_version=pkg_version or "",
                    ecosystem=ecosystem,
                    message=msg,
                )
            except Exception as e:
                _emit_error(
                    use_json=use_json,
                    package_name=package_name,
                    package_version=pkg_version or "",
                    ecosystem=ecosystem,
                    message=f"Failed to resolve package: {e}",
                )

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
            if not use_json:
                console.print("[dim](cached result)[/dim]")
            report = _report_from_cached(
                cached, fallback_package=package, total_latency_ms=total_ms
            )
            _print_report_and_exit(report, use_json, use_sarif)

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
                if not use_json:
                    console.print(f"[dim]Enrichment failed: {e}[/dim]")
                enrichment_result = EnrichmentResult(errors=[f"enrichment: {e}"])

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
                if not use_json:
                    console.print(f"[yellow]AI analysis failed: {e}[/yellow]")
    elif not skip_ai and not prefilter_result.passed:
        pass
    elif skip_ai and prefilter_result.risk_signals:
        if not use_json:
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

    _print_report_and_exit(report, use_json, use_sarif)


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
@click.option("--sarif", "use_sarif", is_flag=True, help="Output as SARIF 2.1.0")
@click.option("--skip-ai", is_flag=True, help="Only run static pre-filter")
@click.option("--verbose", "-V", is_flag=True, help="Enable debug logging.", hidden=True)
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output.", hidden=True)
@click.pass_context
def scan(
    ctx,
    lockfile: str,
    ecosystem: str | None,
    use_json: bool,
    use_sarif: bool,
    skip_ai: bool,
    verbose: bool,
    quiet: bool,
):
    """Scan all dependencies in a lockfile.

    Example: aigate scan requirements.txt
    """
    _apply_global_flags(ctx, verbose, quiet)
    asyncio.run(_scan(lockfile, use_json, use_sarif, skip_ai, ecosystem))


async def _scan(
    lockfile: str,
    use_json: bool,
    use_sarif: bool,
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
            "decision": "safe",
            "exit_code": 0,
        }
        if use_json:
            _print_json(payload)
        else:
            console.print("[yellow]No packages found in lockfile[/yellow]")
        return

    config = Config.load()
    if not use_json and not use_sarif:
        console.print(f"Scanning {len(packages)} packages from {lockfile} ({ecosystem})...")

    results = []
    for name, version in packages:
        result = await _scan_dependency(name, version, ecosystem, config, skip_ai)
        results.append(result)
        if not use_json and not use_sarif:
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

    if use_sarif:
        reports = [result["report"] for result in results]
        _print_scan_sarif(reports)
    elif use_json:
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
    type=click.Choice(["pypi", "npm", "pub"]),
    help="Package ecosystem",
)
@click.option("--json", "use_json", is_flag=True, help="Output as JSON")
@click.option("--sarif", "use_sarif", is_flag=True, help="Output as SARIF 2.1.0")
@click.option("--skip-ai", is_flag=True, help="Only run static pre-filter")
@click.option("--verbose", "-V", is_flag=True, help="Enable debug logging.", hidden=True)
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output.", hidden=True)
@click.pass_context
def diff(
    ctx,
    package: str,
    old_version: str,
    new_version: str,
    ecosystem: str,
    use_json: bool,
    use_sarif: bool,
    skip_ai: bool,
    verbose: bool,
    quiet: bool,
):
    """Compare two versions of a package for suspicious changes.

    Example: aigate diff litellm 1.82.6 1.82.8
    """
    _apply_global_flags(ctx, verbose, quiet)
    asyncio.run(_diff(package, old_version, new_version, ecosystem, use_json, use_sarif, skip_ai))


async def _diff(
    package_name: str,
    old_ver: str,
    new_ver: str,
    ecosystem: str,
    use_json: bool,
    use_sarif: bool,
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
            _emit_error(
                use_json=use_json,
                package_name=package_name,
                package_version=new_ver,
                ecosystem=ecosystem,
                message=f"Failed: {e}",
            )

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

    _print_report_and_exit(report, use_json, use_sarif)


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
    type=click.Choice(
        ["claude", "gemini", "codex", "cursor", "windsurf", "aider", "opencode", "cline", "all"]
    ),
    help="AI tool to install hooks for (repeatable, or 'all')",
)
@click.option(
    "--auto",
    "auto_detect",
    is_flag=True,
    help="Auto-detect installed tools and install hooks for all found.",
)
@click.option(
    "--project-dir",
    "-d",
    default=".",
    type=click.Path(exists=True, file_okay=False),
    help="Project directory (default: current directory)",
)
def install_hooks(tools: tuple[str, ...], auto_detect: bool, project_dir: str):
    """Install aigate PreToolUse hooks into AI coding tool configs.

    Example: aigate install-hooks --tool claude --tool gemini
    Example: aigate install-hooks --auto
    """
    from pathlib import Path

    from .hook_installer import install_hooks as _install
    from .hook_installer import install_hooks_auto

    if not tools and not auto_detect:
        raise click.UsageError("Either --tool or --auto is required.")

    target = Path(project_dir).resolve()
    if auto_detect:
        messages = install_hooks_auto(target)
    else:
        messages = _install(list(tools), target)
    for msg in messages:
        if msg.startswith("(skip)"):
            console.print(f"[yellow]{msg}[/yellow]")
        elif msg.startswith("Unknown") or msg.startswith("No supported"):
            console.print(f"[red]{msg}[/red]")
        else:
            console.print(f"[green]{msg}[/green]")


@main.command()
def init():
    """Create a default .aigate.yml configuration file with auto-detected backends."""
    from pathlib import Path

    from .detect import KNOWN_BACKENDS, detect_backends, detect_hooks, generate_config_yaml

    config_path = Path.cwd() / ".aigate.yml"
    if config_path.exists():
        console.print(f"[yellow]{config_path} already exists[/yellow]")
        return

    # Detect backends
    backends = detect_backends()
    console.print("\n[bold]Detecting AI backends...[/bold]")
    for template in KNOWN_BACKENDS:
        found = any(b.name == template.name for b in backends)
        icon = "[green]v[/green]" if found else "[dim]x[/dim]"
        style = "green" if found else "dim"
        hint = "" if found else f"  ({template.install_hint})"
        console.print(f"  {icon} [{style}]{template.name}[/{style}]{hint}")

    # Detect hook tools
    hooks = detect_hooks()
    if hooks:
        console.print("\n[bold]Detected hook-compatible tools:[/bold]")
        for h in hooks:
            console.print(f"  [green]v[/green] [green]{h.tool}[/green]")

    # Generate config
    yaml_content = generate_config_yaml(backends)
    config_path.write_text(yaml_content)

    count = len(backends)
    if count == 0:
        console.print(
            "\n[yellow]No AI backends found. Config created with prefilter-only mode.[/yellow]"
        )
    elif count == 1:
        console.print(f"\n[green]Created {config_path} (single-model mode)[/green]")
    elif count == 2:
        console.print(f"\n[green]Created {config_path} (dual-model consensus)[/green]")
    else:
        console.print(
            f"\n[green]Created {config_path} (full consensus with {count} backends)[/green]"
        )

    if hooks:
        tool_names = ", ".join(h.tool for h in hooks)
        console.print(
            f"\n[dim]Tip: Run 'aigate install-hooks' to set up hooks for: {tool_names}[/dim]"
        )

    # Generate AI tool instruction files
    from .instructions import generate_instruction_files, generate_skill_files

    console.print("\n[bold]Generating AI tool instruction files...[/bold]")
    instruction_messages = generate_instruction_files(Path.cwd())
    for msg in instruction_messages:
        if msg.startswith("(skip)"):
            console.print(f"  [dim]{msg}[/dim]")
        else:
            console.print(f"  [green]{msg}[/green]")

    # Generate skill files for Claude Code, Gemini CLI, Codex CLI
    console.print("\n[bold]Generating skill files...[/bold]")
    skill_messages = generate_skill_files(Path.cwd())
    for msg in skill_messages:
        if msg.startswith("(skip)"):
            console.print(f"  [dim]{msg}[/dim]")
        else:
            console.print(f"  [green]{msg}[/green]")


@main.command()
@click.option(
    "--tool",
    "tools",
    multiple=True,
    default=None,
    help="Specific tool(s) to generate for (e.g. --tool claude --tool cursor).",
)
def instructions(tools: tuple[str, ...]):
    """Generate/update AI instruction files for all coding tools.

    Writes aigate usage instructions into tool-specific files
    (CLAUDE.md, GEMINI.md, AGENTS.md, .cursorrules, etc.)
    so that LLMs automatically run aigate before installing packages.

    Examples:
        aigate instructions
        aigate instructions --tool claude --tool gemini
    """
    from pathlib import Path

    from .instructions import generate_instruction_files, generate_skill_files

    tool_list = list(tools) if tools else None
    messages = generate_instruction_files(Path.cwd(), tools=tool_list)
    for msg in messages:
        if msg.startswith("(skip)"):
            console.print(f"  [dim]{msg}[/dim]")
        else:
            console.print(f"  [green]{msg}[/green]")

    # Generate skill files
    skill_messages = generate_skill_files(Path.cwd(), tools=tool_list)
    for msg in skill_messages:
        if msg.startswith("(skip)"):
            console.print(f"  [dim]{msg}[/dim]")
        else:
            console.print(f"  [green]{msg}[/green]")

    all_messages = messages + skill_messages
    if not all_messages:
        console.print("[yellow]No instruction or skill files to generate.[/yellow]")


@main.command()
@click.pass_context
def doctor(ctx):
    """Diagnose aigate setup: backends, hooks, config."""
    from .detect import KNOWN_BACKENDS, detect_backends, detect_hooks

    console.print("\n[bold]aigate doctor[/bold]\n")

    # 1. Backends
    console.print("[bold]AI Backends:[/bold]")
    detected = detect_backends()
    detected_names = {b.name for b in detected}
    for template in KNOWN_BACKENDS:
        if template.name in detected_names:
            console.print(f"  [green]\u2713[/green] {template.name}")
        else:
            console.print(f"  [dim]\u2717 {template.name}[/dim]  ({template.install_hint})")

    # 2. Strategy
    count = len(detected)
    strategy = {0: "prefilter-only", 1: "single-model", 2: "dual-model"}.get(
        count, f"full consensus ({count} models)"
    )
    console.print(f"\n[bold]Consensus Strategy:[/bold] {strategy}")

    # 3. Config
    console.print("\n[bold]Config:[/bold]")
    try:
        config = Config.load()
        console.print(
            f"  [green]\u2713[/green] Loaded .aigate.yml ({len(config.models)} models configured)"
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        import logging

        logging.debug("Config load failed: %s", exc)
        console.print("  [yellow]![/yellow] No .aigate.yml found (using defaults)")

    # 4. Hooks
    console.print("\n[bold]Hook Status:[/bold]")
    hooks = detect_hooks()
    if hooks:
        for h in hooks:
            console.print(f"  [green]\u2713[/green] {h.tool} detected")
    else:
        console.print("  [dim]No AI tools detected for hook installation[/dim]")

    console.print()


# ---------------------------------------------------------------------------
# aigate rules — rule management subcommands
# ---------------------------------------------------------------------------


@main.group()
def rules():
    """Manage detection rules."""


@rules.command("list")
@click.option("--tag", default=None, help="Filter rules by tag.")
def rules_list(tag: str | None):
    """List all loaded detection rules."""
    from .rules.loader import BUILTIN_DIR
    from .rules.loader import load_rules as _load_rules

    all_rules = _load_rules(builtin_dir=BUILTIN_DIR)

    if tag:
        all_rules = [r for r in all_rules if tag in r.tags]

    if not all_rules:
        console.print("[yellow]No rules found[/yellow]")
        return

    # Header
    console.print(f"{'ID':<30} {'Severity':<10} {'Scope':<16} {'Tags':<30} Description")
    console.print("-" * 110)
    for r in sorted(all_rules, key=lambda x: x.id):
        tags_str = ", ".join(r.tags)
        console.print(f"{r.id:<30} {r.severity:<10} {r.scope:<16} {tags_str:<30} {r.description}")

    console.print(f"\n[dim]{len(all_rules)} rules loaded[/dim]")


@rules.command("stats")
def rules_stats():
    """Show rule statistics by severity, scope, and tag."""
    from collections import Counter

    from .rules.loader import BUILTIN_DIR
    from .rules.loader import load_rules as _load_rules

    all_rules = _load_rules(builtin_dir=BUILTIN_DIR)

    if not all_rules:
        console.print("[yellow]No rules loaded[/yellow]")
        return

    console.print(f"[bold]Total rules:[/bold] {len(all_rules)}\n")

    # By severity
    severity_counts = Counter(r.severity for r in all_rules)
    console.print("[bold]By severity:[/bold]")
    for sev in ("critical", "high", "medium", "low"):
        count = severity_counts.get(sev, 0)
        if count:
            console.print(f"  {sev:<10} {count}")

    # By scope
    scope_counts = Counter(r.scope for r in all_rules)
    console.print("\n[bold]By scope:[/bold]")
    for scope, count in scope_counts.most_common():
        console.print(f"  {scope:<16} {count}")

    # By tag
    tag_counts: Counter[str] = Counter()
    for r in all_rules:
        tag_counts.update(r.tags)
    console.print("\n[bold]By tag:[/bold]")
    for t, count in tag_counts.most_common(15):
        console.print(f"  {t:<24} {count}")


@rules.command("update-popular")
def rules_update_popular():
    """Fetch and cache popular package lists from PyPI/npm."""
    import asyncio as _asyncio

    _asyncio.run(_update_popular())


async def _update_popular():
    from .rules.popular_packages import get_popular_packages

    console.print("Fetching popular packages...")
    for ecosystem in ("pypi", "npm"):
        try:
            pkgs = await get_popular_packages(ecosystem)
            console.print(f"  Updated {ecosystem}: {len(pkgs)} packages cached")
        except Exception as e:
            console.print(f"  [red]Failed to update {ecosystem}: {e}[/red]")
    console.print("[green]Updated popular package cache[/green]")


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
                enrichment_result = EnrichmentResult(errors=[f"enrichment: {e}"])

        source_text = _format_source_for_ai(source_files)
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


def _print_scan_sarif(reports: list[AnalysisReport]) -> None:
    """Print a single SARIF document containing results for all scanned packages."""
    sys.stdout.write(SarifReporter().to_sarif_multi(reports))
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


def _emit_error(
    *,
    use_json: bool,
    package_name: str,
    package_version: str,
    ecosystem: str,
    message: str,
) -> None:
    if use_json:
        _print_json(
            {
                "package": {
                    "name": package_name,
                    "version": package_version,
                    "ecosystem": ecosystem,
                },
                "decision": "error",
                "exit_code": 3,
                "should_block_install": False,
                "error": message,
            }
        )
    else:
        console.print(f"[red]{message}[/red]")
    sys.exit(3)


def _print_report_and_exit(
    report: AnalysisReport,
    use_json: bool,
    use_sarif: bool = False,
) -> None:
    quiet = False
    ctx = click.get_current_context(silent=True)
    if ctx and ctx.obj:
        quiet = ctx.obj.get("quiet", False)

    if use_sarif:
        reporter = SarifReporter()
    elif use_json:
        reporter = JsonReporter()
    else:
        reporter = TerminalReporter(console, quiet=quiet)
    reporter.print_report(report)
    sys.exit(decision_from_report(report).exit_code)


def _report_from_cached(
    cached: dict,
    *,
    fallback_package: PackageInfo,
    total_latency_ms: int,
) -> AnalysisReport:
    package_data = cached.get("package") or {}
    package = PackageInfo(
        name=package_data.get("name", fallback_package.name),
        version=package_data.get("version", fallback_package.version),
        ecosystem=package_data.get("ecosystem", fallback_package.ecosystem),
        author=package_data.get("author", fallback_package.author),
        description=package_data.get("description", fallback_package.description),
        download_count=package_data.get("download_count", fallback_package.download_count),
        publish_date=package_data.get("publish_date", fallback_package.publish_date),
        homepage=package_data.get("homepage", fallback_package.homepage),
        repository=package_data.get("repository", fallback_package.repository),
        has_install_scripts=package_data.get(
            "has_install_scripts",
            fallback_package.has_install_scripts,
        ),
        dependencies=package_data.get("dependencies", fallback_package.dependencies),
        metadata=package_data.get("metadata", fallback_package.metadata),
    )

    prefilter_data = cached.get("prefilter") or {}
    prefilter = PrefilterResult(
        passed=prefilter_data.get("passed", True),
        reason=prefilter_data.get("reason", "cached"),
        risk_signals=prefilter_data.get("risk_signals", []),
        risk_level=RiskLevel(prefilter_data.get("risk_level", "none")),
        needs_ai_review=prefilter_data.get("needs_ai_review", False),
    )

    consensus = None
    consensus_data = cached.get("consensus")
    if consensus_data:
        consensus = ConsensusResult(
            final_verdict=Verdict(consensus_data.get("final_verdict", "error")),
            confidence=float(consensus_data.get("confidence", 0.0)),
            model_results=[
                ModelResult(
                    model_name=model.get("model_name", ""),
                    verdict=Verdict(model.get("verdict", "error")),
                    confidence=float(model.get("confidence", 0.0)),
                    reasoning=model.get("reasoning", ""),
                    risk_signals=model.get("risk_signals", []),
                    analysis_level=AnalysisLevel(model.get("analysis_level", "l1_quick")),
                    token_usage=int(model.get("token_usage", 0)),
                    latency_ms=int(model.get("latency_ms", 0)),
                    raw_response=model.get("raw_response", ""),
                )
                for model in consensus_data.get("model_results", [])
            ],
            has_disagreement=consensus_data.get("has_disagreement", False),
            summary=consensus_data.get("summary", ""),
            risk_signals=consensus_data.get("risk_signals", []),
            recommendation=consensus_data.get("recommendation", ""),
        )

    enrichment = None
    enrichment_data = cached.get("enrichment")
    if enrichment_data:
        scorecard = None
        if enrichment_data.get("scorecard"):
            scorecard_data = enrichment_data["scorecard"]
            scorecard = ScorecardResult(
                repository_url=scorecard_data.get("repository_url", ""),
                date=scorecard_data.get("date", ""),
                score=float(scorecard_data.get("score", 0.0)),
                critical_findings=scorecard_data.get("critical_findings", []),
                checks=[
                    ScorecardCheck(
                        name=check.get("name", ""),
                        score=float(check.get("score", 0.0)),
                        reason=check.get("reason", ""),
                        documentation_url=check.get("documentation_url", ""),
                    )
                    for check in scorecard_data.get("checks", [])
                ],
            )

        provenance = None
        if enrichment_data.get("provenance"):
            provenance = ProvenanceInfo(**enrichment_data["provenance"])

        enrichment = EnrichmentResult(
            repository_url=enrichment_data.get("repository_url", ""),
            project_status=enrichment_data.get("project_status", ""),
            advisory_ids=enrichment_data.get("advisory_ids", []),
            library_description=enrichment_data.get("library_description", ""),
            expected_capabilities=enrichment_data.get("expected_capabilities", []),
            doc_snippets=enrichment_data.get("doc_snippets", []),
            security_mentions=[
                SecurityMention(**mention)
                for mention in enrichment_data.get("security_mentions", [])
            ],
            author_info=enrichment_data.get("author_info", ""),
            known_vulnerabilities=[
                KnownVulnerability(**vuln)
                for vuln in enrichment_data.get("known_vulnerabilities", [])
            ],
            scorecard=scorecard,
            provenance=provenance,
            sources_queried=enrichment_data.get("sources_queried", []),
            cache_hit=enrichment_data.get("cache_hit", False),
            enrichment_latency_ms=int(enrichment_data.get("enrichment_latency_ms", 0)),
            errors=enrichment_data.get("errors", []),
        )

    return AnalysisReport(
        package=package,
        prefilter=prefilter,
        consensus=consensus,
        enrichment=enrichment,
        cached=True,
        total_latency_ms=int(cached.get("total_latency_ms", total_latency_ms)),
    )


if __name__ == "__main__":
    main()
