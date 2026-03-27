"""npm/yarn/pnpm install hook — wraps JS package managers to intercept installs."""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import sys

from rich.console import Console

from ..config import Config
from ..consensus import run_consensus
from ..models import AnalysisLevel
from ..prefilter import run_prefilter
from ..reporters.terminal import TerminalReporter
from ..resolver import download_source, resolve_package

console = Console()

# Detect which package manager invoked us
_PM_BINARIES = {
    "npm": "npm",
    "yarn": "yarn",
    "pnpm": "pnpm",
}


def npm_wrapper():
    """Entry point for `aigate-npm` wrapper command.

    Works as a drop-in interceptor for npm, yarn and pnpm.
    Detects `install` / `add` sub-commands, checks every explicit package
    through aigate, then delegates to the real package manager.
    """
    args = sys.argv[1:]
    pm = _detect_package_manager(args)

    # Strip the leading package-manager name if the user typed
    # `aigate-npm npm install foo` (convenience form)
    if args and args[0] in _PM_BINARIES:
        pm = args[0]
        args = args[1:]

    install_cmds = _install_commands_for(pm)
    if not args or args[0] not in install_cmds:
        _passthrough(pm, args)
        return

    packages = _extract_packages(args, pm)
    if not packages:
        _passthrough(pm, args)
        return

    console.print(
        f"[cyan]aigate[/cyan] intercepting {pm} install for "
        f"{len(packages)} package(s)"
    )

    blocked = asyncio.run(_check_packages(packages))
    if blocked:
        console.print(
            f"\n[red bold]BLOCKED: {len(blocked)} malicious package(s) detected![/red bold]"
        )
        for name in blocked:
            console.print(f"  [red]- {name}[/red]")
        console.print(f"\nTo override, use: {pm} install --no-aigate <package>")
        sys.exit(2)

    console.print(
        "[green]All packages passed security check. Proceeding with install...[/green]\n"
    )
    _passthrough(pm, args)


# ── internal helpers ─────────────────────────────────────────────


async def _check_packages(packages: list[tuple[str, str | None]]) -> list[str]:
    """Check all packages against aigate, return list of blocked names."""
    config = Config.load()
    blocked: list[str] = []

    for name, version in packages:
        try:
            package = await resolve_package(name, version, "npm")
            source_files = await download_source(package)
            prefilter = run_prefilter(package, config, source_files)

            if not prefilter.passed and not prefilter.needs_ai_review:
                blocked.append(name)
                continue

            if prefilter.needs_ai_review:
                source_text = "\n".join(
                    f"### {p}\n```\n{c}\n```" for p, c in source_files.items()
                )
                result = await run_consensus(
                    package=package,
                    risk_signals=prefilter.risk_signals,
                    source_code=source_text,
                    config=config,
                    level=AnalysisLevel.L1_QUICK,
                )
                from ..models import Verdict

                if result.final_verdict == Verdict.MALICIOUS:
                    blocked.append(name)
                    TerminalReporter(console).print_report(
                        __import__(
                            "aigate.models", fromlist=["AnalysisReport"]
                        ).AnalysisReport(
                            package=package,
                            prefilter=prefilter,
                            consensus=result,
                        )
                    )
        except Exception as e:
            console.print(f"[yellow]Warning: Could not check {name}: {e}[/yellow]")

    return blocked


def _detect_package_manager(args: list[str]) -> str:
    """Guess package manager from first arg or fall back to what's available."""
    if args and args[0] in _PM_BINARIES:
        return args[0]
    # Default to npm
    return "npm"


def _install_commands_for(pm: str) -> set[str]:
    """Return the set of sub-commands that mean 'install packages'."""
    if pm == "yarn":
        return {"add", "install"}
    if pm == "pnpm":
        return {"add", "install", "i"}
    # npm
    return {"install", "i", "add"}


def _extract_packages(args: list[str], pm: str) -> list[tuple[str, str | None]]:
    """Extract (name, version|None) tuples from CLI args.

    Supports:
      npm install express@4.18.2   -> ("express", "4.18.2")
      npm install express          -> ("express", None)
      npm install @scope/pkg@1.0   -> ("@scope/pkg", "1.0")
      yarn add lodash@^4           -> ("lodash", "^4")
      pnpm add -D typescript@5     -> ("typescript", "5")
    """
    packages: list[tuple[str, str | None]] = []
    skip_next = False

    for arg in args[1:]:  # skip the sub-command (install/add/i)
        if skip_next:
            skip_next = False
            continue

        # Skip flags
        if arg.startswith("-"):
            # Flags that consume the next token
            if arg in ("-w", "--workspace", "--registry", "--tag"):
                skip_next = True
            continue

        parsed = _parse_npm_spec(arg)
        if parsed:
            packages.append(parsed)

    return packages


def _parse_npm_spec(spec: str) -> tuple[str, str | None] | None:
    """Parse an npm package specifier into (name, version).

    Handles both scoped (@scope/pkg@ver) and unscoped (pkg@ver) packages.
    Returns None if the spec doesn't look like a package name.
    """
    # Scoped: @scope/name@version
    m = re.match(r"^(@[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+)(?:@(.+))?$", spec)
    if m:
        return (m.group(1), m.group(2))

    # Unscoped: name@version
    m = re.match(r"^([a-zA-Z0-9._-]+)(?:@(.+))?$", spec)
    if m:
        return (m.group(1), m.group(2))

    return None


def _passthrough(pm: str, args: list[str]):
    """Run the real package manager with original args."""
    binary = shutil.which(pm)
    if not binary:
        console.print(f"[red]Error: '{pm}' not found in PATH[/red]")
        sys.exit(1)
    result = subprocess.run([binary, *args])
    sys.exit(result.returncode)
