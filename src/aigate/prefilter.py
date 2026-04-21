"""Static pre-filter engine — fast checks before AI analysis."""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Sequence
from difflib import SequenceMatcher

from .config import Config
from .models import PackageInfo, PrefilterResult, RiskLevel, RiskSignal
from .rules.behavior_chains import detect_behavior_chains
from .rules.compound import check_compound_signals
from .rules.loader import Rule, load_rules
from .rules.popular_packages import _read_cache
from .sandbox.evasion.aggregator import aggregate_signals as _aggregate_evasion
from .sandbox.evasion.registry import run_static as _run_evasion_static

logger = logging.getLogger(__name__)

# Module-level cache: loaded once, reused for all calls.
_CACHED_RULES: list[Rule] | None = None
_CACHED_RULES_KEY: tuple[str, tuple[str, ...]] | None = None

# Severity ordering for max() comparison
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SEVERITY_LABEL = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}


def _get_rules(config: Config | None = None) -> list[Rule]:
    """Return cached rules, loading from YAML on first call.

    When *config* is provided, ``config.rules_dir`` and ``config.disable_rules``
    are forwarded to :func:`load_rules`.  The cache is invalidated when these
    values change.
    """
    global _CACHED_RULES, _CACHED_RULES_KEY  # noqa: PLW0603

    rules_dir = config.rules_dir if config else ""
    disable = tuple(config.disable_rules) if config else ()
    cache_key = (rules_dir, disable)

    if _CACHED_RULES is not None and _CACHED_RULES_KEY == cache_key:
        return _CACHED_RULES

    from pathlib import Path

    user_dir = Path(rules_dir).expanduser() if rules_dir else None
    _CACHED_RULES = load_rules(
        user_dir=user_dir,
        disable_rules=list(disable) if disable else None,
    )
    _CACHED_RULES_KEY = cache_key
    return _CACHED_RULES


# Top 1000 PyPI packages (abbreviated — expanded at runtime from cache)
POPULAR_PYPI: set[str] = {
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "boto3",
    "urllib3",
    "setuptools",
    "pip",
    "wheel",
    "pyyaml",
    "cryptography",
    "certifi",
    "click",
    "rich",
    "httpx",
    "pydantic",
    "fastapi",
    "sqlalchemy",
    "pytest",
    "black",
    "ruff",
    "mypy",
    "pillow",
    "scipy",
    "matplotlib",
    "torch",
    "tensorflow",
    "transformers",
    "openai",
    "anthropic",
    "litellm",
    "langchain",
    "crewai",
    "dspy",
    "pytorch-triton",
}

POPULAR_NPM: set[str] = {
    "express",
    "react",
    "vue",
    "angular",
    "next",
    "typescript",
    "lodash",
    "axios",
    "webpack",
    "babel",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chalk",
    "commander",
    "inquirer",
    "debug",
    "moment",
    "dayjs",
    "cross-env",
}

POPULAR_CARGO: set[str] = {
    "serde",
    "tokio",
    "rand",
    "clap",
    "reqwest",
    "hyper",
    "axum",
    "actix-web",
    "diesel",
    "sqlx",
    "tracing",
    "anyhow",
    "thiserror",
    "chrono",
    "regex",
    "log",
    "serde_json",
    "futures",
    "async-trait",
    "bytes",
    "once_cell",
    "lazy_static",
}

POPULAR_GEM: set[str] = {
    "rails",
    "rake",
    "bundler",
    "rspec",
    "puma",
    "sidekiq",
    "devise",
    "nokogiri",
    "pg",
    "redis",
    "sinatra",
    "rubocop",
    "capistrano",
    "rspec-rails",
    "factory_bot",
    "faker",
}

POPULAR_COMPOSER: set[str] = {
    "laravel/framework",
    "symfony/console",
    "guzzlehttp/guzzle",
    "monolog/monolog",
    "phpunit/phpunit",
    "doctrine/orm",
    "league/flysystem",
    "twig/twig",
}

POPULAR_GO: set[str] = {
    "gin",
    "mux",
    "grpc",
    "echo",
    "fiber",
    "cobra",
    "viper",
    "zap",
    "logrus",
    "gorm",
    "sqlx",
    "testify",
    "wire",
    "fx",
}

POPULAR_NUGET: set[str] = {
    "Newtonsoft.Json",
    "Serilog",
    "AutoMapper",
    "MediatR",
    "Dapper",
    "FluentValidation",
    "Polly",
    "Moq",
    "xunit",
    "NUnit",
}

POPULAR_COCOAPODS: set[str] = {
    "AFNetworking",
    "Alamofire",
    "SDWebImage",
    "SnapKit",
    "RxSwift",
    "RxCocoa",
    "Kingfisher",
    "Realm",
    "ReactiveCocoa",
    "Masonry",
    "FBSDKCoreKit",
    "Firebase",
    "FirebaseAnalytics",
    "FirebaseAuth",
    "GoogleSignIn",
    "Lottie",
    "MBProgressHUD",
    "SwiftLint",
    "Sentry",
    "Stripe",
}

POPULAR_JSR: set[str] = {
    # JSR scopes (the @std/* ecosystem dominates)
    "@std/fs",
    "@std/path",
    "@std/http",
    "@std/encoding",
    "@std/async",
    "@std/log",
    "@std/uuid",
    "@std/json",
    "@std/yaml",
    "@std/text",
    "@std/datetime",
    "@std/cli",
    "@std/io",
    "@std/streams",
    "@std/testing",
    "@oak/oak",
    "@hono/hono",
}


# Note: Dangerous patterns are now loaded from YAML rules via _get_rules().
# See src/aigate/rules/builtin/ for the rule definitions.

# Typosquatting distance threshold
TYPO_SIMILARITY_THRESHOLD = 0.85


def run_prefilter(
    package: PackageInfo,
    config: Config,
    source_files: dict[str, str] | None = None,
) -> PrefilterResult:
    """Run all pre-filter checks. Returns whether AI review is needed."""
    signals: list[str] = []
    evasion_signals: list[RiskSignal] = []  # Phase 3 T9: structured RiskSignal objects

    # 1. Blocklist check
    if package.name in config.blocklist:
        return PrefilterResult(
            passed=False,
            reason=f"Package '{package.name}' is in the blocklist",
            risk_level=RiskLevel.CRITICAL,
            risk_signals=["blocklisted"],
        )

    # 2. Whitelist check
    if package.name in config.whitelist:
        return PrefilterResult(
            passed=True,
            reason=f"Package '{package.name}' is whitelisted",
            risk_level=RiskLevel.NONE,
        )

    # 3. Typosquatting detection
    typo_matches = check_typosquatting(package.name, package.ecosystem)
    if typo_matches:
        signals.append(f"typosquat_candidate: similar to {typo_matches}")

    # 4. Metadata anomalies
    meta_signals = check_metadata_anomalies(package)
    signals.extend(meta_signals)

    # 5. Source code dangerous patterns
    if source_files:
        code_signals = check_dangerous_patterns(
            source_files,
            ecosystem=package.ecosystem,
            config=config,
        )
        signals.extend(code_signals)

    # 5.0 Evasion detector static pass (Phase 3 T9 + T8 aggregator)
    # Results are RiskSignal objects; aggregator collapses LOW/MEDIUM clusters
    # per T8 rules. HIGH/CRITICAL always preserved individually.
    if source_files:
        _raw = _run_evasion_static(source_files)
        evasion_signals.extend(_aggregate_evasion(_raw))

    # 5.1 Ecosystem-specific compile-time-attack signals (Rust / crates)
    if source_files and package.ecosystem in ("crates", "cargo"):
        signals.extend(check_crates_risks(source_files))

    # 5.2 Ecosystem-specific signals for CocoaPods (Phase 3 opensrc-integration-plan)
    if source_files and package.ecosystem in ("cocoapods", "pods"):
        signals.extend(check_cocoapods_risks(source_files))

    # 5.5 Extension mismatch detection — catch disguised code files
    if source_files:
        mismatch_signals = check_extension_mismatch(source_files)
        signals.extend(mismatch_signals)

    # 6. Compound signal detection — ONLY on install-time files
    #    Normal source files (flask/cli.py, numpy/__init__.py) commonly have
    #    exec() + .env + subprocess which are legitimate. Chain analysis only
    #    makes sense for files that run at install/import time.
    if source_files:
        install_only = _filter_install_files(source_files)
        if install_only:
            per_file = _build_per_file_signals(install_only, package.ecosystem, config=config)
            compound_signals = check_compound_signals(per_file)
            signals.extend(compound_signals)

    # 7. Behavior chain detection — ONLY on install-time files
    #    Same reasoning: download→decode→execute in setup.py = attack.
    #    download→decode→execute in regular library code = normal.
    if source_files:
        install_only = _filter_install_files(source_files)
        if install_only:
            chain_matches = detect_behavior_chains(install_only)
            signals.extend(m.to_signal() for m in chain_matches)

    # 8. Shannon entropy check for obfuscation
    if source_files:
        entropy_signals = check_high_entropy(source_files)
        signals.extend(entropy_signals)

    # Determine risk level and whether AI review is needed.
    # Evasion RiskSignals remain structured so T14 multi-evasion gate in
    # decision_from_prefilter sees them via isinstance(s, RiskSignal) filter.
    all_signals: list[str | RiskSignal] = [*signals, *evasion_signals]
    risk_level = _calculate_risk_level(all_signals)
    needs_ai = risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

    if not all_signals:
        return PrefilterResult(
            passed=True,
            reason="No risk signals detected",
            risk_level=RiskLevel.NONE,
        )

    return PrefilterResult(
        passed=not needs_ai,
        reason=f"Found {len(all_signals)} risk signal(s)",
        risk_signals=all_signals,
        risk_level=risk_level,
        needs_ai_review=needs_ai,
    )


def check_typosquatting(name: str, ecosystem: str) -> list[str]:
    """Check if package name is suspiciously similar to popular packages.

    Uses cached dynamic lists (fetched by ``get_popular_packages``) when
    available, otherwise falls back to the hardcoded sets above.
    """
    # Always start with hardcoded sets (guaranteed baseline)
    # Reviewer bug_011 / US-010: keys must match resolver's canonicalized
    # ecosystem strings. resolver normalizes Rust to "crates" not "cargo";
    # cocoapods/jsr were added in this PR but never indexed here. Unknown
    # ecosystems fall back to an EMPTY set (not POPULAR_PYPI) to avoid
    # cross-ecosystem similarity false positives.
    popular_map: dict[str, set[str]] = {
        "pypi": POPULAR_PYPI,
        "npm": POPULAR_NPM,
        "crates": POPULAR_CARGO,
        "cargo": POPULAR_CARGO,  # legacy alias retained for back-compat
        "gem": POPULAR_GEM,
        "composer": POPULAR_COMPOSER,
        "go": POPULAR_GO,
        "nuget": POPULAR_NUGET,
        "cocoapods": POPULAR_COCOAPODS,
        "pods": POPULAR_COCOAPODS,  # alias matching resolver's accepted forms
        "jsr": POPULAR_JSR,
    }
    if ecosystem not in popular_map:
        logger.warning(
            "check_typosquatting: no popular_map entry for ecosystem '%s' "
            "— skipping typosquat check",
            ecosystem,
        )
        return []
    popular = popular_map[ecosystem]

    # Merge with dynamic cache if available (extends, never replaces)
    cached = _read_cache(ecosystem)
    if cached:
        popular |= cached
    # For Go modules, compare only the last path segment (e.g. github.com/gin-gonic/gim → gim)
    compare_name = name.rsplit("/", 1)[-1] if ecosystem == "go" else name
    matches = []
    for known in popular:
        if compare_name == known:
            continue
        similarity = SequenceMatcher(None, compare_name.lower(), known.lower()).ratio()
        if similarity >= TYPO_SIMILARITY_THRESHOLD:
            matches.append(f"{known} ({similarity:.0%})")
    return matches


def check_metadata_anomalies(package: PackageInfo) -> list[str]:
    """Check for suspicious metadata patterns."""
    signals = []

    if not package.author:
        signals.append("no_author: package has no author information")

    if not package.repository and not package.homepage:
        signals.append("no_repo: no repository or homepage URL")

    if package.download_count > 0 and package.download_count < 100:
        signals.append(f"low_downloads: only {package.download_count} downloads")

    if package.has_install_scripts:
        signals.append("has_install_scripts: package has install-time scripts")

    return signals


def check_dangerous_patterns(
    source_files: dict[str, str],
    package_name: str = "",
    ecosystem: str = "*",
    config: Config | None = None,
) -> list[str]:
    """Check source code for dangerous patterns using YAML rules."""
    signals: list[str] = []
    rules = _get_rules(config)

    # Files that run at install/import time — patterns here are HIGH risk
    install_files = {
        "setup.py",
        "setup.cfg",
        "postinstall.js",
        "preinstall.js",
        "install.js",
        "prepare.js",
        # crates: build.rs runs at ``cargo build`` time, same trust profile.
        "build.rs",
    }
    # Files that are HIGH only at package root (not in subdirs like tests/)
    root_only_install_files = {
        "conftest.py",
        "__main__.py",
        "Makefile",
        "CMakeLists.txt",
        "__init__.py",
        "setup.js",
    }
    # Skip non-code files — docs, configs, CI pipelines describe usage, not malicious behavior
    skip_extensions = {
        ".md",
        ".rst",
        ".txt",
        ".html",
        ".css",
        ".yml",
        ".yaml",
        ".toml",
        ".cfg",
        ".ini",
        ".json",
        ".lock",
    }
    # Skip CI/CD and config directories entirely
    skip_dirs = {
        ".github",
        ".circleci",
        ".gitlab",
        ".travis",
        ".jenkins",
        "__pycache__",
        "node_modules",
        ".git",
    }

    for filepath, content in source_files.items():
        filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
        suffix = ("." + filename.rsplit(".", 1)[-1]).lower() if "." in filename else ""
        is_pth = filepath.endswith(".pth")
        # Root-only install files: only HIGH if at package root (1 level deep like pkg-1.0/Makefile)
        depth = filepath.count("/")
        is_root_install = filename in root_only_install_files and depth <= 1
        is_install_file = filename in install_files or is_pth or is_root_install

        # S2: .pth files auto-generate HIGH signal regardless of content
        if is_pth:
            signals.append(f"dangerous_pattern(HIGH): '.pth file' in install_script:{filepath}")

        # Skip files in CI/config directories (never contain install-time attacks)
        if any(part in skip_dirs for part in filepath.split("/")):
            continue
        # Skip non-code files, but never skip install files (e.g. CMakeLists.txt)
        if suffix in skip_extensions and not is_install_file:
            continue

        for rule in rules:
            # Ecosystem filter: rule applies if ecosystem is "*" or matches
            if rule.ecosystem != "*" and rule.ecosystem != ecosystem:
                continue

            # Scope filter: install_script rules only apply to install files,
            # source rules only apply to non-install files, any applies to both
            if rule.scope == "install_script" and not is_install_file:
                continue
            if rule.scope == "source" and is_install_file:
                continue

            if rule.pattern.search(content):
                label = "install_script" if is_install_file else "source"
                # Install scripts (setup.py, postinstall.js) are HIGH risk —
                # code there runs automatically at install time.
                # Regular source files are LOW — patterns like requests.get()
                # or subprocess are normal library code, not attack indicators.
                if is_install_file:
                    # Use at least HIGH for install scripts
                    sev_ord = max(_SEVERITY_ORDER.get(rule.severity, 0), _SEVERITY_ORDER["high"])
                else:
                    # Regular source: always LOW
                    sev_ord = _SEVERITY_ORDER["low"]
                risk = _SEVERITY_LABEL[sev_ord]
                signals.append(
                    f"dangerous_pattern({risk}): '{rule.pattern.pattern}' in {label}:{filepath}"
                )

    return signals


def check_extension_mismatch(source_files: dict[str, str]) -> list[str]:
    """Detect files whose content type mismatches their extension.

    Catches attacks where malicious code is disguised with a non-code
    extension (e.g. Python saved as .png) or has no extension at all.
    """
    from .content_sniff import detect_extension_mismatch

    signals: list[str] = []
    for filepath, content in source_files.items():
        mismatch = detect_extension_mismatch(filepath, content)
        if mismatch:
            signals.append(f"extension_mismatch(HIGH): {mismatch} in {filepath}")
    return signals


# Regex: ``proc-macro = true`` inside a ``[lib]`` table.
# Permissive whitespace, accepts single/double-quoted bool too.
_PROC_MACRO_RE = re.compile(
    r"^\s*proc[-_]macro\s*=\s*(?:true|\"true\"|'true')\s*$",
    re.MULTILINE | re.IGNORECASE,
)

# Regex: ``lib.proc-macro = true`` style (inline, single-line) — rarer.
_PROC_MACRO_INLINE_RE = re.compile(
    r"proc[-_]macro\s*=\s*(?:true|\"true\"|'true')",
    re.IGNORECASE,
)

# Network-at-build-time detectors for build.rs content. Each presence is HIGH.
_BUILD_RS_NETWORK_PATTERNS = [
    (re.compile(r"\breqwest\b"), "reqwest"),
    (re.compile(r"\bureq\b"), "ureq"),
    (re.compile(r"\bhyper\b"), "hyper"),
    (re.compile(r"\bstd::net::"), "std::net"),
    (re.compile(r"\bTcpStream\b"), "TcpStream"),
    (re.compile(r"\bCommand::new\s*\(\s*\"(?:curl|wget|nc|bash|sh)\""), "Command(curl/wget/sh)"),
]


def check_crates_risks(source_files: dict[str, str]) -> list[str]:
    """Rust-specific risk signals for crates.io packages.

    Emits HIGH-severity signals per PRD §3.2 and Architect P2 #6:

    * ``build.rs`` presence → arbitrary code at ``cargo build`` time.
    * ``proc-macro = true`` in a ``Cargo.toml`` → arbitrary code at compile time.
    * Network calls or shell-outs inside ``build.rs`` → HIGH.

    All three are severity-HIGH to match aigate's existing npm ``postinstall``
    handling (Architect P2 #6). These are detected additively — presence alone
    is enough; further pattern matches inside ``build.rs`` (e.g. subprocess,
    env-var exfil) already fire via ``check_dangerous_patterns``.
    """
    signals: list[str] = []

    for filepath, content in source_files.items():
        filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath

        # build.rs presence — HIGH (matches npm postinstall severity).
        if filename == "build.rs":
            signals.append(
                "dangerous_pattern(HIGH): "
                f"'build.rs' in install_script:{filepath} "
                "(executes arbitrary code at cargo build time)"
            )
            # Network-at-build-time — bump when additional network deps are
            # used during the build (far more suspicious than a build.rs that
            # just links a .a file).
            for pattern, label in _BUILD_RS_NETWORK_PATTERNS:
                if pattern.search(content):
                    signals.append(
                        "dangerous_pattern(HIGH): "
                        f"'build.rs:{label}' in install_script:{filepath} "
                        "(network or subprocess from build script)"
                    )

        # proc-macro = true in any Cargo.toml — HIGH.
        if filename == "Cargo.toml":
            if _PROC_MACRO_RE.search(content) or _PROC_MACRO_INLINE_RE.search(content):
                signals.append(
                    "dangerous_pattern(HIGH): "
                    f"'proc-macro=true' in install_script:{filepath} "
                    "(proc-macro crate — executes arbitrary code at compile time)"
                )

    return signals


def check_cocoapods_risks(source_files: dict[str, str]) -> list[str]:
    """CocoaPods-specific risk signals (Phase 3 opensrc-integration-plan §3.3).

    Emits:

    * HIGH when ``__aigate__/cocoapods-divergence.txt`` is present (synthetic
      signal file injected by ``_download_cocoapods_source`` when the
      GitHub-tarball file list diverges from the podspec's advertised
      ``source_files`` — aigate-unique defense against the git-archive-vs-
      checkout / export-ignore attack class). See T-COC-DIV-1 / T-COC-DIV-2.
    * HIGH when a ``.gitattributes`` file contains ``export-ignore`` directives
      that could hide malicious files from ``git archive`` while still landing
      them in a ``git checkout`` (same attack class; the resolver already
      suppresses the divergence signal when ``.gitattributes`` exists, so
      users still get a HIGH signal here to surface the condition).
    """
    signals: list[str] = []

    for filepath, content in source_files.items():
        if filepath == "__aigate__/cocoapods-divergence.txt":
            signals.append(
                f"suspicious_pattern(HIGH): podspec-vs-tarball path divergence ({content.strip()})"
            )
        if filepath.endswith(".gitattributes") and "export-ignore" in (content or ""):
            signals.append(
                "suspicious_pattern(HIGH): "
                f"'.gitattributes export-ignore' in install_script:{filepath} "
                "(can hide files from git archive, may differ from git checkout)"
            )

    return signals


def _filter_install_files(source_files: dict[str, str]) -> dict[str, str]:
    """Return only install-time files from source_files.

    Install-time files (setup.py, postinstall.js, .pth, etc.) run automatically
    during package installation or first import. Compound and behavior chain
    analysis is restricted to these files to avoid false positives on normal
    library code (e.g., flask using exec() + .env is legitimate).
    """
    install_names = {
        "setup.py",
        "setup.cfg",
        "postinstall.js",
        "preinstall.js",
        "install.js",
        "prepare.js",
        # crates: build.rs runs at ``cargo build`` time — same trust profile
        # as npm postinstall / python setup.py.
        "build.rs",
    }
    result = {}
    for filepath, content in source_files.items():
        filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
        depth = filepath.count("/")
        is_install = (
            filename in install_names
            or filepath.endswith(".pth")
            or (
                filename
                in {
                    "conftest.py",
                    "__main__.py",
                    "Makefile",
                    "CMakeLists.txt",
                    "__init__.py",
                    "setup.js",
                }
                and depth <= 1
            )
        )
        if is_install:
            result[filepath] = content
    return result


def _build_per_file_signals(
    source_files: dict[str, str],
    ecosystem: str = "*",
    config: Config | None = None,
) -> dict[str, list[dict]]:
    """Build per-file signal dicts with rule tags for compound detection.

    Returns a mapping of ``filepath`` → list of ``{"rule_id": ..., "tags": [...]}``.
    Only code files are scanned (same skip logic as ``check_dangerous_patterns``).
    """
    rules = _get_rules(config)
    skip_extensions = {
        ".md",
        ".rst",
        ".txt",
        ".html",
        ".css",
        ".yml",
        ".yaml",
        ".toml",
        ".cfg",
        ".ini",
        ".json",
        ".lock",
    }
    skip_dirs = {
        ".github",
        ".circleci",
        ".gitlab",
        ".travis",
        ".jenkins",
        "__pycache__",
        "node_modules",
        ".git",
    }

    result: dict[str, list[dict]] = {}

    for filepath, content in source_files.items():
        filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
        suffix = ("." + filename.rsplit(".", 1)[-1]).lower() if "." in filename else ""

        if any(part in skip_dirs for part in filepath.split("/")):
            continue
        if suffix in skip_extensions:
            continue

        for rule in rules:
            if rule.ecosystem != "*" and rule.ecosystem != ecosystem:
                continue
            if rule.pattern.search(content):
                result.setdefault(filepath, []).append(
                    {"rule_id": rule.id, "tags": list(rule.tags)}
                )

    return result


def check_high_entropy(
    source_files: dict[str, str],
    threshold: float = 5.5,
) -> list[str]:
    """Detect obfuscated code via Shannon entropy."""
    signals = []
    for filepath, content in source_files.items():
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if len(stripped) < 80:
                continue
            entropy = _shannon_entropy(stripped)
            if entropy > threshold:
                signals.append(
                    f"high_entropy({entropy:.2f}): {filepath}:{i} "
                    f"(possible obfuscation, threshold={threshold})"
                )
    return signals


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# Evasion categories — single-HIGH must not auto-escalate to MALICIOUS here.
# Per plan REV-NI2, autonomous blocking requires ≥2 orthogonal HIGH tactics
# (enforced by T14 multi-evasion gate in policy.py). Legacy _calculate_risk_level
# would otherwise bypass the gate via the 1-HIGH→HIGH→MALICIOUS chain.
_EVASION_CATEGORIES: frozenset[str] = frozenset(
    {
        "env_mutation",
        "time_bomb",
        "build_hooks",
        "derived_exfil",
        "direct_xpc",
        "anti_debug",
        "parser_partial_drift",
    }
)


def _is_evasion_signal(s: str | RiskSignal) -> bool:
    return isinstance(s, RiskSignal) and s.category in _EVASION_CATEGORIES


def _signal_severity(s: str | RiskSignal) -> RiskLevel:
    """Extract severity from a signal (structured or legacy string)."""
    if isinstance(s, RiskSignal):
        return s.severity
    # Legacy string parsing fallback
    if "CRITICAL" in s or "blocklist" in s:
        return RiskLevel.CRITICAL
    if "HIGH" in s:
        return RiskLevel.HIGH
    if "MEDIUM" in s or "typosquat" in s:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _calculate_risk_level(signals: Sequence[str | RiskSignal]) -> RiskLevel:
    """Calculate overall risk level from signals.

    Accepts both structured ``RiskSignal`` objects and legacy format strings.
    Uses unique pattern counts to avoid inflation from the same pattern
    appearing in multiple files (e.g., requests.get() in source + tests).
    """
    if not signals:
        return RiskLevel.NONE

    # Evasion signals are excluded from legacy HIGH escalation — T14 gate in
    # policy.py enforces REV-NI2 (≥2 orthogonal HIGH required for MALICIOUS).
    # They still count toward MEDIUM so needs_ai_review triggers.
    high_count = sum(
        1
        for s in signals
        if _signal_severity(s) in (RiskLevel.HIGH, RiskLevel.CRITICAL) and not _is_evasion_signal(s)
    )

    # Count unique MEDIUM patterns (extract pattern before 'in source:' / 'in install_script:')
    medium_patterns: set[str] = set()
    for s in signals:
        sev = _signal_severity(s)
        # Treat evasion HIGH as MEDIUM for legacy scoring (drives needs_ai_review
        # but does not auto-escalate; T14 gate is the authoritative path).
        if sev == RiskLevel.MEDIUM or (
            _is_evasion_signal(s) and sev in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ):
            s_str = str(s)
            # Extract pattern key: "dangerous_pattern(MEDIUM): 'pattern' in source:file"
            # → key is "pattern" (deduplicate across files)
            if "dangerous_pattern" in s_str and "'" in s_str:
                key = s_str.split("'")[1] if "'" in s_str else s_str
            else:
                key = s_str
            medium_patterns.add(key)
    medium_count = len(medium_patterns)

    if high_count >= 2:
        return RiskLevel.CRITICAL
    if high_count >= 1:
        return RiskLevel.HIGH
    # Only HIGH and MEDIUM signals escalate risk. LOW signals are informational.
    typosquat_count = sum(
        1
        for s in signals
        if (isinstance(s, RiskSignal) and s.category == "typosquat")
        or (isinstance(s, str) and "typosquat" in s)
    )
    escalating = medium_count + typosquat_count

    if medium_count >= 3 or escalating >= 4:
        return RiskLevel.HIGH
    if escalating >= 1:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
