"""Static pre-filter engine — fast checks before AI analysis."""

from __future__ import annotations

import math
from collections.abc import Sequence
from difflib import SequenceMatcher

from .config import Config
from .models import PackageInfo, PrefilterResult, RiskLevel
from .rules.compound import check_compound_signals
from .rules.loader import Rule, load_rules
from .rules.popular_packages import _read_cache

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

    # 6. Compound signal detection (multi-indicator attack chains)
    if source_files:
        per_file = _build_per_file_signals(source_files, package.ecosystem, config=config)
        compound_signals = check_compound_signals(per_file)
        signals.extend(compound_signals)

    # 7. Shannon entropy check for obfuscation
    if source_files:
        entropy_signals = check_high_entropy(source_files)
        signals.extend(entropy_signals)

    # Determine risk level and whether AI review is needed
    risk_level = _calculate_risk_level(signals)
    needs_ai = risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

    if not signals:
        return PrefilterResult(
            passed=True,
            reason="No risk signals detected",
            risk_level=RiskLevel.NONE,
        )

    return PrefilterResult(
        passed=not needs_ai,
        reason=f"Found {len(signals)} risk signal(s)",
        risk_signals=signals,
        risk_level=risk_level,
        needs_ai_review=needs_ai,
    )


def check_typosquatting(name: str, ecosystem: str) -> list[str]:
    """Check if package name is suspiciously similar to popular packages.

    Uses cached dynamic lists (fetched by ``get_popular_packages``) when
    available, otherwise falls back to the hardcoded sets above.
    """
    # Try dynamic cache first (sync read, no network call)
    popular = _read_cache(ecosystem)

    if popular is None:
        # Fallback to hardcoded sets
        popular_map: dict[str, set[str]] = {
            "pypi": POPULAR_PYPI,
            "npm": POPULAR_NPM,
            "cargo": POPULAR_CARGO,
            "gem": POPULAR_GEM,
            "composer": POPULAR_COMPOSER,
            "go": POPULAR_GO,
            "nuget": POPULAR_NUGET,
        }
        popular = popular_map.get(ecosystem, POPULAR_PYPI)
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
    }
    # Files that are HIGH only at package root (not in subdirs like tests/)
    root_only_install_files = {
        "conftest.py",
        "__main__.py",
        "Makefile",
        "CMakeLists.txt",
        "__init__.py",
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


def _calculate_risk_level(signals: Sequence[str]) -> RiskLevel:
    """Calculate overall risk level from signals.

    Uses unique pattern counts to avoid inflation from the same pattern
    appearing in multiple files (e.g., requests.get() in source + tests).
    """
    if not signals:
        return RiskLevel.NONE

    high_count = sum(1 for s in signals if "HIGH" in s or "CRITICAL" in s or "blocklist" in s)

    # Count unique MEDIUM patterns (extract pattern before 'in source:' / 'in install_script:')
    medium_patterns: set[str] = set()
    for s in signals:
        if "MEDIUM" in s or "typosquat" in s:
            # Extract pattern key: "dangerous_pattern(MEDIUM): 'pattern' in source:file"
            # → key is "pattern" (deduplicate across files)
            if "dangerous_pattern" in s and "'" in s:
                key = s.split("'")[1] if "'" in s else s
            else:
                key = s
            medium_patterns.add(key)
    medium_count = len(medium_patterns)

    if high_count >= 2:
        return RiskLevel.CRITICAL
    if high_count >= 1:
        return RiskLevel.HIGH
    # Only HIGH and MEDIUM signals escalate risk. LOW signals are informational.
    # Typosquat is always MEDIUM-equivalent.
    typosquat_count = sum(1 for s in signals if "typosquat" in s)
    escalating = medium_count + typosquat_count

    if medium_count >= 3 or escalating >= 4:
        return RiskLevel.HIGH
    if escalating >= 1:
        return RiskLevel.MEDIUM
    if high_count == 0 and escalating == 0:
        return RiskLevel.LOW
    return RiskLevel.LOW
