"""Static pre-filter engine — fast checks before AI analysis."""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from difflib import SequenceMatcher

from .config import Config
from .models import PackageInfo, PrefilterResult, RiskLevel

# Top 1000 PyPI packages (abbreviated — expanded at runtime from cache)
POPULAR_PYPI: set[str] = {
    "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
    "setuptools", "pip", "wheel", "pyyaml", "cryptography", "certifi",
    "click", "rich", "httpx", "pydantic", "fastapi", "sqlalchemy",
    "pytest", "black", "ruff", "mypy", "pillow", "scipy", "matplotlib",
    "torch", "tensorflow", "transformers", "openai", "anthropic",
    "litellm", "langchain", "crewai", "dspy",
}

POPULAR_NPM: set[str] = {
    "express", "react", "vue", "angular", "next", "typescript", "lodash",
    "axios", "webpack", "babel", "eslint", "prettier", "jest", "mocha",
    "chalk", "commander", "inquirer", "debug", "moment", "dayjs",
}

# Known dangerous patterns in install scripts
DANGEROUS_PATTERNS: list[re.Pattern] = [
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\b__import__\s*\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\b", re.IGNORECASE),
    re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
    re.compile(r"\bos\.popen\s*\(", re.IGNORECASE),
    re.compile(r"base64\.b64decode", re.IGNORECASE),
    re.compile(r"\bcompile\s*\(.*exec", re.IGNORECASE),
    re.compile(r"requests?\.(get|post|put)\s*\(", re.IGNORECASE),
    re.compile(r"urllib\.request\.urlopen", re.IGNORECASE),
    re.compile(r"httpx?\.(get|post)\s*\(", re.IGNORECASE),
    re.compile(r"\bsocket\b.*connect", re.IGNORECASE),
    re.compile(r"\.ssh/", re.IGNORECASE),
    re.compile(r"\.aws/", re.IGNORECASE),
    re.compile(r"\.env\b", re.IGNORECASE),
    re.compile(r"\.npmrc\b", re.IGNORECASE),
    re.compile(r"\.pypirc\b", re.IGNORECASE),
    re.compile(r"GITHUB_TOKEN|NPM_TOKEN|PYPI_TOKEN|AWS_SECRET", re.IGNORECASE),
]

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
        code_signals = check_dangerous_patterns(source_files)
        signals.extend(code_signals)

    # 6. Shannon entropy check for obfuscation
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
    """Check if package name is suspiciously similar to popular packages."""
    popular = POPULAR_PYPI if ecosystem == "pypi" else POPULAR_NPM
    matches = []
    for known in popular:
        if name == known:
            continue
        similarity = SequenceMatcher(None, name.lower(), known.lower()).ratio()
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
) -> list[str]:
    """Check source code for dangerous patterns."""
    signals = []
    install_files = {"setup.py", "setup.cfg", "postinstall.js", "preinstall.js", "install.js"}
    # Skip docs/readme — they describe API usage, not malicious behavior
    skip_extensions = {".md", ".rst", ".txt", ".html", ".css"}

    for filepath, content in source_files.items():
        filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
        suffix = ("." + filename.rsplit(".", 1)[-1]).lower() if "." in filename else ""
        if suffix in skip_extensions:
            continue
        is_install_file = filename in install_files or filepath.endswith(".pth")

        for pattern in DANGEROUS_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                label = "install_script" if is_install_file else "source"
                risk = "HIGH" if is_install_file else "MEDIUM"
                signals.append(
                    f"dangerous_pattern({risk}): '{pattern.pattern}' in {label}:{filepath}"
                )

    return signals


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
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _calculate_risk_level(signals: Sequence[str]) -> RiskLevel:
    """Calculate overall risk level from signals."""
    if not signals:
        return RiskLevel.NONE

    high_count = sum(1 for s in signals if "HIGH" in s or "blocklist" in s)
    medium_count = sum(1 for s in signals if "MEDIUM" in s or "typosquat" in s)

    if high_count >= 2:
        return RiskLevel.CRITICAL
    if high_count >= 1:
        return RiskLevel.HIGH
    if medium_count >= 2 or len(signals) >= 4:
        return RiskLevel.HIGH
    if medium_count >= 1 or len(signals) >= 2:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
