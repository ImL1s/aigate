"""Behavior chain detection — API-agnostic attack pattern matching.

Inspired by SpiderScan's graph-based behavior modeling and CHASE's multi-stage
attack chain dissection.  Instead of matching specific API names, we match
*behavior categories* (download, decode, write, execute, persist, exfiltrate,
credential_access) and then check whether combinations of those behaviors form
known attack chains.

Key difference from ``compound.py``:
- compound.py checks rule TAG co-occurrence (tied to specific YAML rules).
- This module checks BEHAVIOR CATEGORY co-occurrence (API-agnostic), covering
  future unknown APIs as long as they fit a behavior category.

Known limitation: patterns are matched against raw source text, so code inside
comments and docstrings will also match.  This is acceptable for a pre-filter
(false positives are cheaper than false negatives) but should be noted when
triaging results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Behavior definitions — each maps to multiple API patterns
# ---------------------------------------------------------------------------

BEHAVIORS: dict[str, dict] = {
    "download": {
        "description": "Fetching remote content",
        "patterns": [
            r"\burllib\.request\.urlopen\b",
            r"\burlopen\s*\(",
            r"\burllib\b.*\burlretrieve\b",
            r"\brequests?\.\bget\b",
            r"\bhttpx?\.\bget\b",
            r"\bhttps?\.\b(?:get|request)\b",
            r"\bfetch\s*\(",
            r"\bcurl\b",
            r"\bwget\b",
            r"\bsocket\b.*\b(?:connect|getaddrinfo)\b",
            r"\bdns\b.*\bresolv",
        ],
    },
    "decode": {
        "description": "Decoding/deobfuscating data",
        "patterns": [
            r"\bbase64\b.*\b(?:b64decode|decode)\b",
            r"Buffer\.from\b.*base64",
            r"\.split\(['\"].*\)\.reverse\(\)\.join",
            r"\batob\s*\(",
            r"\bxor\b",
            r"\bmarshal\.loads\b",
            r"\bpickle\.loads\b",
            r"\bzlib\.decompress\b",
            r"\bString\.fromCharCode\b",
        ],
    },
    "write": {
        "description": "Writing to filesystem",
        "patterns": [
            r"\bopen\s*\(.*['\"]w",
            r"\bfs\.(?:writeFileSync|writeFile|appendFile)\b",
            r"\bshutil\.copy\b",
            r"\bos\.(?:rename|replace)\b",
        ],
    },
    "execute": {
        "description": "Executing code/commands",
        "patterns": [
            r"\bexec\s*\(",
            r"\beval\s*\(",
            r"\bexecSync\s*\(",
            r"\bsubprocess\b",
            r"\bos\.system\s*\(",
            r"\bos\.popen\s*\(",
            r"\bchild_process\b",
            r"\b__import__\s*\(",
            r"\bFunction\s*\(",
        ],
    },
    "persist": {
        "description": "Establishing persistence",
        "patterns": [
            r"/Library/(?:Caches|LaunchAgents|LaunchDaemons)",
            r"\.pth\b",
            r"crontab",
            r"systemd",
            r"LaunchAgent",
            r"HKEY_",
            r"chmod\s+\+x",
            r"/tmp/.*\.(?:py|sh|bin)",
            r"%PROGRAMDATA%",
            r"%APPDATA%",
            r"autostart",
        ],
    },
    "exfiltrate": {
        "description": "Sending data to external server",
        "patterns": [
            r"\b(?:requests?|httpx?)\.post\s*\(",
            r"urllib\.request\.urlopen.*data=",
            r"webhook",
            r"discord\.com/api/webhooks",
            r"telegram\.org/bot",
        ],
    },
    "credential_access": {
        "description": "Accessing credentials/secrets",
        "patterns": [
            r"\.ssh/",
            r"\.aws/",
            r"\.env\b(?!iron)",
            r"\.npmrc\b",
            r"\.pypirc\b",
            r"GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET",
            r"keychain",
            r"\.gnupg/",
            r"\.kube/config",
        ],
    },
}

# Pre-compile all patterns for performance
_COMPILED_BEHAVIORS: dict[str, list[re.Pattern[str]]] = {
    name: [re.compile(p, re.IGNORECASE) for p in info["patterns"]]
    for name, info in BEHAVIORS.items()
}

# ---------------------------------------------------------------------------
# Attack chain definitions
# ---------------------------------------------------------------------------

ATTACK_CHAINS: list[dict] = [
    {
        "id": "dropper",
        "description": "Download and execute remote payload",
        "chain": ["download", "execute"],
        "severity": "high",
    },
    {
        "id": "encoded-dropper",
        "description": "Download, decode, and execute obfuscated payload",
        "chain": ["download", "decode", "execute"],
        "severity": "critical",
    },
    {
        "id": "rat-deployment",
        "description": "Download, write, execute, and persist (RAT)",
        "chain": ["download", "write", "execute", "persist"],
        "severity": "critical",
    },
    {
        "id": "credential-theft",
        "description": "Access credentials and exfiltrate",
        "chain": ["credential_access", "exfiltrate"],
        "severity": "critical",
    },
    {
        "id": "staged-credential-theft",
        "description": "Access credentials, encode, and exfiltrate",
        "chain": ["credential_access", "decode", "exfiltrate"],
        "severity": "critical",
    },
    {
        "id": "obfuscated-execution",
        "description": "Decode obfuscated payload and execute",
        "chain": ["decode", "execute"],
        "severity": "high",
    },
    {
        "id": "persistent-backdoor",
        "description": "Execute and establish persistence",
        "chain": ["execute", "persist"],
        "severity": "critical",
    },
    {
        "id": "full-attack-chain",
        "description": "Complete attack: download -> decode -> write -> execute -> persist",
        "chain": ["download", "decode", "write", "execute", "persist"],
        "severity": "critical",
    },
]

# ---------------------------------------------------------------------------
# File extensions to skip (non-code files)
# ---------------------------------------------------------------------------

_SKIP_EXTENSIONS = {
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

_SKIP_DIRS = {
    ".github",
    ".circleci",
    ".gitlab",
    ".travis",
    ".jenkins",
    "__pycache__",
    "node_modules",
    ".git",
}

# Severity label mapping
_SEVERITY_LABEL = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}


# ---------------------------------------------------------------------------
# Data class for results
# ---------------------------------------------------------------------------


@dataclass
class BehaviorChainMatch:
    """A single matched attack chain in a specific file."""

    chain_id: str
    description: str
    severity: str
    file_path: str
    detected_behaviors: set[str] = field(default_factory=set)

    def to_signal(self) -> str:
        """Format as a prefilter-compatible signal string."""
        label = _SEVERITY_LABEL.get(self.severity, "HIGH")
        behaviors = ", ".join(sorted(self.detected_behaviors))
        return (
            f"behavior_chain({label}): '{self.chain_id}' in {self.file_path}"
            f" -- {self.description} [behaviors: {behaviors}]"
        )


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def _detect_behaviors_in_content(content: str) -> set[str]:
    """Scan content and return set of detected behavior categories."""
    detected: set[str] = set()
    for behavior_name, patterns in _COMPILED_BEHAVIORS.items():
        for pattern in patterns:
            if pattern.search(content):
                detected.add(behavior_name)
                break  # One match is enough for this behavior
    return detected


def _should_skip_file(filepath: str) -> bool:
    """Return True if the file should be skipped (non-code, CI dirs, etc.)."""
    # Check skip dirs
    parts = filepath.split("/")
    if any(part in _SKIP_DIRS for part in parts):
        return True

    # Check extension
    filename = parts[-1] if parts else filepath
    if "." in filename:
        suffix = "." + filename.rsplit(".", 1)[-1].lower()
        if suffix in _SKIP_EXTENSIONS:
            return True

    return False


def detect_behavior_chains(source_files: dict[str, str]) -> list[BehaviorChainMatch]:
    """Detect attack behavior chains in source files.

    For each file, scans content against all behavior patterns, then checks
    whether any known attack chain is a subset of detected behaviors.
    Detection is file-scoped: behaviors in different files do NOT combine.

    Args:
        source_files: Mapping of file path to file content.

    Returns:
        List of :class:`BehaviorChainMatch` for every chain matched.
    """
    all_matches: list[BehaviorChainMatch] = []

    for filepath, content in source_files.items():
        if _should_skip_file(filepath):
            continue

        detected = _detect_behaviors_in_content(content)
        if len(detected) < 2:
            continue

        # Check each attack chain — most specific first (longest chain)
        for chain_def in sorted(ATTACK_CHAINS, key=lambda c: len(c["chain"]), reverse=True):
            required = set(chain_def["chain"])
            if required.issubset(detected):
                # Don't suppress sub-chains: report all matching chains
                # so that severity escalation works correctly
                all_matches.append(
                    BehaviorChainMatch(
                        chain_id=chain_def["id"],
                        description=chain_def["description"],
                        severity=chain_def["severity"],
                        file_path=filepath,
                        detected_behaviors=detected & required,
                    )
                )

    return all_matches
