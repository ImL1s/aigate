"""AI agent vector scanning — detect suspicious patterns in MCP configs, skills, and rules files.

Scans for:
- Reverse shells, netcat listeners, eval/exec chains
- Credential access (.ssh/, .aws/, .env)
- Shell pipe attacks (curl|sh)
- Prompt injection in AI rules files
- Raw IP URLs (potential C2 servers)
"""

from __future__ import annotations

import json
import re

SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"reverse.?shell", "reverse shell reference"),
    (r"nc\s+-[elp]", "netcat listener"),
    (r"\beval\b.*\bexec\b", "eval/exec chain"),
    (r"curl.*\|\s*(?:ba|z)?sh", "curl piped to shell"),
    (r"wget.*\|\s*(?:ba|z)?sh", "wget piped to shell"),
    (r"\.ssh/", "SSH directory access"),
    (r"\.aws/", "AWS credentials access"),
    (r"\.env\b", ".env file access"),
    (r"ignore\s+(?:all\s+)?previous\s+instructions", "prompt injection attempt"),
    (r"(?:always|must|should)\s+hardcode", "hardcoded credential reference"),
    (r"http://\d+\.\d+\.\d+\.\d+", "raw IP URL (potential C2)"),
]


def scan_file_for_suspicious_patterns(content: str) -> list[str]:
    """Scan text content for suspicious patterns.

    Returns list of human-readable findings, one per match.
    """
    findings: list[str] = []
    for pattern, description in SUSPICIOUS_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            # Get surrounding context (up to 40 chars each side)
            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(f"{description}: ...{context}...")
    return findings


def scan_mcp_config(config_content: str) -> list[str]:
    """Scan MCP server config JSON for suspicious command patterns.

    Parses JSON config and inspects command/args fields for dangerous patterns.
    Also runs the generic pattern scanner on the full content.
    """
    findings: list[str] = []

    # Try to parse as JSON and inspect structured fields
    try:
        config = json.loads(config_content)
    except (json.JSONDecodeError, TypeError):
        # Not valid JSON — still scan as raw text
        return scan_file_for_suspicious_patterns(config_content)

    # Walk the config looking for "command" and "args" fields
    def _walk(obj: object, path: str = "") -> None:
        if isinstance(obj, dict):
            cmd = obj.get("command", "")
            args = obj.get("args", [])
            if isinstance(cmd, str) and cmd:
                cmd_str = cmd
                if isinstance(args, list):
                    cmd_str += " " + " ".join(str(a) for a in args)
                for pattern, description in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, cmd_str, re.IGNORECASE):
                        findings.append(
                            f"MCP server {path or 'root'}: {description} in command: {cmd_str[:80]}"
                        )
            for key, val in obj.items():
                _walk(val, path=f"{path}.{key}" if path else key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, path=f"{path}[{i}]")

    _walk(config)

    # Also scan the raw text for anything the structured walk missed
    raw_findings = scan_file_for_suspicious_patterns(config_content)
    # Deduplicate: only add raw findings not already covered
    existing_descriptions = {f.split(":")[0] for f in findings}
    for rf in raw_findings:
        desc = rf.split(":")[0]
        if desc not in existing_descriptions:
            findings.append(rf)

    return findings


def scan_rules_file(content: str) -> list[str]:
    """Scan .cursorrules/.windsurfrules/.claude files for hidden prompt injection.

    Looks for:
    - Prompt injection phrases ("ignore previous instructions")
    - Hidden instructions using Unicode tricks (zero-width chars, RTL override)
    - Suspicious shell commands embedded in rules
    - Credential exfiltration patterns
    """
    findings: list[str] = []

    # Standard pattern scan
    findings.extend(scan_file_for_suspicious_patterns(content))

    # Check for hidden Unicode characters (zero-width space, RTL override, etc.)
    hidden_unicode = re.findall(r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\ufeff]", content)
    if hidden_unicode:
        findings.append(
            f"hidden Unicode characters detected ({len(hidden_unicode)} occurrences) "
            "— possible invisible prompt injection"
        )

    # Check for base64-encoded payloads (often used to hide malicious commands)
    b64_m = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", content)
    for match in b64_m:
        findings.append(f"possible base64-encoded payload: {match[:50]}...")

    return findings
