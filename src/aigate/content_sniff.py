"""Lightweight content-aware file type detection.

Zero-dependency sniffing via shebang lines, AST probes, and structural
heuristics.  Used to catch files with disguised or missing extensions
(e.g. malicious Python saved as .png).

For AI-powered detection, see the optional ``magika`` integration.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

# --------------------------------------------------------------------------
# Shebang patterns
# --------------------------------------------------------------------------

_SHEBANG_MAP: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^#!.*\bpython[23]?\b"), "python"),
    (re.compile(r"^#!.*\bnode\b"), "javascript"),
    (re.compile(r"^#!.*\b(?:ba)?sh\b"), "shell"),
    (re.compile(r"^#!.*\bperl\b"), "perl"),
    (re.compile(r"^#!.*\bruby\b"), "ruby"),
    (re.compile(r"^#!.*\bphp\b"), "php"),
]

# --------------------------------------------------------------------------
# Structural probes — cheap regex checks for language-specific patterns
# --------------------------------------------------------------------------

# Python: import/from statements, def/class keywords
_PYTHON_PROBE = re.compile(
    r"(?m)"
    r"(?:^import\s+\w+|^from\s+\w+\s+import\s+|"
    r"^(?:def|class)\s+\w+\s*[\(:]|"
    r"^if\s+__name__\s*==\s*['\"]__main__['\"])",
)

# JavaScript: require(), module.exports, import/export
_JS_PROBE = re.compile(
    r"(?m)"
    r"(?:\brequire\s*\(['\"]|"
    r"\bmodule\.exports\b|"
    r"^import\s+\{?\s*\w+.*\bfrom\s+['\"]|"
    r"^export\s+(?:default|const|function|class)\b)",
)

# JSON: starts with { or [
_JSON_PROBE = re.compile(r"^\s*[\[{]")

# Binary: high ratio of null bytes or control characters
_BINARY_THRESHOLD = 0.10  # >10% non-text bytes = binary

# Content types that represent executable/scriptable code.
# Used by resolver and prefilter to decide which sniffed files to extract.
CODE_TYPES: frozenset[str] = frozenset({"python", "javascript", "shell", "ruby", "perl", "php"})

# Extensions that map to content types
_EXT_TO_TYPE: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".pth": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".sh": "shell",
    ".bash": "shell",
    ".bat": "shell",
    ".cmd": "shell",
    ".rb": "ruby",
    ".pl": "perl",
    ".php": "php",
    ".dart": "dart",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".cfg": "config",
    ".ini": "config",
    ".md": "markdown",
    ".rst": "markdown",
    ".txt": "text",
    ".html": "html",
    ".css": "css",
}


def _is_likely_binary(content: str) -> bool:
    """Return True if content looks like decoded binary (many replacement chars)."""
    if not content:
        return False
    non_text = sum(1 for c in content[:4096] if ord(c) < 9 or (13 < ord(c) < 32))
    return (non_text / min(len(content), 4096)) > _BINARY_THRESHOLD


def sniff_content_type(content: str) -> str | None:
    """Detect the content type of a file from its text content.

    Returns a type string (e.g. "python", "javascript", "shell") or None
    if the content type cannot be determined or is binary.
    """
    if not content or _is_likely_binary(content):
        return None

    # 1. Shebang detection (most reliable)
    first_line = content.split("\n", 1)[0]
    if first_line.startswith("#!"):
        for pattern, lang in _SHEBANG_MAP:
            if pattern.match(first_line):
                return lang

    # 2. JSON probe (check before code — JSON can contain 'import' as a key)
    stripped = content.lstrip()
    if stripped and stripped[0] in "{[":
        try:
            import json

            json.loads(content)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass

    # 3. Python structural probe
    if _PYTHON_PROBE.search(content):
        return "python"

    # 4. JavaScript structural probe
    if _JS_PROBE.search(content):
        return "javascript"

    return None


def detect_extension_mismatch(filepath: str, content: str) -> str | None:
    """Detect if a file's content type mismatches its extension.

    Returns a human-readable mismatch description, or None if the types match
    or cannot be determined.

    Uses Google Magika (AI-powered) when available, falling back to regex
    heuristics.

    Args:
        filepath: The file path (e.g. "logo.png" or "LICENSE").
        content: The decoded text content of the file.
    """
    # Cheap heuristics first, expensive Magika only as fallback.
    # This avoids running AI model inference per-file in hot scanning loops
    # (check_extension_mismatch, _scan_single_file, scan_directory_for_disguised_files).
    detected = sniff_content_type(content)
    if detected is None:
        # Heuristics couldn't determine — try AI-powered detection.
        # Only trust Magika when it returns a recognized code type; generic
        # labels like "txt"/"unknown" are not useful for mismatch detection.
        try:
            magika_result = magika_sniff(content.encode("utf-8"))
            if magika_result in CODE_TYPES:
                detected = magika_result
        except Exception:
            pass
    if detected is None:
        return None

    # Get expected type from extension
    suffix = Path(filepath).suffix.lower()

    if not suffix:
        # No extension — if we detected code, that's suspicious
        if detected in CODE_TYPES:
            filename = Path(filepath).name
            return f"extensionless file '{filename}' contains {detected} code"
        return None

    expected = _EXT_TO_TYPE.get(suffix)

    if expected is None:
        # Unknown extension (e.g. .png, .gif) but content is code → mismatch
        if detected in CODE_TYPES:
            return f"extension '{suffix}' but content is {detected}"
        return None

    if expected != detected:
        # Known extension but content doesn't match
        if detected in CODE_TYPES:
            return f"extension '{suffix}' (expected {expected}) but content is {detected}"

    return None


# --------------------------------------------------------------------------
# Optional Magika integration (requires: pip install aigate[magika])
# --------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _get_magika_instance():
    """Return a cached Magika instance (avoids reloading the model per call)."""
    from magika import Magika  # type: ignore[import-untyped]

    return Magika()


def magika_sniff(raw_bytes: bytes) -> str | None:
    """Use Google Magika for AI-powered content type detection.

    Returns a content type string or None.  Requires ``pip install aigate[magika]``.
    """
    try:
        import magika as _magika_mod  # noqa: F401  — availability check
    except ImportError:
        return None

    m = _get_magika_instance()
    result = m.identify_bytes(raw_bytes)
    if result and result.output and result.output.ct_label:
        label = result.output.ct_label.lower()
        # Map Magika labels to our types
        mapping = {
            "python": "python",
            "javascript": "javascript",
            "typescript": "javascript",
            "shell": "shell",
            "bash": "shell",
            "ruby": "ruby",
            "perl": "perl",
            "php": "php",
            "json": "json",
            "yaml": "yaml",
            "html": "html",
            "css": "css",
        }
        return mapping.get(label, label)
    return None
