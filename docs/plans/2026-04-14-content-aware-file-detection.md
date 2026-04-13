# Content-Aware File Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close aigate's file extension bypass blind spot by adding content-aware file type detection, so attackers can't hide malicious Python/JS inside `.png` or extensionless files.

**Architecture:** Two-layer approach — (1) zero-dependency lightweight content sniffing via shebang, UTF-8 heuristics, and `ast.parse()` probes, integrated directly into `_extract_archive()` and `read_local_source()`; (2) optional Magika integration as `aigate[magika]` extra for users who want AI-powered detection. A new `extension_mismatch` risk signal is added to prefilter.

**Tech Stack:** Python 3.11+, pytest, optional `magika` dependency

---

### Task 1: Add `content_sniff` module — core detection logic

**Files:**
- Create: `src/aigate/content_sniff.py`
- Test: `tests/unit/test_content_sniff.py`

**Step 1: Write the failing tests**

```python
# tests/unit/test_content_sniff.py
"""Tests for content-aware file type sniffing."""

from __future__ import annotations

from aigate.content_sniff import sniff_content_type


class TestShebangDetection:
    def test_python_shebang(self):
        content = "#!/usr/bin/env python3\nimport os\nprint('hello')\n"
        assert sniff_content_type(content) == "python"

    def test_python_shebang_no_env(self):
        content = "#!/usr/bin/python\nimport os\n"
        assert sniff_content_type(content) == "python"

    def test_node_shebang(self):
        content = "#!/usr/bin/env node\nconsole.log('hi')\n"
        assert sniff_content_type(content) == "javascript"

    def test_bash_shebang(self):
        content = "#!/bin/bash\necho 'hello'\n"
        assert sniff_content_type(content) == "shell"

    def test_sh_shebang(self):
        content = "#!/bin/sh\necho 'hello'\n"
        assert sniff_content_type(content) == "shell"

    def test_perl_shebang(self):
        content = "#!/usr/bin/perl\nprint 'hello';\n"
        assert sniff_content_type(content) == "perl"

    def test_ruby_shebang(self):
        content = "#!/usr/bin/env ruby\nputs 'hello'\n"
        assert sniff_content_type(content) == "ruby"


class TestAstProbeDetection:
    def test_python_import_statement(self):
        content = "import os\nimport subprocess\nos.system('ls')\n"
        assert sniff_content_type(content) == "python"

    def test_python_def_and_class(self):
        content = "class Exploit:\n    def run(self):\n        pass\n"
        assert sniff_content_type(content) == "python"

    def test_python_from_import(self):
        content = "from base64 import b64decode\ndata = b64decode('abc')\n"
        assert sniff_content_type(content) == "python"


class TestJsProbeDetection:
    def test_require_statement(self):
        content = "const fs = require('fs');\nfs.readFileSync('/etc/passwd');\n"
        assert sniff_content_type(content) == "javascript"

    def test_module_exports(self):
        content = "module.exports = function() { return 42; };\n"
        assert sniff_content_type(content) == "javascript"

    def test_es_import(self):
        content = "import { readFile } from 'fs';\n"
        assert sniff_content_type(content) == "javascript"


class TestNonCode:
    def test_binary_content_returns_none(self):
        # Simulates binary garbage decoded with errors="replace"
        content = "\x00\x01\x02\xff\xfe\x89PNG\r\n\x1a\n"
        assert sniff_content_type(content) is None

    def test_plain_text_returns_none(self):
        content = "This is just a README with some words.\n"
        assert sniff_content_type(content) is None

    def test_empty_string_returns_none(self):
        assert sniff_content_type("") is None

    def test_json_returns_json(self):
        content = '{"name": "malicious", "scripts": {"postinstall": "node exploit.js"}}\n'
        assert sniff_content_type(content) == "json"


class TestExtensionMismatch:
    def test_python_disguised_as_png(self):
        from aigate.content_sniff import detect_extension_mismatch

        content = "#!/usr/bin/env python3\nimport os\nos.system('rm -rf /')\n"
        result = detect_extension_mismatch("logo.png", content)
        assert result is not None
        assert "python" in result.lower()

    def test_js_disguised_as_css(self):
        from aigate.content_sniff import detect_extension_mismatch

        content = "const fs = require('fs');\nfs.readFileSync('/etc/passwd');\n"
        result = detect_extension_mismatch("styles.css", content)
        assert result is not None

    def test_python_as_python_no_mismatch(self):
        from aigate.content_sniff import detect_extension_mismatch

        content = "import os\nprint('hello')\n"
        result = detect_extension_mismatch("script.py", content)
        assert result is None

    def test_no_extension_with_code(self):
        from aigate.content_sniff import detect_extension_mismatch

        content = "#!/usr/bin/env python3\nimport os\n"
        result = detect_extension_mismatch("LICENSE", content)
        assert result is not None
        assert "python" in result.lower()

    def test_no_extension_plain_text_ok(self):
        from aigate.content_sniff import detect_extension_mismatch

        content = "MIT License\n\nCopyright (c) 2024\n"
        result = detect_extension_mismatch("LICENSE", content)
        assert result is None
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_content_sniff.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aigate.content_sniff'`

**Step 3: Write minimal implementation**

```python
# src/aigate/content_sniff.py
"""Lightweight content-aware file type detection.

Zero-dependency sniffing via shebang lines, AST probes, and structural
heuristics.  Used to catch files with disguised or missing extensions
(e.g. malicious Python saved as .png).

For AI-powered detection, see the optional ``magika`` integration.
"""

from __future__ import annotations

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

    Args:
        filepath: The file path (e.g. "logo.png" or "LICENSE").
        content: The decoded text content of the file.
    """
    detected = sniff_content_type(content)
    if detected is None:
        return None

    # Get expected type from extension
    suffix = Path(filepath).suffix.lower()

    if not suffix:
        # No extension — if we detected code, that's suspicious
        if detected in ("python", "javascript", "shell", "ruby", "perl", "php"):
            filename = Path(filepath).name
            return f"extensionless file '{filename}' contains {detected} code"
        return None

    expected = _EXT_TO_TYPE.get(suffix)

    if expected is None:
        # Unknown extension (e.g. .png, .gif) but content is code → mismatch
        if detected in ("python", "javascript", "shell", "ruby", "perl", "php"):
            return f"extension '{suffix}' but content is {detected}"
        return None

    if expected != detected:
        # Known extension but content doesn't match
        if detected in ("python", "javascript", "shell", "ruby", "perl", "php"):
            return f"extension '{suffix}' (expected {expected}) but content is {detected}"

    return None
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_content_sniff.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add src/aigate/content_sniff.py tests/unit/test_content_sniff.py
git commit -m "feat: add content_sniff module for extension-bypass detection"
```

---

### Task 2: Integrate content sniffing into `_extract_archive()`

**Files:**
- Modify: `src/aigate/resolver.py:218-277`
- Test: `tests/unit/test_resolver.py` (add new tests)

**Step 1: Write the failing test**

Add to `tests/unit/test_resolver.py`:

```python
import io
import tarfile


class TestContentSniffingInArchive:
    """Verify _extract_archive catches disguised files."""

    def _make_tar_gz(self, files: dict[str, str]) -> bytes:
        """Create a tar.gz in memory with given {path: content} entries."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for path, content in files.items():
                data = content.encode("utf-8")
                info = tarfile.TarInfo(name=path)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def test_python_disguised_as_png_is_extracted(self):
        """A .png file containing Python code should now be extracted."""
        content = "#!/usr/bin/env python3\nimport os\nos.system('rm -rf /')\n"
        archive = self._make_tar_gz({"pkg-1.0/logo.png": content})
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg-1.0/logo.png" in result

    def test_extensionless_python_is_extracted(self):
        """A file with no extension containing Python should be extracted."""
        content = "import subprocess\nsubprocess.call(['curl', 'evil.com'])\n"
        archive = self._make_tar_gz({"pkg-1.0/run": content})
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg-1.0/run" in result

    def test_genuine_binary_png_not_extracted(self):
        """A real binary PNG should NOT be extracted."""
        content = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00"
        archive = self._make_tar_gz({"pkg-1.0/real.png": content})
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg-1.0/real.png" not in result

    def test_normal_py_file_still_extracted(self):
        """Regular .py file extraction is not affected."""
        content = "print('hello')\n"
        archive = self._make_tar_gz({"pkg-1.0/main.py": content})
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg-1.0/main.py" in result
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_resolver.py::TestContentSniffingInArchive -v`
Expected: `test_python_disguised_as_png_is_extracted` FAILS, `test_extensionless_python_is_extracted` FAILS

**Step 3: Modify `_extract_archive` in resolver.py**

In `src/aigate/resolver.py:218-277`, change the extraction logic for **both** tar.gz and zip branches. After the existing extension check fails, add a content sniff fallback:

```python
def _extract_archive(content: bytes, filename: str) -> dict[str, str]:
    """Extract text files from tar.gz or zip/whl archive."""
    from .content_sniff import sniff_content_type

    files: dict[str, str] = {}
    text_extensions = {
        ".dart", ".py", ".js", ".ts", ".json", ".yaml", ".yml",
        ".toml", ".cfg", ".ini", ".txt", ".md", ".rst", ".sh", ".bat", ".pth",
    }
    max_file_size = 512 * 1024  # 512KB per file

    def _should_extract(name: str, raw_bytes: bytes) -> tuple[bool, str | None]:
        """Return (should_extract, decoded_text_or_None)."""
        suffix = Path(name).suffix.lower()
        if suffix in text_extensions:
            try:
                return True, raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                return False, None
        # Extension not in whitelist — try content sniffing
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            return False, None
        detected = sniff_content_type(text)
        if detected and detected in ("python", "javascript", "shell", "ruby", "perl", "php"):
            return True, text
        return False, None

    try:
        if filename.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile() or member.size > max_file_size:
                        continue
                    if not _is_path_safe(member.name):
                        continue
                    f = tar.extractfile(member)
                    if f:
                        try:
                            raw = f.read()
                            ok, text = _should_extract(member.name, raw)
                            if ok and text is not None:
                                files[member.name] = text
                        except Exception:
                            pass
        elif filename.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > max_file_size:
                        continue
                    if not _is_path_safe(info.filename):
                        continue
                    try:
                        raw = zf.read(info.filename)
                        ok, text = _should_extract(info.filename, raw)
                        if ok and text is not None:
                            files[info.filename] = text
                    except Exception:
                        pass
    except Exception:
        pass

    return files
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_resolver.py -v`
Expected: All PASS (old + new tests)

**Step 5: Commit**

```bash
git add src/aigate/resolver.py tests/unit/test_resolver.py
git commit -m "feat: integrate content sniffing into _extract_archive"
```

---

### Task 3: Add `extension_mismatch` risk signal to prefilter

**Files:**
- Modify: `src/aigate/prefilter.py:209-294` (add step 5.5 in `run_prefilter`)
- Test: `tests/unit/test_prefilter.py` (add new tests)

**Step 1: Write the failing test**

Add to `tests/unit/test_prefilter.py`:

```python
class TestExtensionMismatch:
    """Verify extension_mismatch signals are generated."""

    def test_python_in_png_generates_signal(self):
        source = {"pkg-1.0/logo.png": "#!/usr/bin/env python3\nimport os\nos.system('evil')\n"}
        config = Config()
        pkg = _make_pkg()
        result = run_prefilter(pkg, config, source)
        assert any("extension_mismatch" in s for s in result.risk_signals)

    def test_js_in_css_generates_signal(self):
        source = {"pkg-1.0/styles.css": "const fs = require('fs');\nfs.readFileSync('/etc/passwd');\n"}
        config = Config()
        pkg = _make_pkg()
        result = run_prefilter(pkg, config, source)
        assert any("extension_mismatch" in s for s in result.risk_signals)

    def test_extensionless_python_generates_signal(self):
        source = {"pkg-1.0/run": "#!/usr/bin/env python3\nimport os\n"}
        config = Config()
        pkg = _make_pkg()
        result = run_prefilter(pkg, config, source)
        assert any("extension_mismatch" in s for s in result.risk_signals)

    def test_normal_py_no_mismatch(self):
        source = {"pkg-1.0/main.py": "import os\nprint('hello')\n"}
        config = Config()
        pkg = _make_pkg()
        result = run_prefilter(pkg, config, source)
        assert not any("extension_mismatch" in s for s in result.risk_signals)
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_prefilter.py::TestExtensionMismatch -v`
Expected: FAIL — no `extension_mismatch` signals generated

**Step 3: Add extension mismatch check to `run_prefilter`**

In `src/aigate/prefilter.py`, add between step 5 (source code patterns) and step 6 (compound signals), around line 252:

```python
    # 5.5 Extension mismatch detection
    if source_files:
        mismatch_signals = check_extension_mismatch(source_files)
        signals.extend(mismatch_signals)
```

And add the function at module level (after `check_dangerous_patterns`):

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_prefilter.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add src/aigate/prefilter.py tests/unit/test_prefilter.py
git commit -m "feat: add extension_mismatch risk signal to prefilter"
```

---

### Task 4: Integrate content sniffing into `read_local_source()`

**Files:**
- Modify: `src/aigate/resolver.py:301-333`
- Test: `tests/unit/test_resolver.py` (add tests in `TestReadLocalSource`)

**Step 1: Write the failing test**

Add to `TestReadLocalSource` class in `tests/unit/test_resolver.py`:

```python
    def test_extensionless_script_is_read(self, tmp_path):
        """Extensionless files with code content should be included."""
        (tmp_path / "run").write_text("#!/usr/bin/env python3\nimport os\n")
        result = read_local_source(tmp_path)
        assert "import os" in result

    def test_disguised_extension_is_read(self, tmp_path):
        """Code in .png extension should be included in local scan."""
        (tmp_path / "logo.png").write_text("import subprocess\nsubprocess.call(['evil'])\n")
        result = read_local_source(tmp_path)
        assert "subprocess" in result
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_resolver.py::TestReadLocalSource::test_extensionless_script_is_read -v`
Expected: FAIL — extensionless files are not read by current logic

**Step 3: Modify `read_local_source` in resolver.py**

In `src/aigate/resolver.py:301-333`, after the `f.suffix in SKIP_EXTENSIONS` check, add a content sniffing fallback for files that have no extension or have a skipped extension:

```python
def read_local_source(path: Path) -> str:
    """Read source code from a local file or directory for analysis."""
    from .content_sniff import sniff_content_type

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if path.is_file():
        return path.read_text(errors="replace")

    cumulative_size = 0
    parts: list[str] = []
    for root_str, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        root = Path(root_str)
        for fname in sorted(files):
            f = root / fname
            # If extension is in skip list, try content sniffing before skipping
            if f.suffix in SKIP_EXTENSIONS:
                try:
                    peek = f.read_text(errors="replace")[:4096]
                    detected = sniff_content_type(peek)
                    if detected not in ("python", "javascript", "shell", "ruby", "perl", "php"):
                        continue  # Genuinely non-code, skip
                    # Fall through — content is code despite extension
                except (OSError, UnicodeDecodeError):
                    continue
            elif not f.suffix:
                # No extension — check if it's code
                try:
                    peek = f.read_text(errors="replace")[:4096]
                    detected = sniff_content_type(peek)
                    if detected not in ("python", "javascript", "shell", "ruby", "perl", "php"):
                        continue  # Not code, skip
                except (OSError, UnicodeDecodeError):
                    continue
            try:
                size = f.stat().st_size
                cumulative_size += size
                if cumulative_size > MAX_LOCAL_SOURCE_SIZE:
                    logger.warning(
                        "Local source size limit reached (%d bytes), stopping read",
                        MAX_LOCAL_SOURCE_SIZE,
                    )
                    return "\n\n".join(parts)
                text = f.read_text(errors="replace")
                parts.append(f"# --- {f.relative_to(path)} ---\n{text}")
            except (OSError, UnicodeDecodeError):
                continue
    return "\n\n".join(parts)
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_resolver.py::TestReadLocalSource -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add src/aigate/resolver.py tests/unit/test_resolver.py
git commit -m "feat: content-sniff extensionless/disguised files in read_local_source"
```

---

### Task 5: Add optional Magika integration

**Files:**
- Modify: `pyproject.toml:31-37` (add `magika` optional extra)
- Modify: `src/aigate/content_sniff.py` (add `magika_sniff()` function)
- Test: `tests/unit/test_content_sniff.py` (add Magika tests with skip-if-not-installed)

**Step 1: Write the failing test**

Add to `tests/unit/test_content_sniff.py`:

```python
import importlib

has_magika = importlib.util.find_spec("magika") is not None


@pytest.mark.skipif(not has_magika, reason="magika not installed")
class TestMagikaIntegration:
    def test_magika_detects_python(self):
        from aigate.content_sniff import magika_sniff

        content = "#!/usr/bin/env python3\nimport os\nos.system('ls')\n"
        result = magika_sniff(content.encode("utf-8"))
        assert result is not None
        assert "python" in result.lower()

    def test_magika_returns_none_for_unknown(self):
        from aigate.content_sniff import magika_sniff

        result = magika_sniff(b"just some random text")
        # May or may not detect — we just verify it doesn't crash
        assert result is None or isinstance(result, str)
```

**Step 2: Add optional dependency to `pyproject.toml`**

Add after the `dev` optional-dependencies:

```toml
magika = [
    "magika>=0.6",
]
```

**Step 3: Add `magika_sniff()` to `content_sniff.py`**

Append to `src/aigate/content_sniff.py`:

```python
def magika_sniff(raw_bytes: bytes) -> str | None:
    """Use Google Magika for AI-powered content type detection.

    Returns a content type string or None.  Requires ``pip install aigate[magika]``.
    """
    try:
        from magika import Magika
    except ImportError:
        return None

    m = Magika()
    result = m.identify_bytes(raw_bytes)
    if result and result.output and result.output.ct_label:
        label = result.output.ct_label.lower()
        # Map Magika labels to our types
        mapping = {
            "python": "python",
            "javascript": "javascript",
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
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_content_sniff.py -v`
Expected: All PASS (Magika tests skipped if not installed)

**Step 5: Commit**

```bash
git add pyproject.toml src/aigate/content_sniff.py tests/unit/test_content_sniff.py
git commit -m "feat: add optional Magika integration as aigate[magika]"
```

---

### Task 6: Update documentation and attack-detection.md

**Files:**
- Modify: `docs/attack-detection.md:158` (remove "binary analysis" limitation)
- Modify: `README.md` (add extension bypass to attack coverage table)

**Step 1: Update `docs/attack-detection.md`**

Change line 158 from:
```markdown
| Limited to text file analysis | Binary payloads, compiled extensions not scanned | Entropy check on text; future: binary analysis |
```
To:
```markdown
| Limited to text file analysis | Binary payloads, compiled extensions not scanned | Entropy check on text; content sniffing catches disguised extensions; optional Magika integration |
```

**Step 2: Update `README.md` attack coverage table**

Add a new row to the attack coverage table (around line 218):
```markdown
| Extension disguise | Malicious Python as .png | Content sniffing + extension_mismatch signal |
```

**Step 3: Commit**

```bash
git add docs/attack-detection.md README.md
git commit -m "docs: document extension bypass detection and Magika integration"
```

---

### Task 7: Run full test suite

**Step 1: Run all tests**

Run: `.venv/bin/python -m pytest tests/ -v`
Expected: All 705+ tests PASS (+ new tests from this plan)

**Step 2: Run linter**

Run: `.venv/bin/ruff check src/aigate/content_sniff.py tests/unit/test_content_sniff.py`
Expected: No errors

**Step 3: Final commit**

```bash
git add -A
git commit -m "chore: final cleanup for content-aware file detection"
```

---

### Task 8: Create GitHub Issue for tracking

**Step 1: Create the issue**

Run:
```bash
cd /Users/iml1s/Documents/mine/aigate
gh issue create \
  --title "feat: content-aware file type detection (extension bypass defense)" \
  --label "enhancement" \
  --body "## Problem

aigate's \`_extract_archive()\` uses a hardcoded extension whitelist (16 types) to decide which files to extract from package archives. Attackers can bypass all prefilter and AI analysis by saving malicious Python/JS with non-whitelisted extensions (e.g. \`.png\`) or no extension at all.

This blind spot is documented in \`docs/attack-detection.md\` line 158: *\"Limited to text file analysis — Binary payloads, compiled extensions not scanned.\"*

## Solution

Two-layer content-aware detection:

1. **Lightweight content sniffing** (zero new dependencies): shebang detection, AST structural probes, UTF-8 heuristics
2. **Optional Magika integration** (\`aigate[magika]\`): Google's AI-powered file type detection for users wanting deeper analysis

### New risk signal: \`extension_mismatch(HIGH)\`
Fires when a file's detected content type doesn't match its extension (e.g. Python code in a \`.png\` file).

## Multi-model consensus
Evaluated by Claude Opus 4.6 and Codex GPT-5.4 — both independently agreed this is a valid blind spot worth addressing.

## Files changed
- \`src/aigate/content_sniff.py\` (NEW)
- \`src/aigate/resolver.py\` (MODIFIED)
- \`src/aigate/prefilter.py\` (MODIFIED)
- \`pyproject.toml\` (MODIFIED — optional \`magika\` extra)
- \`docs/attack-detection.md\` (MODIFIED)
- \`README.md\` (MODIFIED)"
```

Expected: Issue created successfully with URL output
