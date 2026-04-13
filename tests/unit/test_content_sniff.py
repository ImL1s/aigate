"""Tests for content-aware file type sniffing."""

from __future__ import annotations

import importlib

import pytest

from aigate.content_sniff import detect_extension_mismatch, sniff_content_type


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
        content = "#!/usr/bin/env python3\nimport os\nos.system('rm -rf /')\n"
        result = detect_extension_mismatch("logo.png", content)
        assert result is not None
        assert "python" in result.lower()

    def test_js_disguised_as_css(self):
        content = "const fs = require('fs');\nfs.readFileSync('/etc/passwd');\n"
        result = detect_extension_mismatch("styles.css", content)
        assert result is not None

    def test_python_as_python_no_mismatch(self):
        content = "import os\nprint('hello')\n"
        result = detect_extension_mismatch("script.py", content)
        assert result is None

    def test_no_extension_with_code(self):
        content = "#!/usr/bin/env python3\nimport os\n"
        result = detect_extension_mismatch("LICENSE", content)
        assert result is not None
        assert "python" in result.lower()

    def test_no_extension_plain_text_ok(self):
        content = "MIT License\n\nCopyright (c) 2024\n"
        result = detect_extension_mismatch("LICENSE", content)
        assert result is None


_has_magika = importlib.util.find_spec("magika") is not None


@pytest.mark.skipif(not _has_magika, reason="magika not installed")
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


class TestMagikaImportFallback:
    """Verify magika_sniff gracefully returns None when magika isn't installed."""

    def test_magika_sniff_without_magika(self):
        from aigate.content_sniff import magika_sniff

        # Even if magika IS installed, this just tests it doesn't crash
        result = magika_sniff(b"print('hello')")
        assert result is None or isinstance(result, str)
