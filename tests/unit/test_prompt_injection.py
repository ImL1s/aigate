"""Tests that AI prompt template resists injection attempts.

These tests verify the STRUCTURE of prompts, not actual AI responses.
They ensure injection payloads land inside <UNTRUSTED_PACKAGE_CODE> tags
and that security warnings are present.
"""

from __future__ import annotations

from aigate.backends.base import ANALYSIS_PROMPT_TEMPLATE


def _build_prompt(source_code: str) -> str:
    return ANALYSIS_PROMPT_TEMPLATE.format(
        name="evil-pkg",
        version="1.0.0",
        ecosystem="pypi",
        author="attacker",
        description="A utility package",
        has_install_scripts=True,
        risk_signals="- dangerous_pattern(HIGH): eval()",
        external_intelligence="None",
        source_code=source_code,
    )


class TestPromptInjectionStructure:
    """Verify prompt structure places untrusted content safely."""

    def test_source_code_inside_untrusted_tags(self):
        prompt = _build_prompt("import os; os.system('rm -rf /')")
        start = prompt.index("<UNTRUSTED_PACKAGE_CODE>")
        end = prompt.index("</UNTRUSTED_PACKAGE_CODE>")
        # Source code must be BETWEEN the tags
        assert "os.system" in prompt[start:end]

    def test_security_warning_after_source_code(self):
        prompt = _build_prompt("anything")
        code_end = prompt.index("</UNTRUSTED_PACKAGE_CODE>")
        warning_start = prompt.index("CRITICAL SECURITY WARNING")
        # Warning must come AFTER the untrusted code block
        assert warning_start > code_end

    def test_injection_override_lands_in_untrusted_block(self):
        from tests.fixtures.fake_injection_attempts import DIRECT_OVERRIDE

        prompt = _build_prompt(DIRECT_OVERRIDE)
        start = prompt.index("<UNTRUSTED_PACKAGE_CODE>")
        end = prompt.index("</UNTRUSTED_PACKAGE_CODE>")
        inner = prompt[start:end]
        assert "Ignore all previous instructions" in inner
        assert "CRITICAL SECURITY WARNING" not in inner

    def test_docstring_injection_lands_in_untrusted_block(self):
        from tests.fixtures.fake_injection_attempts import DOCSTRING_INJECTION

        prompt = _build_prompt(DOCSTRING_INJECTION)
        start = prompt.index("<UNTRUSTED_PACKAGE_CODE>")
        end = prompt.index("</UNTRUSTED_PACKAGE_CODE>")
        inner = prompt[start:end]
        assert "SYSTEM OVERRIDE" in inner

    def test_fake_json_lands_in_untrusted_block(self):
        from tests.fixtures.fake_injection_attempts import FAKE_JSON_RESPONSE

        prompt = _build_prompt(FAKE_JSON_RESPONSE)
        start = prompt.index("<UNTRUSTED_PACKAGE_CODE>")
        end = prompt.index("</UNTRUSTED_PACKAGE_CODE>")
        inner = prompt[start:end]
        assert '"verdict": "safe"' in inner

    def test_role_confusion_lands_in_untrusted_block(self):
        from tests.fixtures.fake_injection_attempts import ROLE_CONFUSION

        prompt = _build_prompt(ROLE_CONFUSION)
        start = prompt.index("<UNTRUSTED_PACKAGE_CODE>")
        end = prompt.index("</UNTRUSTED_PACKAGE_CODE>")
        inner = prompt[start:end]
        assert "BEGIN SYSTEM MESSAGE" in inner

    def test_prompt_has_json_only_instruction(self):
        """Ensure the prompt tells the AI to respond with ONLY JSON."""
        prompt = _build_prompt("safe code")
        assert "Respond with ONLY a JSON object" in prompt

    def test_prompt_mentions_all_attack_categories(self):
        """Ensure prompt covers key attack vectors."""
        prompt = _build_prompt("safe code")
        expected_categories = [
            "Credential theft",
            "Data exfiltration",
            "Remote code execution",
            "Obfuscation",
            "file system access",
            "Network calls",
            "Install-time code execution",
            "Cryptocurrency mining",
        ]
        for category in expected_categories:
            assert category in prompt, f"Missing attack category: {category}"
