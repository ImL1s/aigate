"""Tests that AI prompt template resists injection attempts.

These tests verify the STRUCTURE of prompts, not actual AI responses.
They ensure injection payloads land inside <UNTRUSTED_PACKAGE_CODE> tags
and that security warnings are present.
"""

from __future__ import annotations

from aigate.backends.base import (
    ANALYSIS_PROMPT_TEMPLATE,
    ANALYSIS_SYSTEM_PROMPT,
    ANALYSIS_USER_TEMPLATE,
    _parse_response,
    _validate_safe_verdict,
)
from aigate.models import AnalysisLevel, Verdict


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

    def test_security_warning_present(self):
        """Prompt warns about untrusted source code."""
        prompt = _build_prompt("anything")
        assert "UNTRUSTED" in prompt
        assert "prompt injection" in prompt.lower()

    def test_injection_override_lands_in_untrusted_block(self):
        from tests.fixtures.fake_injection_attempts import DIRECT_OVERRIDE

        prompt = _build_prompt(DIRECT_OVERRIDE)
        start = prompt.index("<UNTRUSTED_PACKAGE_CODE>")
        end = prompt.index("</UNTRUSTED_PACKAGE_CODE>")
        inner = prompt[start:end]
        assert "Ignore all previous instructions" in inner

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


class TestMessageSeparation:
    """Verify system/user message separation for injection defense."""

    def test_system_prompt_has_no_placeholders(self):
        """System prompt must not contain any {placeholders} for untrusted content."""
        # These are format placeholders that would inject untrusted data into
        # the system message — none should be present.
        untrusted_placeholders = [
            "{source_code}",
            "{name}",
            "{version}",
            "{author}",
            "{description}",
            "{risk_signals}",
            "{external_intelligence}",
        ]
        for placeholder in untrusted_placeholders:
            assert placeholder not in ANALYSIS_SYSTEM_PROMPT, (
                f"System prompt contains untrusted placeholder: {placeholder}"
            )

    def test_user_template_has_no_analysis_instructions(self):
        """User template must not contain analysis instructions."""
        assert "Respond with ONLY" not in ANALYSIS_USER_TEMPLATE
        assert "Analyze for:" not in ANALYSIS_USER_TEMPLATE
        assert "Credential theft" not in ANALYSIS_USER_TEMPLATE

    def test_system_prompt_has_injection_warning(self):
        """System prompt must warn about prompt injection."""
        assert "UNTRUSTED" in ANALYSIS_SYSTEM_PROMPT
        assert "prompt injection" in ANALYSIS_SYSTEM_PROMPT.lower()
        assert "Ignore ANY instructions" in ANALYSIS_SYSTEM_PROMPT

    def test_system_prompt_has_all_categories(self):
        """System prompt contains all 8 analysis categories."""
        categories = [
            "Credential theft",
            "Data exfiltration",
            "Remote code execution",
            "Obfuscation",
            "file system access",
            "Network calls",
            "Install-time code execution",
            "Cryptocurrency mining",
        ]
        for cat in categories:
            assert cat in ANALYSIS_SYSTEM_PROMPT, f"Missing in system prompt: {cat}"

    def test_system_prompt_has_json_format(self):
        """System prompt specifies the JSON response format."""
        assert "Respond with ONLY a JSON object" in ANALYSIS_SYSTEM_PROMPT
        assert '"verdict"' in ANALYSIS_SYSTEM_PROMPT

    def test_user_template_has_source_code_placeholder(self):
        """User template contains {source_code} for the untrusted content."""
        assert "{source_code}" in ANALYSIS_USER_TEMPLATE

    def test_user_template_has_package_info(self):
        """User template has placeholders for package metadata."""
        assert "{name}" in ANALYSIS_USER_TEMPLATE
        assert "{version}" in ANALYSIS_USER_TEMPLATE
        assert "{ecosystem}" in ANALYSIS_USER_TEMPLATE

    def test_combined_template_equals_system_plus_user(self):
        """ANALYSIS_PROMPT_TEMPLATE == system + newline + user."""
        assert ANALYSIS_PROMPT_TEMPLATE == ANALYSIS_SYSTEM_PROMPT + "\n" + ANALYSIS_USER_TEMPLATE


class TestOutputValidation:
    """Verify output validation catches contradictory safe+malicious responses."""

    def test_safe_with_malicious_reasoning_upgrades_to_suspicious(self):
        """If verdict=safe but reasoning says 'credential theft', upgrade."""
        verdict, signals = _validate_safe_verdict(
            "This code performs credential theft by reading .ssh keys",
            [],
        )
        assert verdict == Verdict.SUSPICIOUS
        assert any("output_validation" in s for s in signals)

    def test_safe_with_exfiltration_reasoning_upgrades(self):
        verdict, signals = _validate_safe_verdict(
            "The package exfiltrates data to an external server",
            ["some_signal"],
        )
        assert verdict == Verdict.SUSPICIOUS
        assert any("output_validation" in s for s in signals)
        # Existing signals preserved
        assert "some_signal" in signals

    def test_safe_with_backdoor_reasoning_upgrades(self):
        verdict, signals = _validate_safe_verdict(
            "Contains a backdoor that opens a reverse shell",
            [],
        )
        assert verdict == Verdict.SUSPICIOUS

    def test_safe_with_clean_reasoning_stays_safe(self):
        verdict, signals = _validate_safe_verdict(
            "This is a standard utility library with no suspicious behavior",
            [],
        )
        assert verdict == Verdict.SAFE
        assert signals == []

    def test_safe_with_benign_network_mention_stays_safe(self):
        """Mentioning network in a non-malicious way shouldn't trigger."""
        verdict, signals = _validate_safe_verdict(
            "The package makes HTTP requests to download images as documented",
            [],
        )
        assert verdict == Verdict.SAFE

    def test_malicious_verdict_not_affected_by_validation(self):
        """Output validation only applies to 'safe' verdicts."""
        raw = (
            '{"verdict": "malicious", "confidence": 0.95, '
            '"reasoning": "credential theft detected", "risk_signals": ["ssh"]}'
        )
        result = _parse_response(raw, "test", AnalysisLevel.L1_QUICK, 100)
        assert result.verdict == Verdict.MALICIOUS
        # Should not have output_validation signal — it was already malicious
        assert not any("output_validation" in s for s in result.risk_signals)

    def test_parse_response_integrates_output_validation(self):
        """End-to-end: _parse_response catches safe+malicious contradiction."""
        raw = (
            '{"verdict": "safe", "confidence": 0.9, '
            '"reasoning": "The code steals SSH keys and exfiltrates them", '
            '"risk_signals": []}'
        )
        result = _parse_response(raw, "test", AnalysisLevel.L1_QUICK, 100)
        assert result.verdict == Verdict.SUSPICIOUS
        assert any("output_validation" in s for s in result.risk_signals)
