"""Tests for compound signal detection (multi-indicator attack chains)."""

from __future__ import annotations

from aigate.rules.compound import COMPOUND_RULES, check_compound_signals
from tests.fixtures.fake_malicious_ctx import PACKAGE_FILES as CTX_FILES


class TestExecPlusCredentialInSameFile:
    def test_exec_plus_credential_escalates_to_medium(self):
        """exec + credential_access tags in the same file → MEDIUM compound signal."""
        per_file_signals = {
            "steal.py": [
                {"rule_id": "exec-call", "tags": ["execution", "dynamic"]},
                {"rule_id": "ssh-dir-access", "tags": ["credential_access", "filesystem"]},
            ],
        }
        compounds = check_compound_signals(per_file_signals)
        assert len(compounds) >= 1
        assert any("MEDIUM" in s for s in compounds)
        assert any("exec-plus-cred-theft" in s for s in compounds)


class TestExecAloneNoCompound:
    def test_exec_alone_no_compound(self):
        """A single exec signal with no other categories → no compound escalation."""
        per_file_signals = {
            "normal.py": [
                {"rule_id": "exec-call", "tags": ["execution", "dynamic"]},
            ],
        }
        compounds = check_compound_signals(per_file_signals)
        assert compounds == []


class TestExecPlusCredPlusExfil:
    def test_full_attack_chain_escalates_to_critical(self):
        """exec + credential + exfiltration in the same file → CRITICAL."""
        per_file_signals = {
            "payload.py": [
                {"rule_id": "exec-call", "tags": ["execution", "dynamic"]},
                {"rule_id": "ssh-dir-access", "tags": ["credential_access", "filesystem"]},
                {"rule_id": "requests-get-post", "tags": ["exfiltration", "network"]},
            ],
        }
        compounds = check_compound_signals(per_file_signals)
        # Should have the most specific (critical) compound
        assert any("CRITICAL" in s for s in compounds)
        assert any("full-attack-chain" in s for s in compounds)


class TestSignalsInDifferentFiles:
    def test_signals_in_different_files_no_compound(self):
        """Signals in different files should NOT trigger compound detection."""
        per_file_signals = {
            "utils.py": [
                {"rule_id": "exec-call", "tags": ["execution", "dynamic"]},
            ],
            "config.py": [
                {"rule_id": "ssh-dir-access", "tags": ["credential_access", "filesystem"]},
            ],
        }
        compounds = check_compound_signals(per_file_signals)
        assert compounds == []


class TestObfuscationPlusExfiltration:
    def test_obfuscation_plus_exfiltration_escalates_to_high(self):
        """obfuscation + exfiltration in the same file → HIGH."""
        per_file_signals = {
            "loader.py": [
                {"rule_id": "base64-decode", "tags": ["obfuscation", "encoding"]},
                {"rule_id": "requests-get-post", "tags": ["exfiltration", "network"]},
            ],
        }
        compounds = check_compound_signals(per_file_signals)
        assert any("HIGH" in s for s in compounds)
        assert any("obfuscation-plus-exfiltration" in s for s in compounds)


class TestCompoundWithRealFixture:
    def test_ctx_fixture_triggers_compound(self):
        """The ctx fixture (setup.py) has credential + exfil; adding an exec signal
        in the same file should escalate to CRITICAL (full attack chain)."""
        from aigate.rules.loader import load_rules

        rules = load_rules()

        # Build per-file signals from the ctx fixture by scanning with rules
        per_file_signals: dict[str, list[dict]] = {}
        for filepath, content in CTX_FILES.items():
            for rule in rules:
                if rule.pattern.search(content):
                    per_file_signals.setdefault(filepath, []).append(
                        {"rule_id": rule.id, "tags": list(rule.tags)}
                    )

        # The ctx fixture's setup.py has credential_access + exfiltration
        setup_key = "ctx-0.2.6/setup.py"
        assert setup_key in per_file_signals
        tags_found = set()
        for sig in per_file_signals[setup_key]:
            tags_found.update(sig["tags"])
        assert "credential_access" in tags_found
        assert "exfiltration" in tags_found

        # Simulate the real ctx attack having an exec() call too
        # (the original malware used exec() but our fixture simplified it)
        per_file_signals[setup_key].append(
            {"rule_id": "exec-call", "tags": ["execution", "dynamic"]}
        )

        compounds = check_compound_signals(per_file_signals)
        assert len(compounds) >= 1
        assert any("CRITICAL" in s for s in compounds)


class TestCompoundRulesStructure:
    def test_all_rules_have_required_fields(self):
        """All compound rules have the expected fields."""
        for rule in COMPOUND_RULES:
            assert "id" in rule
            assert "description" in rule
            assert "requires_all" in rule
            assert "min_signals" in rule
            assert "escalate_to" in rule
            assert isinstance(rule["requires_all"], list)
            assert rule["escalate_to"] in ("low", "medium", "high", "critical")
