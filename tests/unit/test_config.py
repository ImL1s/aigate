"""Tests for configuration management."""

from pathlib import Path

from aigate.config import Config, _parse_config


class TestDefault:
    def test_default_has_two_models(self):
        c = Config.default()
        assert len(c.models) == 2

    def test_default_model_names(self):
        c = Config.default()
        names = {m.name for m in c.models}
        assert "claude" in names
        assert "gemini" in names

    def test_default_thresholds(self):
        c = Config.default()
        assert c.thresholds.malicious == 0.6
        assert c.thresholds.suspicious == 0.5

    def test_default_cache_dir(self):
        c = Config.default()
        assert "aigate" in c.cache_dir

    def test_default_ecosystems_include_pub(self):
        c = Config.default()
        assert "pub" in c.ecosystems


class TestParseYaml:
    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("")
        c = _parse_config(f)
        # Should fallback to defaults
        assert len(c.models) == 2

    def test_custom_models(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text(
            "models:\n"
            "  - name: ollama\n"
            "    backend: ollama\n"
            "    weight: 0.8\n"
            "    model_id: llama3.1:8b\n"
        )
        c = _parse_config(f)
        assert len(c.models) == 1
        assert c.models[0].name == "ollama"
        assert c.models[0].weight == 0.8
        assert c.models[0].model_id == "llama3.1:8b"

    def test_custom_thresholds(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("thresholds:\n  malicious: 0.8\n  suspicious: 0.7\n")
        c = _parse_config(f)
        assert c.thresholds.malicious == 0.8
        assert c.thresholds.suspicious == 0.7

    def test_whitelist_blocklist(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("whitelist:\n  - requests\n  - numpy\nblocklist:\n  - crossenv\n")
        c = _parse_config(f)
        assert "requests" in c.whitelist
        assert "crossenv" in c.blocklist

    def test_ecosystems(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("ecosystems:\n  - pypi\n  - npm\n  - pub\n")
        c = _parse_config(f)
        assert "pub" in c.ecosystems


class TestEnrichmentConfig:
    def test_default_enrichment_disabled(self):
        c = Config.default()
        assert hasattr(c, "enrichment")
        assert c.enrichment.enabled is False

    def test_parse_enrichment(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("enrichment:\n  enabled: true\n  osv:\n    enabled: true\n")
        c = _parse_config(f)
        assert c.enrichment.enabled is True


class TestLoad:
    def test_load_missing_returns_default(self):
        c = Config.load(Path("/nonexistent/.aigate.yml"))
        assert len(c.models) == 2

    def test_load_none_returns_default(self, monkeypatch):
        # Ensure no config file is found by patching cwd to tmp
        monkeypatch.chdir("/tmp")
        c = Config.load(None)
        assert isinstance(c, Config)


# ---------------------------------------------------------------------------
# Sandbox config — PRD v3.1 §3.4 — Phase 1 scaffold
# ---------------------------------------------------------------------------


class TestSandboxConfig:
    def test_default_sandbox_is_opt_in(self):
        c = Config.default()
        assert hasattr(c, "sandbox")
        # PRD Principle 1: sandbox is OPT-IN. Default must stay False.
        assert c.sandbox.enabled is False

    def test_default_sandbox_mode_and_runtime(self):
        c = Config.default()
        assert c.sandbox.mode == "auto"
        assert c.sandbox.runtime == "auto"
        assert c.sandbox.required is False

    def test_default_network_policy_is_deny_outbound(self):
        # PRD §3.4 v3 P0-3: deny-outbound is the shipped default.
        c = Config.default()
        assert c.sandbox.network_policy == "deny-outbound"
        assert c.sandbox.install_source == "tarball"

    def test_default_command_gates_invert_check_and_scan(self):
        # PRD Architect req #1: check eager=True, scan eager=False.
        c = Config.default()
        assert c.sandbox.check.eager is True
        assert c.sandbox.check.min_prefilter_severity == "none"
        assert c.sandbox.scan.eager is False
        assert c.sandbox.scan.min_prefilter_severity == "medium"
        assert c.sandbox.scan.cost_budget_s == 900
        assert c.sandbox.scan.budget_exhausted_action == "suspend_scan"

    def test_default_observation_captures_all_surfaces(self):
        c = Config.default()
        obs = c.sandbox.observation
        assert obs.capture_dns is True
        assert obs.capture_tls is True
        assert obs.capture_fs_writes is True
        assert obs.capture_env_reads is True
        assert obs.redact_secrets is True
        assert obs.canary_scheme is True

    def test_default_observation_floor_matches_prd(self):
        # PRD P0-2 floor: ≥3 distinct kinds OR ≥10 events for ≥2s runs.
        c = Config.default()
        obs = c.sandbox.observation
        assert obs.min_distinct_kinds == 3
        assert obs.min_total_events == 10
        assert obs.applies_if_duration_ms_gte == 2000

    def test_default_cache_ttl_aligns_with_prefilter(self):
        c = Config.default()
        assert c.sandbox.cache.enabled is True
        assert c.sandbox.cache.ttl_hours == 168

    def test_default_cache_key_components(self):
        c = Config.default()
        keys = c.sandbox.cache.key_components
        for needed in ("pkg@version", "image_digest", "probe_hash", "policy_hash", "sandbox_mode"):
            assert needed in keys

    def test_parse_sandbox_enabled(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("sandbox:\n  enabled: true\n  mode: strict\n")
        c = _parse_config(f)
        assert c.sandbox.enabled is True
        assert c.sandbox.mode == "strict"

    def test_parse_sandbox_invalid_mode_falls_back_to_default(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("sandbox:\n  mode: super_paranoid\n")
        c = _parse_config(f)
        # Invalid → warn + default; NEVER silently promote to a less-safe surface.
        assert c.sandbox.mode == "auto"

    def test_parse_sandbox_deprecated_paranoid_alias_preserved_raw(self, tmp_path: Path):
        # Raw ``paranoid`` is still valid for backward-compat; canonicalization
        # happens via normalized_mode(). This test pins the alias acceptance
        # at the config surface per PRD P2-11.
        f = tmp_path / ".aigate.yml"
        f.write_text("sandbox:\n  mode: paranoid\n")
        c = _parse_config(f)
        assert c.sandbox.mode == "paranoid"
        assert c.sandbox.normalized_mode() == "strict"

    def test_parse_sandbox_per_command_gates(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text(
            "sandbox:\n"
            "  enabled: true\n"
            "  check:\n"
            "    eager: false\n"
            "    min_prefilter_severity: high\n"
            "  scan:\n"
            "    eager: true\n"
            "    cost_budget_s: 1200\n"
            "    budget_exhausted_action: warn_and_continue\n"
        )
        c = _parse_config(f)
        assert c.sandbox.check.eager is False
        assert c.sandbox.check.min_prefilter_severity == "high"
        assert c.sandbox.scan.eager is True
        assert c.sandbox.scan.cost_budget_s == 1200
        assert c.sandbox.scan.budget_exhausted_action == "warn_and_continue"

    def test_parse_sandbox_observation_overrides(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text(
            "sandbox:\n"
            "  observation:\n"
            "    capture_tls: false\n"
            "    redact_secrets: true\n"
            "    minimum_floor:\n"
            "      min_distinct_kinds: 5\n"
            "      min_total_events: 20\n"
            "      applies_if_duration_ms_gte: 5000\n"
        )
        c = _parse_config(f)
        assert c.sandbox.observation.capture_tls is False
        assert c.sandbox.observation.redact_secrets is True
        assert c.sandbox.observation.min_distinct_kinds == 5
        assert c.sandbox.observation.min_total_events == 20
        assert c.sandbox.observation.applies_if_duration_ms_gte == 5000

    def test_parse_sandbox_empty_block_matches_default(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("sandbox: {}\n")
        c = _parse_config(f)
        defaults = Config.default().sandbox
        assert c.sandbox.enabled == defaults.enabled
        assert c.sandbox.mode == defaults.mode
        assert c.sandbox.check.eager == defaults.check.eager
        assert c.sandbox.scan.eager == defaults.scan.eager

    def test_parse_sandbox_invalid_network_policy_warns_and_defaults(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("sandbox:\n  network_policy: wide_open\n")
        c = _parse_config(f)
        assert c.sandbox.network_policy == "deny-outbound"

    def test_parse_sandbox_invalid_budget_action_warns_and_defaults(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text("sandbox:\n  scan:\n    budget_exhausted_action: ignore_and_ship\n")
        c = _parse_config(f)
        # Must fall back to the safe default (suspend_scan), not the bogus value.
        assert c.sandbox.scan.budget_exhausted_action == "suspend_scan"

    def test_parse_sandbox_cache_overrides(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text(
            "sandbox:\n"
            "  cache:\n"
            "    enabled: false\n"
            "    ttl_hours: 24\n"
            "    location: /tmp/sbxcache/\n"
        )
        c = _parse_config(f)
        assert c.sandbox.cache.enabled is False
        assert c.sandbox.cache.ttl_hours == 24
        assert c.sandbox.cache.location == "/tmp/sbxcache/"

    def test_parse_sandbox_scalar_true_falls_back_to_defaults(self, tmp_path: Path, caplog):
        """Codex P2: `sandbox: true` shorthand must not crash config load.

        Before the fix this raised AttributeError because _parse_sandbox
        called raw.get(...) on a bool. Now it WARNs and returns defaults.
        """
        import logging

        f = tmp_path / ".aigate.yml"
        f.write_text("sandbox: true\n")
        with caplog.at_level(logging.WARNING, logger="aigate.config"):
            c = _parse_config(f)
        assert c.sandbox.enabled is False  # falls back to default
        assert any("Invalid sandbox config" in rec.getMessage() for rec in caplog.records), (
            f"expected WARN on scalar sandbox, got: {[r.getMessage() for r in caplog.records]}"
        )

    def test_parse_sandbox_string_falls_back_to_defaults(self, tmp_path: Path, caplog):
        """Same Codex P2 hardening for `sandbox: enabled` (string)."""
        import logging

        f = tmp_path / ".aigate.yml"
        f.write_text("sandbox: enabled\n")
        with caplog.at_level(logging.WARNING, logger="aigate.config"):
            c = _parse_config(f)
        assert c.sandbox.enabled is False
