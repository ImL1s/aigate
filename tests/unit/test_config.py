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
        f.write_text(
            "thresholds:\n"
            "  malicious: 0.8\n"
            "  suspicious: 0.7\n"
        )
        c = _parse_config(f)
        assert c.thresholds.malicious == 0.8
        assert c.thresholds.suspicious == 0.7

    def test_whitelist_blocklist(self, tmp_path: Path):
        f = tmp_path / ".aigate.yml"
        f.write_text(
            "whitelist:\n"
            "  - requests\n"
            "  - numpy\n"
            "blocklist:\n"
            "  - crossenv\n"
        )
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
        f.write_text(
            "enrichment:\n"
            "  enabled: true\n"
            "  osv:\n"
            "    enabled: true\n"
        )
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
