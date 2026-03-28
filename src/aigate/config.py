"""Configuration management for aigate."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .enrichment import (
    Context7Config,
    DepsDevConfig,
    EnrichmentConfig,
    OsvConfig,
    ProvenanceConfig,
    ScorecardConfig,
    WebSearchConfig,
)

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_NAME = ".aigate.yml"


@dataclass
class ModelConfig:
    name: str
    backend: str  # "claude", "gemini", "codex", "ollama"
    weight: float = 1.0
    enabled: bool = True
    model_id: str = ""
    timeout_seconds: int = 120
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class ThresholdConfig:
    malicious: float = 0.6
    suspicious: float = 0.5
    disagreement: float = 0.4  # standard deviation threshold for disagreement


@dataclass
class Config:
    models: list[ModelConfig] = field(default_factory=list)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    whitelist: list[str] = field(default_factory=list)
    blocklist: list[str] = field(default_factory=list)
    cache_dir: str = "~/.aigate/cache"
    cache_ttl_hours: int = 168  # 7 days
    max_analysis_level: str = "l2_deep"  # l1_quick, l2_deep, l3_expert
    output_format: str = "rich"  # rich, json, sarif
    ecosystems: list[str] = field(default_factory=lambda: ["pypi", "npm", "pub"])
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)

    @classmethod
    def default(cls) -> Config:
        return cls(
            models=[
                ModelConfig(
                    name="claude",
                    backend="claude",
                    weight=1.0,
                    model_id="claude-sonnet-4-6",
                ),
                ModelConfig(
                    name="gemini",
                    backend="gemini",
                    weight=0.9,
                    model_id="gemini-2.5-pro",
                ),
            ],
        )

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        if path is None:
            path = _find_config()
        if path is None or not path.exists():
            return cls.default()
        config = _parse_config(path)

        from .config_validator import ConfigValidationError, validate_config

        try:
            validate_config(config)
        except ConfigValidationError as e:
            logger.warning("Config validation: %s", e)
        return config


def _find_config() -> Path | None:
    cwd = Path.cwd()
    for directory in [cwd, *cwd.parents]:
        candidate = directory / DEFAULT_CONFIG_NAME
        if candidate.exists():
            return candidate
    home_config = Path.home() / DEFAULT_CONFIG_NAME
    if home_config.exists():
        return home_config
    return None


def _parse_config(path: Path) -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f)
    if not raw:
        return Config.default()

    models = []
    for m in raw.get("models", []):
        models.append(
            ModelConfig(
                name=m.get("name", "unknown"),
                backend=m.get("backend", "claude"),
                weight=m.get("weight", 1.0),
                enabled=m.get("enabled", True),
                model_id=m.get("model_id", ""),
                timeout_seconds=m.get("timeout_seconds", 120),
                options=m.get("options", {}),
            )
        )

    thresholds = ThresholdConfig()
    if "thresholds" in raw:
        t = raw["thresholds"]
        thresholds = ThresholdConfig(
            malicious=t.get("malicious", 0.6),
            suspicious=t.get("suspicious", 0.5),
            disagreement=t.get("disagreement", 0.4),
        )

    return Config(
        models=models or Config.default().models,
        thresholds=thresholds,
        whitelist=raw.get("whitelist", []),
        blocklist=raw.get("blocklist", []),
        cache_dir=raw.get("cache_dir", "~/.aigate/cache"),
        cache_ttl_hours=raw.get("cache_ttl_hours", 168),
        max_analysis_level=raw.get("max_analysis_level", "l2_deep"),
        output_format=raw.get("output_format", "rich"),
        ecosystems=raw.get("ecosystems", ["pypi", "npm", "pub"]),
        enrichment=_parse_enrichment(raw.get("enrichment", {})),
    )


def _parse_enrichment(raw: dict | None) -> EnrichmentConfig:
    if not raw:
        return EnrichmentConfig()
    return EnrichmentConfig(
        enabled=raw.get("enabled", False),
        context7=Context7Config(
            enabled=raw.get("context7", {}).get("enabled", False),
            api_key_env=raw.get("context7", {}).get("api_key_env", "CONTEXT7_API_KEY"),
        ),
        web_search=WebSearchConfig(
            enabled=raw.get("web_search", {}).get("enabled", False),
            provider=raw.get("web_search", {}).get("provider", "brightdata"),
            api_key_env=raw.get("web_search", {}).get("api_key_env", "BRIGHT_DATA_API_KEY"),
            zone=raw.get("web_search", {}).get("zone", ""),
        ),
        osv=OsvConfig(
            enabled=raw.get("osv", {}).get("enabled", True),
        ),
        deps_dev=DepsDevConfig(
            enabled=raw.get("deps_dev", {}).get("enabled", False),
            api_base_url=raw.get("deps_dev", {}).get("api_base_url", "https://api.deps.dev/v3"),
        ),
        scorecard=ScorecardConfig(
            enabled=raw.get("scorecard", {}).get("enabled", False),
            api_base_url=raw.get("scorecard", {}).get(
                "api_base_url",
                "https://api.securityscorecards.dev",
            ),
        ),
        provenance=ProvenanceConfig(
            enabled=raw.get("provenance", {}).get("enabled", False),
        ),
        timeout_seconds=raw.get("timeout_seconds", 10),
    )
