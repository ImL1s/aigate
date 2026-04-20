"""Configuration management for aigate."""

from __future__ import annotations

import logging
import os
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
class EmitOpensrcConfig:
    """Opt-in ``~/.opensrc`` cache emission — aigate writes scanned tarball bytes.

    Per opensrc-integration-plan §3.1, aigate is a *producer* of opensrc-compatible
    output. Emission is off by default; users enable via CLI ``--emit-opensrc`` or
    ``.aigate.yml``.
    """

    enabled: bool = False
    cache_dir: str | None = None  # Defaults to ~/.opensrc when None
    # never: refuse on any collision with unknown-origin directory (safe default)
    # overwrite: always overwrite, regardless of origin (power users)
    # prefer-aigate: overwrite when aigate-scanned (same-SHA no-op, different-SHA wins)
    on_collision: str = "refuse"  # {refuse, overwrite, prefer-aigate}


@dataclass
class ResolverConfig:
    """Resolver archive-size caps (opensrc-integration-plan Phase 2).

    Each ecosystem can override the default 50MB ceiling when its real-world
    package distribution tail exceeds that (e.g. crates.io often ships 100MB+
    SDKs; capping at 50MB would false-block legitimate packages — Principle
    2 violation, see PRD §2.5 S3).
    """

    # 200MB — headroom for aws-sdk-ec2-style large crates; peaks at 5 × 200MB
    # = 1GB under the existing Semaphore(5) concurrency ceiling.
    max_archive_size_crates: int = 200 * 1024 * 1024


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
    ecosystems: list[str] = field(
        default_factory=lambda: ["pypi", "npm", "pub", "crates", "cocoapods", "jsr"]
    )
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    rules_dir: str = ""  # extra rules directory (e.g. ~/.aigate/rules/)
    disable_rules: list[str] = field(default_factory=list)  # rule IDs to skip
    emit_opensrc: EmitOpensrcConfig = field(default_factory=EmitOpensrcConfig)
    resolver: ResolverConfig = field(default_factory=ResolverConfig)
    # Phase 3 (opensrc-integration-plan §3.3, open-questions #9 v2 resolution):
    # optional GitHub PAT for CocoaPods git-sourced podspecs -> GitHub tarball
    # detour. When unset and the unauth endpoint rate-limits, the resolver
    # raises and the CLI downgrades verdict to NEEDS_HUMAN_REVIEW (never SAFE
    # on uninspected bytes — Principle 2).
    github_token: str | None = None

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

    # Parse rules section
    rules_raw = raw.get("rules", {}) or {}
    rules_dir = rules_raw.get("user_rules_dir", "")
    disable_rules = rules_raw.get("disable_rules", [])

    return Config(
        models=models or Config.default().models,
        thresholds=thresholds,
        whitelist=raw.get("whitelist", []),
        blocklist=raw.get("blocklist", []),
        cache_dir=raw.get("cache_dir", "~/.aigate/cache"),
        cache_ttl_hours=raw.get("cache_ttl_hours", 168),
        max_analysis_level=raw.get("max_analysis_level", "l2_deep"),
        output_format=raw.get("output_format", "rich"),
        ecosystems=raw.get("ecosystems", ["pypi", "npm", "pub", "crates", "cocoapods", "jsr"]),
        enrichment=_parse_enrichment(raw.get("enrichment", {})),
        rules_dir=rules_dir,
        disable_rules=disable_rules,
        emit_opensrc=_parse_emit_opensrc(raw.get("emit_opensrc", {})),
        resolver=_parse_resolver(raw.get("resolver", {})),
        github_token=_resolve_github_token(raw.get("github_token")),
    )


def _resolve_github_token(raw: Any) -> str | None:
    """Resolve github_token from yaml, env var fallback (Phase 3).

    Honors (in order): explicit string in .aigate.yml (including ``${GITHUB_TOKEN}``
    placeholder), ``GITHUB_TOKEN`` env var, None. Empty-string and None both
    disable authed GitHub requests — the CocoaPods resolver then degrades to
    NEEDS_HUMAN_REVIEW on rate-limit (open-questions #10).
    """
    if isinstance(raw, str):
        stripped = raw.strip()
        # Support ``github_token: ${GITHUB_TOKEN}`` placeholder without
        # pulling in a full interpolation library.
        if stripped.startswith("${") and stripped.endswith("}"):
            env_name = stripped[2:-1].strip()
            return os.environ.get(env_name) or None
        if stripped:
            return stripped
    return os.environ.get("GITHUB_TOKEN") or None


def _parse_resolver(raw: dict | None) -> ResolverConfig:
    if not raw:
        return ResolverConfig()
    cap_raw = raw.get("max_archive_size_crates")
    cap = ResolverConfig().max_archive_size_crates
    if cap_raw is not None:
        try:
            cap = int(cap_raw)
        except (TypeError, ValueError):
            logger.warning(
                "Invalid resolver.max_archive_size_crates=%r (expected int bytes); "
                "using default %d",
                cap_raw,
                cap,
            )
    return ResolverConfig(max_archive_size_crates=cap)


def _parse_emit_opensrc(raw: dict | None) -> EmitOpensrcConfig:
    if not raw:
        return EmitOpensrcConfig()
    on_collision = str(raw.get("on_collision", "refuse")).lower()
    if on_collision not in {"refuse", "overwrite", "prefer-aigate"}:
        logger.warning(
            "Invalid emit_opensrc.on_collision=%r (expected refuse|overwrite|prefer-aigate); "
            "defaulting to refuse",
            on_collision,
        )
        on_collision = "refuse"
    return EmitOpensrcConfig(
        enabled=bool(raw.get("enabled", False)),
        cache_dir=raw.get("cache_dir"),
        on_collision=on_collision,
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
