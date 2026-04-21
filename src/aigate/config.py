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


# ---------------------------------------------------------------------------
# Sandbox configuration (PRD v3.1 §3.4)
# ---------------------------------------------------------------------------
#
# Phase 1 scaffolding: config surface + YAML parsing only. Runtime wiring
# (backends, consensus prompt integration, CLI flags) comes in later tasks.
# Defaults follow the PRD's surface-split semantics:
#   - sandbox.enabled  : false (OPT-IN master switch)
#   - sandbox.check.eager : true (per-invocation coverage by default)
#   - sandbox.scan.eager  : false (only prefilter-SUSPICIOUS packages)
# These inversions are intentional (Architect req #1): ``check`` asks about
# ONE package → user already accepts the cost; ``scan`` touches hundreds →
# prefilter gates unless explicitly --sandbox-eager.


@dataclass
class SandboxObservationConfig:
    """PRD §3.4 ``sandbox.observation`` block."""

    capture_dns: bool = True
    capture_tls: bool = True  # mitmproxy
    capture_fs_writes: bool = True
    capture_env_reads: bool = True
    tracee_signatures: bool = True  # strict mode only
    redact_secrets: bool = True  # PRD P0-5: honour SECRET_ENV_PATTERNS
    canary_scheme: bool = True  # PRD P0-1: decoy bind-mounts
    # PRD P0-2: minimum observability floor. Matches the defaults hard-coded
    # on ``DynamicTrace`` so backend / config stay in sync.
    min_distinct_kinds: int = 3
    min_total_events: int = 10
    applies_if_duration_ms_gte: int = 2000


@dataclass
class SandboxCacheConfig:
    """PRD §3.8 / §3.4 deterministic sandbox output cache.

    Separate from ``~/.opensrc`` / prefilter cache; keyed on
    ``(pkg@version, image_digest, probe_hash, policy_hash, sandbox_mode)``.
    """

    enabled: bool = True
    location: str = "~/.aigate/sandbox-cache/"
    ttl_hours: int = 168  # 7 days
    invalidate_on_version_upgrade: bool = True
    # Key components stored as a tuple so downstream cache code can iterate
    # deterministically. Default mirrors the PRD's canonical key list.
    key_components: tuple[str, ...] = (
        "pkg@version",
        "image_digest",
        "probe_hash",
        "policy_hash",
        "sandbox_mode",
    )


@dataclass
class SandboxCommandGate:
    """Per-command sandbox gating (PRD §3.4 Architect req #1 + #4).

    ``aigate check --sandbox`` defaults to eager coverage; every invocation
    sandboxes regardless of prefilter verdict. ``aigate scan --sandbox``
    defaults to prefilter-gated coverage to keep CI latency realistic
    (200 × 5s would be unacceptable).
    """

    eager: bool = False
    min_prefilter_severity: str = "none"  # none | low | medium | high
    # Only used by the scan gate — hard ceiling on total sandbox wall time
    # before auto-suspension kicks in (PRD P2-14; no silent-SAFE fallback).
    cost_budget_s: int = 900
    # Only used by the scan gate — JSON emits a visible sandbox_skipped_by_gate
    # event so skips are observable rather than silent.
    emit_skipped_signal: bool = True
    # PRD P2-14: ``suspend`` stops the scan; ``warn_and_continue`` proceeds
    # without sandboxing but flags each skipped package as NEEDS_REVIEW.
    budget_exhausted_action: str = "suspend_scan"


@dataclass
class SandboxConfig:
    """Top-level sandbox config (PRD §3.4).

    Attach to :class:`Config` as ``config.sandbox``. Default state is
    OPT-IN: ``enabled=False``. Users flip via ``.aigate.yml`` or the
    ``--sandbox`` CLI flag (wired in a later task).
    """

    enabled: bool = False
    mode: str = "auto"  # auto | light | strict  (paranoid = deprecated alias)
    runtime: str = "auto"  # auto | birdcage | docker | docker-only | docker+runsc
    required: bool = False  # true → hard-error when runtime missing
    timeout_s: int = 60  # clamped to 10..300 by config validator
    image_digest: str = ""  # pinned SHA256; verified at runtime
    # PRD §3.4 v3 P0-3 defaults: deny-outbound + tarball install source.
    network_policy: str = "deny-outbound"  # deny-outbound | deny | registry-only | allow
    install_source: str = "tarball"  # tarball | registry
    observation: SandboxObservationConfig = field(default_factory=SandboxObservationConfig)
    cache: SandboxCacheConfig = field(default_factory=SandboxCacheConfig)
    check: SandboxCommandGate = field(
        default_factory=lambda: SandboxCommandGate(eager=True, min_prefilter_severity="none")
    )
    scan: SandboxCommandGate = field(
        default_factory=lambda: SandboxCommandGate(
            eager=False,
            min_prefilter_severity="medium",
            cost_budget_s=900,
            emit_skipped_signal=True,
            budget_exhausted_action="suspend_scan",
        )
    )

    def normalized_mode(self) -> str:
        """Normalize deprecated ``paranoid`` alias → ``strict`` (PRD P2-11).

        Callers that need the canonical mode string for cache keys MUST
        call this — never read ``self.mode`` directly for hashing. Returns
        ``auto``/``light``/``strict``/``docker+runsc`` only.
        """
        raw = (self.mode or "auto").strip().lower()
        if raw == "paranoid":
            return "strict"
        return raw


@dataclass
class Config:
    models: list[ModelConfig] = field(default_factory=list)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    whitelist: list[str] = field(default_factory=list)
    blocklist: list[str] = field(default_factory=list)
    cache_dir: str = "~/.aigate/cache"
    # 72h matches npm's unpublish window: beyond that an attacker can
    # publish -> get SAFE cached -> unpublish -> republish under same version.
    cache_ttl_hours: int = 72
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
    # PRD v3.1 §3.4: sandbox is OPT-IN; default ``enabled=False``. Wiring
    # into cli.py / consensus.py / policy.py ships in subsequent tasks.
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
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
        cache_ttl_hours=raw.get("cache_ttl_hours", 72),
        max_analysis_level=raw.get("max_analysis_level", "l2_deep"),
        output_format=raw.get("output_format", "rich"),
        ecosystems=raw.get("ecosystems", ["pypi", "npm", "pub", "crates", "cocoapods", "jsr"]),
        enrichment=_parse_enrichment(raw.get("enrichment", {})),
        rules_dir=rules_dir,
        disable_rules=disable_rules,
        emit_opensrc=_parse_emit_opensrc(raw.get("emit_opensrc", {})),
        resolver=_parse_resolver(raw.get("resolver", {})),
        sandbox=_parse_sandbox(raw.get("sandbox", {})),
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


_VALID_SANDBOX_MODES = {"auto", "light", "strict", "paranoid"}
_VALID_SANDBOX_RUNTIMES = {"auto", "birdcage", "docker", "docker-only", "docker+runsc"}
_VALID_NETWORK_POLICIES = {"deny-outbound", "deny", "registry-only", "allow"}
_VALID_INSTALL_SOURCES = {"tarball", "registry"}
_VALID_PREFILTER_SEVERITIES = {"none", "low", "medium", "high"}
_VALID_BUDGET_ACTIONS = {"suspend_scan", "warn_and_continue"}


def _coerce_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _coerce_int(value: Any, default: int, *, field_name: str) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid sandbox.%s=%r (expected int); using default %d", field_name, value, default
        )
        return default


def _coerce_choice(value: Any, *, default: str, choices: set[str], field_name: str) -> str:
    if value is None:
        return default
    raw = str(value).strip().lower()
    if raw not in choices:
        logger.warning(
            "Invalid sandbox.%s=%r (expected one of %s); using default %r",
            field_name,
            value,
            sorted(choices),
            default,
        )
        return default
    return raw


def _parse_sandbox_observation(raw: dict | None) -> SandboxObservationConfig:
    if not raw:
        return SandboxObservationConfig()
    defaults = SandboxObservationConfig()
    floor = raw.get("minimum_floor", {}) or {}
    return SandboxObservationConfig(
        capture_dns=_coerce_bool(raw.get("capture_dns"), defaults.capture_dns),
        capture_tls=_coerce_bool(raw.get("capture_tls"), defaults.capture_tls),
        capture_fs_writes=_coerce_bool(raw.get("capture_fs_writes"), defaults.capture_fs_writes),
        capture_env_reads=_coerce_bool(raw.get("capture_env_reads"), defaults.capture_env_reads),
        tracee_signatures=_coerce_bool(raw.get("tracee_signatures"), defaults.tracee_signatures),
        redact_secrets=_coerce_bool(raw.get("redact_secrets"), defaults.redact_secrets),
        canary_scheme=_coerce_bool(raw.get("canary_scheme"), defaults.canary_scheme),
        min_distinct_kinds=_coerce_int(
            floor.get("min_distinct_kinds"),
            defaults.min_distinct_kinds,
            field_name="observation.minimum_floor.min_distinct_kinds",
        ),
        min_total_events=_coerce_int(
            floor.get("min_total_events"),
            defaults.min_total_events,
            field_name="observation.minimum_floor.min_total_events",
        ),
        applies_if_duration_ms_gte=_coerce_int(
            floor.get("applies_if_duration_ms_gte"),
            defaults.applies_if_duration_ms_gte,
            field_name="observation.minimum_floor.applies_if_duration_ms_gte",
        ),
    )


def _parse_sandbox_cache(raw: dict | None) -> SandboxCacheConfig:
    if not raw:
        return SandboxCacheConfig()
    defaults = SandboxCacheConfig()
    key_components_raw = raw.get("key_components")
    if isinstance(key_components_raw, (list, tuple)) and key_components_raw:
        key_components = tuple(str(x) for x in key_components_raw)
    else:
        key_components = defaults.key_components
    return SandboxCacheConfig(
        enabled=_coerce_bool(raw.get("enabled"), defaults.enabled),
        location=str(raw.get("location", defaults.location)),
        ttl_hours=_coerce_int(
            raw.get("ttl_hours"), defaults.ttl_hours, field_name="cache.ttl_hours"
        ),
        invalidate_on_version_upgrade=_coerce_bool(
            raw.get("invalidate_on_version_upgrade"),
            defaults.invalidate_on_version_upgrade,
        ),
        key_components=key_components,
    )


def _parse_sandbox_gate(raw: dict | None, *, default: SandboxCommandGate) -> SandboxCommandGate:
    if not raw:
        return SandboxCommandGate(
            eager=default.eager,
            min_prefilter_severity=default.min_prefilter_severity,
            cost_budget_s=default.cost_budget_s,
            emit_skipped_signal=default.emit_skipped_signal,
            budget_exhausted_action=default.budget_exhausted_action,
        )
    return SandboxCommandGate(
        eager=_coerce_bool(raw.get("eager"), default.eager),
        min_prefilter_severity=_coerce_choice(
            raw.get("min_prefilter_severity"),
            default=default.min_prefilter_severity,
            choices=_VALID_PREFILTER_SEVERITIES,
            field_name="<gate>.min_prefilter_severity",
        ),
        cost_budget_s=_coerce_int(
            raw.get("cost_budget_s"),
            default.cost_budget_s,
            field_name="<gate>.cost_budget_s",
        ),
        emit_skipped_signal=_coerce_bool(
            raw.get("emit_skipped_signal"), default.emit_skipped_signal
        ),
        budget_exhausted_action=_coerce_choice(
            raw.get("budget_exhausted_action"),
            default=default.budget_exhausted_action,
            choices=_VALID_BUDGET_ACTIONS,
            field_name="<gate>.budget_exhausted_action",
        ),
    )


def _parse_sandbox(raw: object) -> SandboxConfig:
    """Parse the ``sandbox:`` block of ``.aigate.yml`` (PRD §3.4).

    Unknown keys are silently ignored so the config stays forward-compatible
    as later phases add surfaces (e.g. a Tracee rule-pack override).
    Invalid enum values log WARN and fall back to the PRD default — never
    silently enable a less-safe surface (Principle 1).

    Non-dict YAML (e.g. ``sandbox: true`` shorthand) is tolerated: we WARN
    and fall back to defaults rather than crash with AttributeError
    (Codex review P2).
    """
    if raw is None or raw == "" or raw is False:
        return SandboxConfig()
    if not isinstance(raw, dict):
        import logging

        logging.getLogger(__name__).warning(
            "Invalid sandbox config (expected mapping, got %s=%r); "
            "using defaults. Use a nested YAML block, e.g. 'sandbox:\\n  enabled: true'.",
            type(raw).__name__,
            raw,
        )
        return SandboxConfig()
    defaults = SandboxConfig()
    check_default = SandboxCommandGate(eager=True, min_prefilter_severity="none")
    scan_default = SandboxCommandGate(
        eager=False,
        min_prefilter_severity="medium",
        cost_budget_s=900,
        emit_skipped_signal=True,
        budget_exhausted_action="suspend_scan",
    )
    return SandboxConfig(
        enabled=_coerce_bool(raw.get("enabled"), defaults.enabled),
        mode=_coerce_choice(
            raw.get("mode"),
            default=defaults.mode,
            choices=_VALID_SANDBOX_MODES,
            field_name="mode",
        ),
        runtime=_coerce_choice(
            raw.get("runtime"),
            default=defaults.runtime,
            choices=_VALID_SANDBOX_RUNTIMES,
            field_name="runtime",
        ),
        required=_coerce_bool(raw.get("required"), defaults.required),
        timeout_s=_coerce_int(raw.get("timeout_s"), defaults.timeout_s, field_name="timeout_s"),
        image_digest=str(raw.get("image_digest", defaults.image_digest) or ""),
        network_policy=_coerce_choice(
            raw.get("network_policy"),
            default=defaults.network_policy,
            choices=_VALID_NETWORK_POLICIES,
            field_name="network_policy",
        ),
        install_source=_coerce_choice(
            raw.get("install_source"),
            default=defaults.install_source,
            choices=_VALID_INSTALL_SOURCES,
            field_name="install_source",
        ),
        observation=_parse_sandbox_observation(raw.get("observation", {})),
        cache=_parse_sandbox_cache(raw.get("cache", {})),
        check=_parse_sandbox_gate(raw.get("check", {}), default=check_default),
        scan=_parse_sandbox_gate(raw.get("scan", {}), default=scan_default),
    )


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
