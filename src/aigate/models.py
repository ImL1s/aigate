"""Core data models for aigate."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    ERROR = "error"


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisLevel(str, Enum):
    L1_QUICK = "l1_quick"
    L2_DEEP = "l2_deep"
    L3_EXPERT = "l3_expert"


@dataclass
class PackageInfo:
    name: str
    version: str
    ecosystem: str  # "pypi", "npm", "pub"
    author: str = ""
    description: str = ""
    download_count: int = 0
    publish_date: str = ""
    homepage: str = ""
    repository: str = ""
    has_install_scripts: bool = False
    dependencies: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FileDiff:
    path: str
    added_lines: list[str] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False


@dataclass
class VersionDiff:
    package: str
    old_version: str
    new_version: str
    files_changed: list[FileDiff] = field(default_factory=list)
    new_imports: list[str] = field(default_factory=list)
    new_network_calls: list[str] = field(default_factory=list)
    new_exec_calls: list[str] = field(default_factory=list)
    new_file_access: list[str] = field(default_factory=list)
    install_script_changes: list[FileDiff] = field(default_factory=list)


@dataclass
class PrefilterResult:
    passed: bool
    reason: str
    risk_signals: list[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.NONE
    needs_ai_review: bool = False


@dataclass
class ModelResult:
    model_name: str
    verdict: Verdict
    confidence: float  # 0.0 - 1.0
    reasoning: str
    risk_signals: list[str] = field(default_factory=list)
    analysis_level: AnalysisLevel = AnalysisLevel.L1_QUICK
    token_usage: int = 0
    latency_ms: int = 0
    raw_response: str = ""


@dataclass
class ConsensusResult:
    final_verdict: Verdict
    confidence: float
    model_results: list[ModelResult] = field(default_factory=list)
    has_disagreement: bool = False
    summary: str = ""
    risk_signals: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class AnalysisReport:
    package: PackageInfo
    prefilter: PrefilterResult
    consensus: ConsensusResult | None = None
    version_diff: VersionDiff | None = None
    cached: bool = False
    total_latency_ms: int = 0
