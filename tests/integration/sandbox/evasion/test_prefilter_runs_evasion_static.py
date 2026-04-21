"""Integration: prefilter calls evasion static detectors (Phase 3 T9).

Verifies that run_prefilter (or registry.run_static directly) returns
signals containing evasion categories when source files match known patterns.
"""

from __future__ import annotations

from aigate.models import RiskSignal
from aigate.sandbox.evasion.registry import run_static


def test_run_static_env_mutation_fires() -> None:
    """Source with env mutation pattern produces env_mutation signal."""
    source_files = {
        "install.py": "import os\nos.environ['LD_PRELOAD'] = '/tmp/evil.so'\n",
    }
    signals = run_static(source_files)
    categories = [s.category for s in signals if isinstance(s, RiskSignal)]
    assert "env_mutation" in categories, (
        f"env_mutation not in signals; got categories: {categories}"
    )


def test_run_static_build_hooks_fires() -> None:
    """Package.json with postinstall script produces build_hooks signal."""
    source_files = {
        "package.json": (
            '{"name":"evil","version":"1.0.0",'
            '"scripts":{"postinstall":"node install.js"}}'
        ),
    }
    signals = run_static(source_files)
    categories = [s.category for s in signals if isinstance(s, RiskSignal)]
    assert "build_hooks" in categories, f"build_hooks not in signals; got categories: {categories}"


def test_run_static_both_categories_present() -> None:
    """Source files with both env_mutation and build_hooks patterns fire both."""
    source_files = {
        "package.json": (
            '{"name":"evil","version":"1.0.0",'
            '"scripts":{"postinstall":"node install.js"}}'
        ),
        "install.py": "import os\nos.environ['LD_PRELOAD'] = '/tmp/evil.so'\n",
    }
    signals = run_static(source_files)
    categories = {s.category for s in signals if isinstance(s, RiskSignal)}
    assert "env_mutation" in categories, f"env_mutation missing; categories={categories}"
    assert "build_hooks" in categories, f"build_hooks missing; categories={categories}"


def test_prefilter_preserves_evasion_risksignal_structured_form() -> None:
    """Regression: evasion RiskSignal objects must survive through run_prefilter.

    If this breaks, the T14 multi-evasion gate in decision_from_prefilter
    becomes dead code (isinstance(s, RiskSignal) filter returns empty list).
    """
    from aigate.config import Config
    from aigate.models import PackageInfo
    from aigate.prefilter import run_prefilter

    pkg = PackageInfo(name="evil", version="1.0.0", ecosystem="pypi")
    source_files = {
        "install.py": "import os\nos.environ['LD_PRELOAD'] = '/tmp/evil.so'\n",
    }
    result = run_prefilter(pkg, Config(), source_files=source_files)
    structured = [s for s in result.risk_signals if isinstance(s, RiskSignal)]
    evasion_cats = {s.category for s in structured}
    assert "env_mutation" in evasion_cats, (
        f"env_mutation RiskSignal lost during prefilter; got: "
        f"{[type(s).__name__ for s in result.risk_signals]}"
    )


def test_single_high_evasion_does_not_auto_escalate_to_malicious() -> None:
    """REV-NI2: 1 HIGH evasion category must NOT auto-trigger MALICIOUS.

    Autonomous blocking requires ≥2 orthogonal HIGH evasion tactics (enforced
    by T14 gate). Legacy _calculate_risk_level must carve out evasion HIGH.
    """
    from aigate.config import Config
    from aigate.models import PackageInfo, RiskLevel
    from aigate.policy import PolicyOutcome, decision_from_prefilter
    from aigate.prefilter import run_prefilter

    pkg = PackageInfo(name="evil", version="1.0.0", ecosystem="pypi")
    source_files = {
        "install.py": "import os\nos.environ['LD_PRELOAD'] = '/tmp/evil.so'\n",
    }
    result = run_prefilter(pkg, Config(), source_files=source_files)
    # Must not escalate to HIGH/CRITICAL from a single evasion HIGH
    assert result.risk_level != RiskLevel.CRITICAL, (
        "single HIGH evasion wrongly escalated to CRITICAL; "
        "REV-NI2 requires ≥2 HIGH for autonomous blocking"
    )
    decision = decision_from_prefilter(result)
    assert decision.outcome != PolicyOutcome.MALICIOUS, (
        f"single HIGH evasion wrongly escalated to MALICIOUS; got: "
        f"{decision.outcome} ({decision.reason})"
    )
