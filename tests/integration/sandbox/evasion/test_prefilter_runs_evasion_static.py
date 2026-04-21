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
