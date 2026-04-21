"""E2E: prefilter-level smoke tests for fake_npm fixture packages (Phase 3 T12).

These tests exercise the evasion detector registry directly against synthetic
package source trees (no real package downloads, no birdcage binary needed).
Each test asserts that the multi-evasion gate fires (or does not fire) as
expected, validating the T14 category contract.

Gate: AIGATE_RUN_E2E=1 to opt-in (set automatically by CI E2E job).
Default: tests run unconditionally because they are pure-Python (no external
binary required). The env-gate is preserved for documentation compatibility
with the task spec but defaults to run.
"""

from __future__ import annotations

from pathlib import Path

from aigate.models import RiskLevel
from aigate.sandbox.evasion.base import _SEVERITY_ORDER, categories_from_signals
from aigate.sandbox.evasion.registry import run_static

_MEDIUM_RANK = _SEVERITY_ORDER[RiskLevel.MEDIUM]

FIXTURE_DIR = Path(__file__).parent.parent.parent.parent / "fixtures"


def _load_fixture(name: str) -> dict[str, str]:
    """Load all text files from a fixture directory into a source_files map."""
    pkg_dir = FIXTURE_DIR / name
    source_files: dict[str, str] = {}
    for p in pkg_dir.rglob("*"):
        if p.is_file():
            source_files[str(p.relative_to(pkg_dir))] = p.read_text(errors="replace")
    return source_files


class TestFakeNpmTimeBomb:
    """fake_npm_time_bomb: must fire time_bomb + build_hooks (>=2 MEDIUM+ categories)."""

    def test_categories_ge_2(self):
        source_files = _load_fixture("fake_npm_time_bomb")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        assert len(cats) >= 2, f"expected >=2 categories, got {list(cats.keys())}"

    def test_medium_or_above_ge_2(self):
        source_files = _load_fixture("fake_npm_time_bomb")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        medium_or_above = {c for c, sev in cats.items() if _SEVERITY_ORDER[sev] >= _MEDIUM_RANK}
        assert len(medium_or_above) >= 2, f"expected >=2 MEDIUM+ categories, got {medium_or_above}"

    def test_time_bomb_present(self):
        source_files = _load_fixture("fake_npm_time_bomb")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        assert "time_bomb" in cats, f"time_bomb category missing; cats={list(cats.keys())}"

    def test_build_hooks_present(self):
        source_files = _load_fixture("fake_npm_time_bomb")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        assert "build_hooks" in cats, f"build_hooks category missing; cats={list(cats.keys())}"


class TestFakeNpmEnvMutation:
    """fake_npm_env_mutation: must fire env_mutation + build_hooks (>=2 MEDIUM+ categories)."""

    def test_categories_ge_2(self):
        source_files = _load_fixture("fake_npm_env_mutation")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        assert len(cats) >= 2, f"expected >=2 categories, got {list(cats.keys())}"

    def test_medium_or_above_ge_2(self):
        source_files = _load_fixture("fake_npm_env_mutation")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        medium_or_above = {c for c, sev in cats.items() if _SEVERITY_ORDER[sev] >= _MEDIUM_RANK}
        assert len(medium_or_above) >= 2, f"expected >=2 MEDIUM+ categories, got {medium_or_above}"

    def test_env_mutation_present(self):
        source_files = _load_fixture("fake_npm_env_mutation")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        assert "env_mutation" in cats, f"env_mutation category missing; cats={list(cats.keys())}"

    def test_build_hooks_present(self):
        source_files = _load_fixture("fake_npm_env_mutation")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        assert "build_hooks" in cats, f"build_hooks category missing; cats={list(cats.keys())}"


class TestFakeNpmClean:
    """fake_npm_clean: must fire zero evasion categories."""

    def test_zero_categories(self):
        source_files = _load_fixture("fake_npm_clean")
        signals = run_static(source_files)
        cats = categories_from_signals(signals, [])
        assert len(cats) == 0, f"expected 0 evasion categories for clean package, got {cats}"

    def test_zero_signals(self):
        source_files = _load_fixture("fake_npm_clean")
        signals = run_static(source_files)
        assert signals == [], f"expected no signals for clean package, got {signals}"
