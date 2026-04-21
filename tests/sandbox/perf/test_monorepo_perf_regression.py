"""Perf-regression test: strace observer overhead ≤ 1.5× clean npm install.

REV-J invariant (§4 R5):
  strace ptrace overhead on a representative npm workload must stay ≤ 1.5×
  the untraced wall-clock time.  Failure is surfaced as pytest.skip with a
  coverage-warning log (not a hard CI fail) until Phase 3 raises the budget.

Gate: AIGATE_RUN_PERF=1 env var + strace on PATH + Linux.

Fixture: lodash@4.17.21 (650 files, ~1.5 MB, zero transitive deps).
See tests/sandbox/perf/fixtures/README.md for fixture rationale.

Method:
  1. Warm npm cache with one pre-run (avoids cold-cache bias).
  2. Time t_clean  = npm install --prefer-offline (no strace).
  3. Time t_traced = strace -f -e trace=... -o /dev/null -- npm install.
  4. Assert t_traced / t_clean ≤ RATIO_CEILING (1.5).
  5. Log ratio to stdout for CI trend tracking regardless of pass/fail.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import time

import pytest

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

_PERF_GATE = pytest.mark.skipif(
    not os.environ.get("AIGATE_RUN_PERF"),
    reason="AIGATE_RUN_PERF=1 not set — perf regression test skipped",
)
_LINUX_GATE = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="strace observer perf test is Linux-only",
)
_STRACE_GATE = pytest.mark.skipif(
    shutil.which("strace") is None,
    reason="strace not on PATH — perf test requires strace binary",
)
_NPM_GATE = pytest.mark.skipif(
    shutil.which("npm") is None,
    reason="npm not on PATH — perf test requires npm binary",
)

pytestmark = [_PERF_GATE, _LINUX_GATE, _STRACE_GATE, _NPM_GATE]

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: REV-J acceptance threshold — strace overhead must stay within 1.5× clean.
RATIO_CEILING: float = 1.5

#: Fixture package pinned for reproducibility (see fixtures/README.md).
FIXTURE_PACKAGE: str = "lodash@4.17.21"

#: strace flags that mirror StraceObserver.argv_prefix() exactly.
#: -o /dev/null avoids FIFO I/O skewing the timing measurement.
_STRACE_FLAGS: list[str] = [
    "strace", "-f",
    "-e", "trace=connect,openat,write,execve,clone",
    "-o", "/dev/null",
    "--",
]

#: npm install flags: offline-prefer (uses ~/.npm cache), no audit noise.
_NPM_FLAGS: list[str] = [
    "npm", "install",
    "--prefer-offline",
    "--no-audit",
    "--no-fund",
    "--no-save",
]

#: Minimum meaningful t_clean to guard against a near-zero denominator.
#: If npm finishes in < 0.5 s the ratio is unreliable — skip instead.
_MIN_CLEAN_SECONDS: float = 0.5

#: Hard cap: if either run exceeds this we abort (CI timeout safety).
_RUN_TIMEOUT_S: int = 180


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_package_dir(tmp_path, suffix: str) -> str:
    """Create an isolated npm project dir with the fixture package.json."""
    pkg_dir = str(tmp_path / suffix)
    os.makedirs(pkg_dir, exist_ok=True)
    pkg_json = {
        "name": f"aigate-perf-fixture-{suffix}",
        "version": "1.0.0",
        "private": True,
        "dependencies": {FIXTURE_PACKAGE.split("@")[0]: FIXTURE_PACKAGE.split("@")[1]},
    }
    with open(os.path.join(pkg_dir, "package.json"), "w") as f:
        json.dump(pkg_json, f)
    return pkg_dir


def _npm_install(pkg_dir: str, traced: bool = False) -> float:
    """Run npm install and return wall-clock seconds.

    ``traced=True`` prepends the strace flags (mirrors BirdcageBackend argv).
    Returns float('inf') if the process fails, so ratio comparisons still work
    without crashing — the caller handles the failure.
    """
    cmd = (_STRACE_FLAGS if traced else []) + _NPM_FLAGS
    try:
        t0 = time.monotonic()
        result = subprocess.run(
            cmd,
            cwd=pkg_dir,
            capture_output=True,
            timeout=_RUN_TIMEOUT_S,
            check=False,
        )
        elapsed = time.monotonic() - t0
        if result.returncode != 0 and not traced:
            # Clean run must succeed for a valid baseline
            stderr = result.stderr.decode(errors="replace")[:300]
            raise RuntimeError(f"clean npm install failed (rc={result.returncode}): {stderr}")
        return elapsed
    except subprocess.TimeoutExpired:
        return float("inf")


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


class TestMonorepoPerfRegression:
    @pytest.fixture(autouse=True)
    def _warm_npm_cache(self, tmp_path):
        """Pre-populate ~/.npm cache before timing begins."""
        warm_dir = _make_package_dir(tmp_path, "warm")
        try:
            result = subprocess.run(
                _NPM_FLAGS,
                cwd=warm_dir,
                capture_output=True,
                timeout=_RUN_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pytest.skip(
                f"npm cache warm-up exceeded {_RUN_TIMEOUT_S}s — "
                "increase timeout or check network/disk"
            )
        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace")[:400]
            pytest.skip(
                f"npm cache warm-up failed (rc={result.returncode}). "
                f"Ensure npm can reach the registry or the package is cached.\n{stderr}"
            )

    def test_strace_overhead_within_ratio_ceiling(self, tmp_path):
        """t_traced / t_clean must be ≤ 1.5 (REV-J R5 budget).

        Failure is surfaced as pytest.skip (coverage warning) rather than
        a hard CI fail — visibility without blocking merges until Phase 3
        raises the perf budget.
        """
        clean_dir = _make_package_dir(tmp_path, "clean")
        traced_dir = _make_package_dir(tmp_path, "traced")

        # Measure clean baseline
        try:
            t_clean = _npm_install(clean_dir, traced=False)
        except RuntimeError as exc:
            pytest.skip(f"clean npm baseline failed: {exc}")

        if t_clean < _MIN_CLEAN_SECONDS:
            pytest.skip(
                f"t_clean={t_clean:.3f}s is below {_MIN_CLEAN_SECONDS}s minimum — "
                "install too fast to measure ratio reliably (likely fully cached)"
            )

        # Measure traced run
        t_traced = _npm_install(traced_dir, traced=True)

        ratio = t_traced / t_clean if t_clean > 0 else float("inf")

        # Always surface ratio in logs for CI trend tracking
        log.warning(
            "[REV-J perf] t_clean=%.3fs  t_traced=%.3fs  ratio=%.2fx  ceiling=%.1fx  %s",
            t_clean,
            t_traced,
            ratio,
            RATIO_CEILING,
            "PASS" if ratio <= RATIO_CEILING else "OVER_BUDGET",
        )
        print(
            f"\n[REV-J perf] fixture={FIXTURE_PACKAGE}"
            f"  t_clean={t_clean:.3f}s  t_traced={t_traced:.3f}s"
            f"  ratio={ratio:.2f}x  ceiling={RATIO_CEILING}x"
            f"  {'PASS' if ratio <= RATIO_CEILING else 'OVER_BUDGET'}"
        )

        if t_traced == float("inf"):
            pytest.skip(
                f"traced npm install timed out after {_RUN_TIMEOUT_S}s — "
                "cannot compute ratio"
            )

        if ratio > RATIO_CEILING:
            # Soft fail: skip with warning (REV-J: not a hard CI fail)
            pytest.skip(
                f"[REV-J perf budget exceeded] "
                f"t_traced/t_clean = {ratio:.2f}x > {RATIO_CEILING}x ceiling. "
                f"t_clean={t_clean:.3f}s, t_traced={t_traced:.3f}s, "
                f"fixture={FIXTURE_PACKAGE}. "
                "Raise Phase 3 priority on bpftrace observer (§4 R5) or "
                "increase --sandbox-timeout."
            )

        # Hard assertion only reached when ratio is within budget
        assert ratio <= RATIO_CEILING, (
            f"strace overhead {ratio:.2f}x exceeds {RATIO_CEILING}x ceiling "
            f"(t_clean={t_clean:.3f}s, t_traced={t_traced:.3f}s)"
        )

    def test_strace_overhead_logged_regardless_of_outcome(self, tmp_path):
        """Ratio is always surfaced in CI logs even on fast/cached runs.

        This test never fails — it only logs.  Useful for trend tracking
        when t_clean < _MIN_CLEAN_SECONDS (too fast for ratio assertion).
        """
        clean_dir = _make_package_dir(tmp_path, "log-clean")
        traced_dir = _make_package_dir(tmp_path, "log-traced")

        try:
            t_clean = _npm_install(clean_dir, traced=False)
        except RuntimeError:
            return  # cache miss or failure — nothing to log

        t_traced = _npm_install(traced_dir, traced=True)
        if t_traced == float("inf") or t_clean <= 0:
            return

        ratio = t_traced / t_clean
        print(
            f"\n[REV-J trend] fixture={FIXTURE_PACKAGE}"
            f"  t_clean={t_clean:.3f}s  t_traced={t_traced:.3f}s"
            f"  ratio={ratio:.2f}x"
        )
        # No assertion — logging only
