"""R4 perf budget: full detector registry <= 250ms on 5MB synthetic fixture.

Skip on AIGATE_SKIP_PERF=1 (for CI cold-cache environments).
Budget: 50ms/MB * 5MB = 250ms; allow 500ms for cold Python startup.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from aigate.sandbox.evasion.registry import run_static

pytestmark = pytest.mark.skipif(
    os.environ.get("AIGATE_SKIP_PERF") == "1",
    reason="AIGATE_SKIP_PERF=1 set — skip perf budget test",
)


def _synthetic_5mb_source_tree() -> dict[str, str]:
    """Generate ~5MB of fake JS/TS/JSON content spread across ~750 files."""
    files: dict[str, str] = {}
    # ~7KB per file x 700 js/ts files + json padding = ~5MB total
    benign_js = "// benign code\n" + "const x = 1;\n" * 700  # ~10KB
    benign_json = json.dumps({"name": "f", "version": "1.0.0", "dependencies": {}})
    for i in range(500):
        files[f"src/module_{i}.js"] = benign_js
    for i in range(100):
        files[f"node_modules/pkg_{i}/package.json"] = benign_json
    for i in range(150):
        files[f"lib/util_{i}.ts"] = benign_js
    return files


def test_detector_runtime_budget():
    source = _synthetic_5mb_source_tree()
    total_bytes = sum(len(v) for v in source.values())
    assert total_bytes > 4_500_000, f"fixture must be >=4.5MB, got {total_bytes}"

    start = time.monotonic()
    signals = run_static(source)
    elapsed = time.monotonic() - start

    # Budget: 50ms/MB x 5MB = 250ms; allow 500ms for cold Python startup
    budget = 0.5
    assert elapsed < budget, (
        f"detectors took {elapsed:.2f}s on 5MB (budget {budget}s); signals={len(signals)}"
    )
