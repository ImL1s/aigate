"""Evasion detector: environment-variable mutation (Phase 3 T2).

Detects static attempts to overwrite sensitive environment variables via
``os.environ[KEY] = VALUE`` assignment syntax.  Dynamic detection is deferred
to a future phase (strace env_write events are not yet emitted by Phase 2).
"""

from __future__ import annotations

import re

from ...models import RiskLevel, RiskSignal
from ..types import DynamicTrace
from .base import Detector


class EnvMutationDetector(Detector):
    """Detect writes to sensitive environment variables via os.environ[KEY]=."""

    CATEGORY = "env_mutation"
    SEVERITY = RiskLevel.HIGH

    # Match: os.environ['SSH_AUTH_SOCK'] = ..., os.environ["LD_PRELOAD"] = ..., etc.
    # Sensitive env var names (partial list — will expand with AST detector):
    _SENSITIVE_ENV = re.compile(
        r"""os\.environ\[['"](SSH_AUTH_SOCK|LD_PRELOAD|LD_LIBRARY_PATH|"""
        r"""PYTHONPATH|NODE_PATH|PATH|HOME|USER|HTTP_PROXY|HTTPS_PROXY|"""
        r"""NPM_TOKEN|GITHUB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)['"]\]\s*=""",
        re.IGNORECASE,
    )

    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        """Scan source map for sensitive env-var assignment patterns."""
        signals: list[RiskSignal] = []
        for path, content in source_files.items():
            for match in self._SENSITIVE_ENV.finditer(content):
                signals.append(
                    RiskSignal(
                        category=self.CATEGORY,
                        severity=self.SEVERITY,
                        description=(f"sensitive env mutation in {path}: {match.group(0)[:80]}"),
                    )
                )
        return signals

    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        """Dynamic detection deferred: strace env_write events not yet emitted.

        Phase 2 observer does not emit ``env_write`` events; this method
        returns ``[]`` until the observer is extended.  The CATEGORY string
        will be added here once ``kind == "env_write"`` events are available.
        """
        return []
