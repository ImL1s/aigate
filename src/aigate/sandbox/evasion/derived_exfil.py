"""Evasion detector: derived exfiltration via encode-then-send (Phase 3 T5).

Detects patterns where file contents are encoded (base64/zlib/hex) and
immediately sent over the network. Dynamic detection correlates /tmp writes
with subsequent connect syscalls.
"""

from __future__ import annotations

import re

from ...models import RiskLevel, RiskSignal
from ..types import DynamicTrace
from .base import Detector


class DerivedExfilDetector(Detector):
    """Detect file-read → encode → network-send exfiltration patterns."""

    CATEGORY = "derived_exfil"
    SEVERITY = RiskLevel.HIGH

    # Pattern: encoding call on the same logical expression as a network send.
    # Uses re.DOTALL to match across lines (multi-line expressions).
    # Covers Python (requests/urllib/http) and JS (fetch/btoa).
    _ENCODE_THEN_SEND = re.compile(
        r"""(?:requests\.(?:post|put)|urllib\.|fetch\s*\(|http\.post)"""
        r""".*?"""
        r"""(?:base64\.b64encode|zlib\.compress|binascii\.hexlify|\.hex\(\)|btoa\s*\()""",
        re.DOTALL,
    )
    # Simpler pattern: open().read() piped directly to base64.b64encode
    _READ_THEN_ENCODE = re.compile(
        r"""open\s*\([^)]+\)\.read\s*\(\).*?base64\.b64encode""",
        re.DOTALL,
    )

    # Write-path allowlist — skip files inside these paths (source maps, bundles)
    WRITE_PATH_ALLOWLIST: tuple[str, ...] = (".map", ".wasm", "dist/", "build/", "node_modules/")

    def detect_static(self, source_files: dict[str, str]) -> list[RiskSignal]:
        """Scan source map for encode-then-send patterns."""
        signals: list[RiskSignal] = []
        for path, content in source_files.items():
            if any(part in path for part in self.WRITE_PATH_ALLOWLIST):
                continue  # legitimate minified bundles
            if self._ENCODE_THEN_SEND.search(content) or self._READ_THEN_ENCODE.search(content):
                signals.append(
                    RiskSignal(
                        category=self.CATEGORY,
                        severity=self.SEVERITY,
                        description=f"derived exfil pattern in {path} (encode+send)",
                    )
                )
        return signals

    def detect_dynamic(self, trace: DynamicTrace) -> list[str]:
        """Correlate /tmp writes with subsequent connect syscalls.

        Any write event targeting /tmp followed by at least one connect
        event is suspicious — a common pattern for staging encoded payloads
        before transmission.
        """
        tmp_writes = [
            e for e in trace.events if e.kind == "write" and (e.target or "").startswith("/tmp")
        ]
        connects = [e for e in trace.events if e.kind == "connect"]
        return [self.CATEGORY] if (tmp_writes and connects) else []
