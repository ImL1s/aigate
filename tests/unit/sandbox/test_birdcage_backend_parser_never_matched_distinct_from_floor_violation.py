"""Tests: parse_birdcage_stream + classify_parse_quality (Task #5, Phase 1b).

Verifies parser-never-matched (0/N) is distinct from floor violation,
and that partial-drift detection works per REV-4 thresholds.
"""

from __future__ import annotations

import json

from aigate.sandbox.birdcage_backend import classify_parse_quality, parse_birdcage_stream
from aigate.sandbox.types import SandboxCoverage


def _valid_line(**overrides: object) -> str:
    base: dict = {"kind": "open", "ts_ms": 100, "pid": 42, "process": "npm", "target": "/tmp/x"}
    base.update(overrides)
    return json.dumps(base)


class TestParserNeverMatched:
    def test_zero_of_ten_events_parsed(self) -> None:
        lines = ["some log preamble"] * 10
        events, events_parsed, raw_lines_seen = parse_birdcage_stream(lines)
        assert events == []
        assert events_parsed == 0
        assert raw_lines_seen == 10

    def test_classify_zero_matched_returns_error_and_drift_coverage(self) -> None:
        err, cov = classify_parse_quality(0, 10)
        assert err is not None
        assert "0/10" in err
        assert cov == SandboxCoverage.PARSER_PARTIAL_DRIFT


class TestPartialDrift:
    def test_seven_of_ten_ratio_is_not_partial_drift(self) -> None:
        # 7 valid + 3 non-JSON → ratio 70% ≥ 50% floor → healthy
        valid = [_valid_line() for _ in range(7)]
        invalid = [f"unexpected-format-line-{i}" for i in range(3)]
        lines = valid + invalid
        events, events_parsed, raw_lines_seen = parse_birdcage_stream(lines)
        assert events_parsed == 7
        assert raw_lines_seen == 10
        err, cov = classify_parse_quality(events_parsed, raw_lines_seen)
        assert err is None
        assert cov is None

    def test_one_of_ten_ratio_triggers_partial_drift(self) -> None:
        # 1 valid + 9 non-JSON → ratio 10% < 50% floor → PARSER_PARTIAL_DRIFT
        lines = [_valid_line()] + ["garbage"] * 9
        events, events_parsed, raw_lines_seen = parse_birdcage_stream(lines)
        assert events_parsed == 1
        assert raw_lines_seen == 10
        err, cov = classify_parse_quality(events_parsed, raw_lines_seen)
        assert err is not None
        assert "1/10" in err
        assert cov == SandboxCoverage.PARSER_PARTIAL_DRIFT

    def test_healthy_ten_of_ten(self) -> None:
        lines = [_valid_line() for _ in range(10)]
        events, events_parsed, raw_lines_seen = parse_birdcage_stream(lines)
        assert events_parsed == 10
        assert raw_lines_seen == 10
        err, cov = classify_parse_quality(events_parsed, raw_lines_seen)
        assert err is None
        assert cov is None


class TestRedactionSanity:
    def test_secret_value_in_target_is_redacted(self) -> None:
        secret = "AKIAFAKEKEY1234567890"
        line = json.dumps(
            {
                "kind": "exec",
                "ts_ms": 0,
                "pid": 1,
                "process": "npm",
                "target": f"npm install lodash AWS_SECRET_ACCESS_KEY={secret}",
            }
        )
        events, _, _ = parse_birdcage_stream([line], scrub_values=[secret])
        assert len(events) == 1
        assert secret not in events[0].target
        assert secret not in events[0].raw
