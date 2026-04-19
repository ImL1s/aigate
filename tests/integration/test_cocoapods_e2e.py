"""Integration test — CocoaPods end-to-end through the CLI.

Exercises Phase 3 (opensrc-integration-plan §3.3):

* Clean http+tar.gz pod -> ``aigate check`` exits SAFE (0) via --skip-ai.
* Git-tag pod WITHOUT GITHUB_TOKEN + 403 -> NEEDS_HUMAN_REVIEW (exit 1),
  ``PrefilterResult.source_unavailable=True``, and ``opensrc_cache.should_emit``
  refuses to publish bytes that were never inspected.

No network: we monkey-patch ``httpx.AsyncClient`` to serve canned responses,
mirroring the existing resolver unit-test pattern.
"""

from __future__ import annotations

import io
import json
import tarfile

import httpx
from click.testing import CliRunner

from aigate.cli import main
from aigate.config import Config, EmitOpensrcConfig
from aigate.models import (
    AnalysisReport,
    ConsensusResult,
    PackageInfo,
    PrefilterResult,
    RiskLevel,
    Verdict,
)
from aigate.opensrc_cache import should_emit
from aigate.resolver import COCOAPODS_CDN, GITHUB_API, _cocoapods_shard


class _FakeResponse:
    def __init__(self, *, json_data=None, content: bytes = b"", status: int = 200):
        self._json = json_data
        self.content = content
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("GET", "https://cdn.cocoapods.org"),
                response=httpx.Response(self.status_code),
            )

    def json(self):
        return self._json


class _FakeAsyncClient:
    def __init__(self, responses):
        self._responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def get(self, url: str, **_):
        if url not in self._responses:
            raise AssertionError(f"Unexpected URL: {url}")
        return self._responses[url]


def _make_tarball(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _install_fake_client(monkeypatch, responses):
    monkeypatch.setattr(
        "aigate.resolver.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(responses),
    )


def test_e2e_clean_http_tar_pod_is_safe(monkeypatch):
    """http+tar.gz pod without risk signals -> SAFE (exit 0) via --skip-ai."""
    cfg = Config.default()
    monkeypatch.setattr("aigate.cli.Config.load", lambda: cfg)

    name = "Foo"
    version = "1.0.0"
    shard = _cocoapods_shard(name)
    podspec_url = f"{COCOAPODS_CDN}/{shard}/{name}/{version}/{name}.podspec.json"

    archive = _make_tarball(
        {
            "Foo-1.0.0/README.md": "# Foo",
            "Foo-1.0.0/Classes/Foo.swift": "public func greet() {}\n",
        }
    )
    responses = {
        podspec_url: _FakeResponse(
            json_data={
                "name": name,
                "version": version,
                "summary": "Harmless pod",
                "authors": {"Test Author": "test@example.com"},
                "homepage": "https://example.com/Foo",
                "source": {
                    "http": "https://example.com/Foo-1.0.0.tar.gz",
                    "type": "tgz",
                },
            }
        ),
        "https://example.com/Foo-1.0.0.tar.gz": _FakeResponse(content=archive),
    }
    _install_fake_client(monkeypatch, responses)

    result = CliRunner().invoke(
        main, ["check", name, "-v", version, "-e", "cocoapods", "--skip-ai", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = _parse_json_from_mixed_output(result.output)
    assert payload["decision"] == "safe"
    assert payload["package"]["ecosystem"] == "cocoapods"
    assert payload["package"]["name"] == name
    # source_unavailable must be False (bytes were inspected successfully).
    assert payload["prefilter"]["source_unavailable"] is False


def _parse_json_from_mixed_output(output: str) -> dict:
    """Pull the JSON payload out of CLI output that may have warning prefixes."""
    start = output.find("{")
    if start == -1:
        raise AssertionError(f"No JSON payload in output: {output!r}")
    return json.loads(output[start:])


def test_e2e_git_tag_pod_without_token_needs_human_review(monkeypatch):
    """T-COC-RATE-1 (integration): git+tag pod + no GITHUB_TOKEN + 403 ->
    NEEDS_HUMAN_REVIEW (exit 1), never SAFE. Opensrc-emit refuses to publish."""
    # Ensure no ambient GITHUB_TOKEN leaks into the test.
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    cfg = Config.default()
    # github_token explicitly unset; CLI -> config.github_token is None.
    cfg.github_token = None
    monkeypatch.setattr("aigate.cli.Config.load", lambda: cfg)

    name = "AFNetworking"
    version = "4.0.1"
    shard = _cocoapods_shard(name)
    podspec_url = f"{COCOAPODS_CDN}/{shard}/{name}/{version}/{name}.podspec.json"

    responses = {
        podspec_url: _FakeResponse(
            json_data={
                "name": name,
                "version": version,
                "summary": "Networking",
                "authors": {"Mattt": "mattt@example.com"},
                "homepage": "https://github.com/AFNetworking/AFNetworking",
                "source": {
                    "git": "https://github.com/AFNetworking/AFNetworking.git",
                    "tag": version,
                },
            }
        ),
        # GitHub tarball endpoint -> 403 rate limit without token.
        f"{GITHUB_API}/repos/AFNetworking/AFNetworking/tarball/{version}": _FakeResponse(
            status=403
        ),
    }
    _install_fake_client(monkeypatch, responses)

    result = CliRunner().invoke(
        main, ["check", name, "-v", version, "-e", "cocoapods", "--skip-ai", "--json"]
    )
    # NEEDS_HUMAN_REVIEW -> exit code 1 (never 0 = SAFE).
    assert result.exit_code == 1, result.output
    payload = _parse_json_from_mixed_output(result.output)
    assert payload["decision"] != "safe"
    prefilter_payload = payload["prefilter"]
    assert prefilter_payload["source_unavailable"] is True
    assert any("source_unavailable" in s for s in prefilter_payload["risk_signals"])

    # opensrc_cache.should_emit must refuse: uninspected bytes never get
    # published downstream, even if the user opts in.
    report = AnalysisReport(
        package=PackageInfo(name=name, version=version, ecosystem="cocoapods"),
        prefilter=PrefilterResult(
            passed=False,
            reason="Source bytes unavailable; manual review required",
            risk_signals=["source_unavailable(HIGH): HTTP 403"],
            risk_level=RiskLevel.MEDIUM,
            source_unavailable=True,
        ),
        consensus=ConsensusResult(final_verdict=Verdict.NEEDS_HUMAN_REVIEW, confidence=0.0),
    )
    emit_cfg = Config.default()
    emit_cfg.emit_opensrc = EmitOpensrcConfig(enabled=True)
    ok, reason = should_emit(report, emit_cfg, flag_override=True)
    assert ok is False
    assert reason == "source_unavailable"
