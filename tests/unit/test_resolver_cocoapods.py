"""Tests for CocoaPods resolver + Podfile.lock parsing + cocoapods prefilter signals.

Phase 3 of opensrc-integration-plan (§3.3). Covers:

* CDN shard calculation (T-COC-CDN-1 baseline): first 3 MD5 hex chars.
* ``_resolve_cocoapods`` happy path via respx-style mocked httpx client.
* 404 podspec -> HTTPStatusError bubbles out.
* git+tag source with GITHUB_TOKEN -> GitHub tarball fetch succeeds.
* git+tag source WITHOUT GITHUB_TOKEN + 403 -> ``SourceUnavailableError``
  and the CLI maps to NEEDS_HUMAN_REVIEW (T-COC-RATE-1).
* http+tar.gz direct download -> success.
* Podfile.lock parser (YAML fixture).
* Divergence detection: tarball with ``.gitattributes export-ignore`` and
  tarball missing advertised source paths (T-COC-DIV-1 / T-COC-DIV-2).
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile

import httpx
import pytest

from aigate.config import Config
from aigate.models import PackageInfo, PrefilterResult
from aigate.prefilter import check_cocoapods_risks, run_prefilter
from aigate.resolver import (
    COCOAPODS_CDN,
    GITHUB_API,
    SourceUnavailableError,
    _cocoapods_shard,
    _derive_github_repo,
    _download_cocoapods_source,
    _resolve_cocoapods,
    download_source,
)

# ---------------------------------------------------------------------------
# Async client fakes — mirror the pattern already used in test_resolver_crates
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(
        self,
        *,
        json_data=None,
        content: bytes = b"",
        status: int = 200,
    ):
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
    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses
        self.calls: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url: str, **kw):
        self.calls.append((url, kw))
        if url not in self._responses:
            raise AssertionError(f"Unexpected URL requested: {url}")
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


# ---------------------------------------------------------------------------
# Shard + helper utilities
# ---------------------------------------------------------------------------


class TestCocoapodsShard:
    def test_shard_matches_md5_prefix(self):
        """T-COC-CDN-1 baseline: first 3 MD5 hex chars of the pod name."""
        digest = hashlib.md5(b"AFNetworking").hexdigest()  # noqa: S324 — shard key
        expected = f"{digest[0]}/{digest[1]}/{digest[2]}"
        assert _cocoapods_shard("AFNetworking") == expected

    def test_shard_is_stable_for_same_input(self):
        assert _cocoapods_shard("Alamofire") == _cocoapods_shard("Alamofire")

    def test_shard_different_for_different_pods(self):
        assert _cocoapods_shard("AFNetworking") != _cocoapods_shard("Alamofire")


class TestDeriveGithubRepo:
    def test_https_github(self):
        assert _derive_github_repo("https://github.com/AFNetworking/AFNetworking.git") == (
            "github.com",
            "AFNetworking",
            "AFNetworking",
        )

    def test_ssh_github(self):
        assert _derive_github_repo("git@github.com:a/b.git") == ("github.com", "a", "b")

    def test_git_plus_https_prefix(self):
        assert _derive_github_repo("git+https://github.com/a/b") == ("github.com", "a", "b")

    def test_unknown_host_returns_none(self):
        assert _derive_github_repo("https://git.example.com/a/b.git") is None

    def test_empty_returns_none(self):
        assert _derive_github_repo("") is None


# ---------------------------------------------------------------------------
# _resolve_cocoapods
# ---------------------------------------------------------------------------


class TestResolveCocoapods:
    @pytest.mark.asyncio
    async def test_resolve_happy_path_git_source(self, monkeypatch):
        shard = _cocoapods_shard("AFNetworking")
        podspec_url = f"{COCOAPODS_CDN}/{shard}/AFNetworking/4.0.1/AFNetworking.podspec.json"
        responses = {
            podspec_url: _FakeResponse(
                json_data={
                    "name": "AFNetworking",
                    "version": "4.0.1",
                    "summary": "Networking framework",
                    "homepage": "https://github.com/AFNetworking/AFNetworking",
                    "authors": {"Mattt": "mattt@example.com"},
                    "source": {
                        "git": "https://github.com/AFNetworking/AFNetworking.git",
                        "tag": "4.0.1",
                    },
                },
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = await _resolve_cocoapods("AFNetworking", "4.0.1")
        assert pkg.name == "AFNetworking"
        assert pkg.version == "4.0.1"
        assert pkg.ecosystem == "cocoapods"
        assert pkg.description == "Networking framework"
        assert pkg.repository == "https://github.com/AFNetworking/AFNetworking.git"
        assert "Mattt" in pkg.author
        # source dict preserved for the downloader to use downstream
        assert pkg.metadata["source"]["tag"] == "4.0.1"

    @pytest.mark.asyncio
    async def test_resolve_404_raises(self, monkeypatch):
        shard = _cocoapods_shard("DoesNotExist")
        url = f"{COCOAPODS_CDN}/{shard}/DoesNotExist/9.9.9/DoesNotExist.podspec.json"
        responses = {url: _FakeResponse(status=404)}
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        with pytest.raises(httpx.HTTPStatusError):
            await _resolve_cocoapods("DoesNotExist", "9.9.9")

    @pytest.mark.asyncio
    async def test_resolve_without_version_raises(self):
        with pytest.raises(ValueError, match="explicit version"):
            await _resolve_cocoapods("AFNetworking", None)


# ---------------------------------------------------------------------------
# _download_cocoapods_source — http path
# ---------------------------------------------------------------------------


class TestDownloadCocoapodsHttp:
    @pytest.mark.asyncio
    async def test_http_tar_gz_direct_download(self, monkeypatch):
        archive = _make_tarball(
            {
                "Foo-1.0.0/Foo.podspec": 'Pod::Spec.new { |s| s.name = "Foo" }\n',
                "Foo-1.0.0/Classes/Foo.swift": "public func greet() {}\n",
            }
        )
        pkg = PackageInfo(
            name="Foo",
            version="1.0.0",
            ecosystem="cocoapods",
            metadata={
                "source": {"http": "https://example.com/Foo-1.0.0.tar.gz", "type": "tgz"},
                "podspec": {},
            },
        )
        responses = {
            "https://example.com/Foo-1.0.0.tar.gz": _FakeResponse(content=archive),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        files = await _download_cocoapods_source(pkg)
        assert "Foo-1.0.0/Classes/Foo.swift" in files

    @pytest.mark.asyncio
    async def test_download_source_dispatches_cocoapods(self, monkeypatch):
        archive = _make_tarball({"Foo-1.0/README.md": "# hi"})
        pkg = PackageInfo(
            name="Foo",
            version="1.0",
            ecosystem="cocoapods",
            metadata={
                "source": {"http": "https://example.com/Foo-1.0.tar.gz"},
                "podspec": {},
            },
        )
        responses = {
            "https://example.com/Foo-1.0.tar.gz": _FakeResponse(content=archive),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        files = await download_source(pkg)
        assert any("README.md" in f for f in files)


# ---------------------------------------------------------------------------
# _download_cocoapods_source — git+tag path (GitHub tarball detour)
# ---------------------------------------------------------------------------


class TestDownloadCocoapodsGit:
    @pytest.mark.asyncio
    async def test_git_tag_with_token_succeeds(self, monkeypatch):
        """git+tag + GITHUB_TOKEN -> fetch GitHub tarball, extract sources."""
        archive = _make_tarball(
            {
                "AFNetworking-AFNetworking-abc123/Classes/AFNetworking.swift": "// ok\n",
                "AFNetworking-AFNetworking-abc123/README.md": "# AFN\n",
            }
        )
        tarball_url = f"{GITHUB_API}/repos/AFNetworking/AFNetworking/tarball/4.0.1"
        responses = {tarball_url: _FakeResponse(content=archive)}

        captured: dict = {}

        class _CapturingClient(_FakeAsyncClient):
            async def get(self, url, **kw):
                captured["url"] = url
                captured["headers"] = kw.get("headers") or {}
                return await super().get(url, **kw)

        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _CapturingClient(responses),
        )

        pkg = PackageInfo(
            name="AFNetworking",
            version="4.0.1",
            ecosystem="cocoapods",
            metadata={
                "source": {
                    "git": "https://github.com/AFNetworking/AFNetworking.git",
                    "tag": "4.0.1",
                },
                "podspec": {"name": "AFNetworking"},
            },
        )
        files = await _download_cocoapods_source(pkg, github_token="ghp_test_token")
        assert any("AFNetworking.swift" in f for f in files)
        # Authorization header present
        assert captured["headers"].get("Authorization") == "Bearer ghp_test_token"

    @pytest.mark.asyncio
    async def test_git_tag_without_token_403_raises_source_unavailable(self, monkeypatch):
        """T-COC-RATE-1: unauth 403 -> SourceUnavailableError; caller maps to NEEDS_REVIEW."""
        tarball_url = f"{GITHUB_API}/repos/a/b/tarball/1.0"
        responses = {tarball_url: _FakeResponse(status=403)}
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        pkg = PackageInfo(
            name="b",
            version="1.0",
            ecosystem="cocoapods",
            metadata={
                "source": {"git": "https://github.com/a/b.git", "tag": "1.0"},
                "podspec": {},
            },
        )
        with pytest.raises(SourceUnavailableError):
            await _download_cocoapods_source(pkg, github_token=None)

    @pytest.mark.asyncio
    async def test_git_tag_without_token_429_raises_source_unavailable(self, monkeypatch):
        tarball_url = f"{GITHUB_API}/repos/a/b/tarball/1.0"
        responses = {tarball_url: _FakeResponse(status=429)}
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        pkg = PackageInfo(
            name="b",
            version="1.0",
            ecosystem="cocoapods",
            metadata={
                "source": {"git": "https://github.com/a/b.git", "tag": "1.0"},
                "podspec": {},
            },
        )
        with pytest.raises(SourceUnavailableError):
            await _download_cocoapods_source(pkg, github_token=None)

    @pytest.mark.asyncio
    async def test_unsupported_host_raises(self, monkeypatch):
        pkg = PackageInfo(
            name="x",
            version="1.0",
            ecosystem="cocoapods",
            metadata={
                "source": {"git": "https://self-hosted.example.com/a/b.git", "tag": "1.0"},
                "podspec": {},
            },
        )
        with pytest.raises(SourceUnavailableError):
            await _download_cocoapods_source(pkg)

    @pytest.mark.asyncio
    async def test_no_git_or_http_raises(self, monkeypatch):
        pkg = PackageInfo(
            name="x",
            version="1.0",
            ecosystem="cocoapods",
            metadata={"source": {}, "podspec": {}},
        )
        with pytest.raises(SourceUnavailableError):
            await _download_cocoapods_source(pkg)


# ---------------------------------------------------------------------------
# Divergence detection (T-COC-DIV-1 / T-COC-DIV-2)
# ---------------------------------------------------------------------------


class TestDivergenceDetection:
    @pytest.mark.asyncio
    async def test_div_1_missing_advertised_paths_signals_divergence(self, monkeypatch):
        """T-COC-DIV-1: podspec advertises Classes/**, tarball missing Classes/."""
        # Tarball has only a README — podspec source_files claims "Classes/**/*.swift"
        archive = _make_tarball(
            {
                "owner-repo-abc/README.md": "# hi\n",
                # No Classes/ directory present.
            }
        )
        tarball_url = f"{GITHUB_API}/repos/owner/repo/tarball/1.0"
        responses = {tarball_url: _FakeResponse(content=archive)}
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = PackageInfo(
            name="Foo",
            version="1.0",
            ecosystem="cocoapods",
            metadata={
                "source": {
                    "git": "https://github.com/owner/repo.git",
                    "tag": "1.0",
                    "source_files": "Classes/**/*.swift",
                },
                "podspec": {},
            },
        )
        files = await _download_cocoapods_source(pkg, github_token="t")
        # Divergence sentinel file should be present
        assert "__aigate__/cocoapods-divergence.txt" in files
        assert "Classes" in files["__aigate__/cocoapods-divergence.txt"]

    @pytest.mark.asyncio
    async def test_div_2_gitattributes_export_ignore_suppresses_divergence(self, monkeypatch):
        """T-COC-DIV-2 control: .gitattributes export-ignore explains divergence -> no signal."""
        archive = _make_tarball(
            {
                "owner-repo-abc/README.md": "# hi\n",
                "owner-repo-abc/.gitattributes": "tests/ export-ignore\n",
            }
        )
        tarball_url = f"{GITHUB_API}/repos/owner/repo/tarball/1.0"
        responses = {tarball_url: _FakeResponse(content=archive)}
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = PackageInfo(
            name="Foo",
            version="1.0",
            ecosystem="cocoapods",
            metadata={
                "source": {
                    "git": "https://github.com/owner/repo.git",
                    "tag": "1.0",
                    "source_files": "Classes/**/*.swift",
                },
                "podspec": {},
            },
        )
        files = await _download_cocoapods_source(pkg, github_token="t")
        assert "__aigate__/cocoapods-divergence.txt" not in files


# ---------------------------------------------------------------------------
# Podfile.lock parsing
# ---------------------------------------------------------------------------


class TestPodfileLockParsing:
    def test_parse_simple_podfile(self, tmp_path):
        """Podfile.lock with PODS list -> (name, version) tuples."""
        lockfile = tmp_path / "Podfile.lock"
        lockfile.write_text(
            """\
PODS:
  - AFNetworking (4.0.1):
    - AFNetworking/NSURLSession (= 4.0.1)
    - AFNetworking/Reachability (= 4.0.1)
  - AFNetworking/NSURLSession (4.0.1):
    - AFNetworking/Reachability
    - AFNetworking/Security
  - Alamofire (5.6.0)

DEPENDENCIES:
  - AFNetworking
  - Alamofire (~> 5.6)

SPEC CHECKSUMS:
  AFNetworking: 7864c38297c79aaca1500c33288e429c1451ecde
  Alamofire: f12bff3b5ef06c75d16ad20c5de7d83ad80ca9f3

PODFILE CHECKSUM: abc123

COCOAPODS: 1.12.1
"""
        )
        from aigate.cli import _parse_lockfile

        packages = _parse_lockfile(str(lockfile))
        # AFNetworking dedupes across its subspecs; Alamofire stands alone.
        pkg_dict = {n: v for n, v in packages}
        assert pkg_dict == {"AFNetworking": "4.0.1", "Alamofire": "5.6.0"}

    def test_parse_skips_external_sources(self, tmp_path):
        """Pods declared under EXTERNAL SOURCES aren't resolved from CDN."""
        lockfile = tmp_path / "Podfile.lock"
        lockfile.write_text(
            """\
PODS:
  - LocalPod (0.1.0)
  - AFNetworking (4.0.1)

EXTERNAL SOURCES:
  LocalPod:
    :path: "../LocalPod"

SPEC CHECKSUMS:
  AFNetworking: abc
  LocalPod: def

COCOAPODS: 1.12.1
"""
        )
        from aigate.cli import _parse_lockfile

        packages = _parse_lockfile(str(lockfile))
        names = {n for n, _ in packages}
        assert "AFNetworking" in names
        assert "LocalPod" not in names

    def test_infer_ecosystem_podfile_lock(self):
        from aigate.cli import _infer_ecosystem

        assert _infer_ecosystem("Podfile.lock") == "cocoapods"
        assert _infer_ecosystem("./ios/Podfile.lock") == "cocoapods"


# ---------------------------------------------------------------------------
# Prefilter: cocoapods-specific signals
# ---------------------------------------------------------------------------


class TestCocoapodsPrefilterSignals:
    def test_divergence_sentinel_emits_high(self):
        signals = check_cocoapods_risks(
            {
                "__aigate__/cocoapods-divergence.txt": (
                    "podspec-vs-tarball path divergence: missing ['Classes']"
                ),
            }
        )
        assert any("divergence" in s and "HIGH" in s for s in signals)

    def test_gitattributes_export_ignore_emits_high(self):
        signals = check_cocoapods_risks(
            {
                "root-abc/.gitattributes": "tests/ export-ignore\n",
            }
        )
        assert any("export-ignore" in s and "HIGH" in s for s in signals)

    def test_clean_pod_no_signals(self):
        signals = check_cocoapods_risks(
            {
                "Foo-1.0/README.md": "# Foo",
                "Foo-1.0/Classes/Foo.swift": "public func greet() {}\n",
            }
        )
        assert signals == []

    def test_run_prefilter_cocoapods_integration(self):
        """Full run_prefilter surfaces cocoapods signals via ecosystem dispatch."""
        pkg = PackageInfo(name="Foo", version="1.0", ecosystem="cocoapods")
        source = {
            "__aigate__/cocoapods-divergence.txt": (
                "podspec-vs-tarball path divergence: missing ['Classes']"
            ),
        }
        result = run_prefilter(pkg, Config.default(), source)
        assert any("divergence" in s for s in result.risk_signals)


# ---------------------------------------------------------------------------
# source_unavailable field + consensus interaction
# ---------------------------------------------------------------------------


class TestSourceUnavailableField:
    def test_default_false(self):
        pr = PrefilterResult(passed=True, reason="ok")
        assert pr.source_unavailable is False

    def test_explicit_set(self):
        pr = PrefilterResult(passed=False, reason="bytes gone", source_unavailable=True)
        assert pr.source_unavailable is True


# ---------------------------------------------------------------------------
# End-to-end through download_source for regression safety
# ---------------------------------------------------------------------------


class TestDownloadSourceCocoapodsIntegration:
    @pytest.mark.asyncio
    async def test_download_source_cocoapods_threads_github_token(self, monkeypatch):
        """download_source threads github_token through to the resolver."""
        archive = _make_tarball({"x-abc/Classes/x.swift": "// ok\n"})
        tarball_url = f"{GITHUB_API}/repos/a/x/tarball/1.0"
        responses = {tarball_url: _FakeResponse(content=archive)}

        captured_headers: list[dict] = []

        class _CaptureClient(_FakeAsyncClient):
            async def get(self, url, **kw):
                captured_headers.append(kw.get("headers") or {})
                return await super().get(url, **kw)

        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _CaptureClient(responses),
        )

        pkg = PackageInfo(
            name="x",
            version="1.0",
            ecosystem="cocoapods",
            metadata={
                "source": {"git": "https://github.com/a/x.git", "tag": "1.0"},
                "podspec": {},
            },
        )
        files = await download_source(pkg, github_token="secret-token")
        assert files
        assert captured_headers[0].get("Authorization") == "Bearer secret-token"


# ---------------------------------------------------------------------------
# Raw JSON sanity checks (non-network — structure only)
# ---------------------------------------------------------------------------


def test_json_dumps_podspec_metadata_is_round_trippable():
    """The podspec payload is JSON-serialisable; sanity-check for cache flows."""
    payload = {
        "name": "AFNetworking",
        "version": "4.0.1",
        "source": {"git": "https://github.com/AFNetworking/AFNetworking.git", "tag": "4.0.1"},
    }
    assert json.loads(json.dumps(payload)) == payload


# ---------------------------------------------------------------------------
# US-004 / Reviewer CRITICAL-3: tar-bomb DoS guards on _list_tarball_members
# ---------------------------------------------------------------------------


def _build_tarball(entries: list[tuple[str, bytes]]) -> bytes:
    """Build an in-memory tar.gz with the given (name, content) members."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_list_tarball_members_caps_member_count(caplog):
    """Reviewer CRITICAL-3: a tarball with > _MAX_MANIFEST_MEMBERS files
    must NOT be enumerated past the cap. We construct cap+500 small files;
    expect manifest length capped and a warning logged."""
    import logging

    from aigate.resolver import _MAX_MANIFEST_MEMBERS, _list_tarball_members

    entries = [(f"pkg-1.0/file_{i:05d}.txt", b"hi") for i in range(_MAX_MANIFEST_MEMBERS + 500)]
    blob = _build_tarball(entries)

    with caplog.at_level(logging.WARNING):
        manifest = _list_tarball_members(blob, "x.tar.gz")

    assert len(manifest) <= _MAX_MANIFEST_MEMBERS, (
        f"manifest size {len(manifest)} should not exceed cap {_MAX_MANIFEST_MEMBERS}"
    )
    assert any("member cap" in rec.message for rec in caplog.records), (
        "expected a tar-bomb member-cap warning"
    )


def test_list_tarball_members_caps_cumulative_bytes(caplog):
    """Reviewer CRITICAL-3: cumulative read bytes past _MAX_MANIFEST_BYTES
    must short-circuit. We pack enough 64KB members to exceed the cap."""
    import logging

    from aigate.resolver import _MAX_MANIFEST_BYTES, _list_tarball_members

    chunk = b"a" * (64 * 1024)  # 64KB — equals the per-member read cap
    members = (_MAX_MANIFEST_BYTES // (64 * 1024)) + 50
    entries = [(f"pkg-1.0/big_{i:04d}.bin", chunk) for i in range(members)]
    blob = _build_tarball(entries)

    with caplog.at_level(logging.WARNING):
        manifest = _list_tarball_members(blob, "x.tar.gz")

    total = sum(len(v) for v in manifest.values())
    assert total <= _MAX_MANIFEST_BYTES + 64 * 1024, (
        f"cumulative bytes {total} broke the {_MAX_MANIFEST_BYTES} cap"
    )
    assert any("cumulative cap" in rec.message for rec in caplog.records), (
        "expected a tar-bomb cumulative-byte-cap warning"
    )


def test_list_tarball_members_normal_tarball_unaffected():
    """The cap must not break legitimate small tarballs."""
    from aigate.resolver import _list_tarball_members

    entries = [
        ("pkg-1.0/Sources/Header.h", b"#pragma once\n"),
        ("pkg-1.0/Sources/Impl.m", b"@implementation X\n@end\n"),
        ("pkg-1.0/.gitattributes", b"*.swift export-ignore\n"),
    ]
    blob = _build_tarball(entries)
    manifest = _list_tarball_members(blob, "x.tar.gz")
    assert "pkg-1.0/Sources/Header.h" in manifest
    assert "pkg-1.0/.gitattributes" in manifest
    assert manifest["pkg-1.0/.gitattributes"] == b"*.swift export-ignore\n"
