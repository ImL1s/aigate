"""Tests for JSR (jsr.io) resolver — Phase 4 opensrc-integration-plan §3.4.

Coverage:

* ``@scope/pkg`` -> ``@jsr/scope__pkg`` rewrite (unit).
* ``_resolve_jsr`` happy path via fake httpx client against ``npm.jsr.io``.
* ``_download_jsr_source`` reuses the npm-compatible tarball path.
* ``download_source`` dispatches ``ecosystem=jsr`` to the JSR path.
* CLI: ``-e jsr`` is accepted by the click.Choice (integration-ish via
  SUPPORTED_ECOSYSTEMS).
"""

from __future__ import annotations

import io
import tarfile

import httpx
import pytest

from aigate.models import PackageInfo
from aigate.resolver import (
    JSR_NPM_API,
    _download_jsr_source,
    _jsr_to_npm_name,
    _resolve_jsr,
    download_source,
    resolve_package,
)

# ---------------------------------------------------------------------------
# Async client fakes — mirror the pattern used in test_resolver_crates.py
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, *, json_data=None, content: bytes = b"", status: int = 200):
        self._json = json_data
        self.content = content
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("GET", "https://npm.jsr.io"),
                response=httpx.Response(self.status_code),
            )

    def json(self):
        return self._json


class _FakeAsyncClient:
    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url: str, **_):
        if url not in self._responses:
            raise AssertionError(f"Unexpected URL requested: {url}")
        return self._responses[url]


def _make_npm_tarball(files: dict[str, str]) -> bytes:
    """Produce an npm-style .tgz (gzipped tar) in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Name rewrite
# ---------------------------------------------------------------------------


class TestJsrNameRewrite:
    def test_scoped_name_rewrites_to_double_underscore(self):
        """`@scope/pkg` maps to `@jsr/scope__pkg` per JSR npm-compat docs."""
        assert _jsr_to_npm_name("@std/async") == "@jsr/std__async"
        assert _jsr_to_npm_name("@luca/flag") == "@jsr/luca__flag"

    def test_scoped_name_with_hyphens_preserved(self):
        """Hyphens in scope / pkg survive the rewrite intact."""
        assert _jsr_to_npm_name("@my-org/some-pkg") == "@jsr/my-org__some-pkg"

    def test_already_rewritten_name_passes_through(self):
        """Idempotent: re-applying the rewrite does not double-wrap."""
        assert _jsr_to_npm_name("@jsr/std__async") == "@jsr/std__async"

    def test_non_scoped_name_returned_as_is(self):
        """Non-scoped names (rejected by JSR policy) pass through unchanged."""
        assert _jsr_to_npm_name("bare-name") == "bare-name"


# ---------------------------------------------------------------------------
# _resolve_jsr
# ---------------------------------------------------------------------------


class TestResolveJsr:
    @pytest.mark.asyncio
    async def test_resolve_jsr_happy_path(self, monkeypatch):
        """`@std/async` hits npm.jsr.io with the rewritten name and parses JSON."""
        responses = {
            f"{JSR_NPM_API}/@jsr/std__async": _FakeResponse(
                json_data={
                    "name": "@jsr/std__async",
                    "dist-tags": {"latest": "1.0.0"},
                    "versions": {
                        "1.0.0": {
                            "name": "@jsr/std__async",
                            "version": "1.0.0",
                            "description": "Standard async utilities",
                            "homepage": "https://jsr.io/@std/async",
                            "repository": {
                                "type": "git",
                                "url": "https://github.com/denoland/std",
                            },
                            "dist": {
                                "tarball": ("https://npm.jsr.io/~/11/@jsr/std__async/1.0.0.tgz"),
                            },
                            "dependencies": {},
                        }
                    },
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = await _resolve_jsr("@std/async", None)

        # Preserve original JSR name in PackageInfo — UX + cache keys
        assert pkg.name == "@std/async"
        assert pkg.ecosystem == "jsr"
        assert pkg.version == "1.0.0"
        assert pkg.description == "Standard async utilities"
        assert pkg.repository == "https://github.com/denoland/std"
        # Tracks the rewritten npm name in metadata for downstream debugging
        assert pkg.metadata.get("npm_name") == "@jsr/std__async"

    @pytest.mark.asyncio
    async def test_resolve_jsr_specific_version(self, monkeypatch):
        """Explicit version selects the right ``versions[v]`` entry."""
        responses = {
            f"{JSR_NPM_API}/@jsr/luca__flag": _FakeResponse(
                json_data={
                    "dist-tags": {"latest": "2.0.0"},
                    "versions": {
                        "1.0.0": {"version": "1.0.0", "dist": {"tarball": "x"}},
                        "2.0.0": {"version": "2.0.0", "dist": {"tarball": "y"}},
                    },
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        pkg = await _resolve_jsr("@luca/flag", "1.0.0")
        assert pkg.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_resolve_jsr_404_raises(self, monkeypatch):
        """Unknown JSR package → HTTPStatusError bubbles out of resolve_package."""
        responses = {
            f"{JSR_NPM_API}/@jsr/nonexistent__pkg": _FakeResponse(status=404),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        with pytest.raises(httpx.HTTPStatusError):
            await resolve_package("@nonexistent/pkg", None, "jsr")


# ---------------------------------------------------------------------------
# _download_jsr_source
# ---------------------------------------------------------------------------


class TestDownloadJsrSource:
    @pytest.mark.asyncio
    async def test_download_jsr_fetches_tarball_and_extracts(self, monkeypatch):
        """Tarball extraction reuses the npm code path via ``_extract_archive``."""
        archive = _make_npm_tarball(
            {
                "package/package.json": '{"name":"@jsr/std__async","version":"1.0.0"}',
                "package/mod.ts": "export async function foo() {}\n",
            }
        )
        tarball_url = "https://npm.jsr.io/~/11/@jsr/std__async/1.0.0.tgz"
        responses = {
            f"{JSR_NPM_API}/@jsr/std__async/1.0.0": _FakeResponse(
                json_data={
                    "name": "@jsr/std__async",
                    "version": "1.0.0",
                    "dist": {"tarball": tarball_url},
                }
            ),
            tarball_url: _FakeResponse(content=archive),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        package = PackageInfo(name="@std/async", version="1.0.0", ecosystem="jsr")
        files = await _download_jsr_source(package)

        assert "package/package.json" in files
        assert "package/mod.ts" in files
        assert "export async function foo" in files["package/mod.ts"]

    @pytest.mark.asyncio
    async def test_download_source_dispatches_jsr(self, monkeypatch):
        """``download_source`` routes ``ecosystem=jsr`` to the JSR path."""
        archive = _make_npm_tarball({"package/mod.ts": "export {};\n"})
        tarball_url = "https://npm.jsr.io/~/11/@jsr/luca__flag/2.0.0.tgz"
        responses = {
            f"{JSR_NPM_API}/@jsr/luca__flag/2.0.0": _FakeResponse(
                json_data={"dist": {"tarball": tarball_url}}
            ),
            tarball_url: _FakeResponse(content=archive),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        package = PackageInfo(name="@luca/flag", version="2.0.0", ecosystem="jsr")
        files = await download_source(package)
        assert "package/mod.ts" in files


# ---------------------------------------------------------------------------
# CLI surface — click.Choice accepts "jsr"
# ---------------------------------------------------------------------------


class TestCliJsrSurface:
    def test_jsr_in_supported_ecosystems(self):
        """``jsr`` is enumerated in the cli SUPPORTED_ECOSYSTEMS tuple."""
        from aigate.cli import SUPPORTED_ECOSYSTEMS

        assert "jsr" in SUPPORTED_ECOSYSTEMS

    def test_config_validator_accepts_jsr(self):
        """``config_validator.VALID_ECOSYSTEMS`` accepts jsr (no warning)."""
        from aigate.config_validator import VALID_ECOSYSTEMS

        assert "jsr" in VALID_ECOSYSTEMS
