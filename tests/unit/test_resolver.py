"""Tests for resolver safety checks."""

from __future__ import annotations

import pytest

from aigate.models import PackageInfo
from aigate.resolver import _extract_archive, _is_path_safe, download_source, resolve_package


class TestPathSafe:
    def test_normal_path(self):
        assert _is_path_safe("package-1.0/src/main.py") is True

    def test_path_traversal_dotdot(self):
        assert _is_path_safe("../../etc/passwd") is False

    def test_path_traversal_mid(self):
        assert _is_path_safe("package-1.0/../../../secret") is False

    def test_absolute_path(self):
        assert _is_path_safe("/etc/passwd") is False

    def test_empty_path(self):
        assert _is_path_safe("") is False

    def test_single_dot(self):
        # "." is fine (current dir reference in archives)
        assert _is_path_safe("./src/main.py") is True

    def test_dotdot_in_name(self):
        # "some..file" is fine, ".." as a directory component is not
        assert _is_path_safe("package/some..file.py") is True


class TestExtractArchive:
    def test_empty_content(self):
        result = _extract_archive(b"", "test.tar.gz")
        assert result == {}

    def test_unsupported_format(self):
        result = _extract_archive(b"data", "test.rpm")
        assert result == {}


class _FakeResponse:
    def __init__(self, *, json_data=None, content: bytes = b""):
        self._json_data = json_data
        self.content = content

    def raise_for_status(self):
        return None

    def json(self):
        return self._json_data


class _FakeAsyncClient:
    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url: str):
        return self._responses[url]


@pytest.mark.asyncio
async def test_resolve_pub_package(monkeypatch):
    responses = {
        "https://pub.dev/api/packages/http": _FakeResponse(
            json_data={
                "name": "http",
                "latest": {
                    "version": "1.2.1",
                    "pubspec": {
                        "name": "http",
                        "version": "1.2.1",
                        "description": "HTTP client",
                        "repository": "https://github.com/dart-lang/http/tree/master/pkgs/http",
                        "dependencies": {"async": "^2.5.0"},
                    },
                    "archive_url": "https://pub.dev/api/archives/http-1.2.1.tar.gz",
                    "published": "2024-02-15T23:25:27.572746Z",
                },
            }
        )
    }
    monkeypatch.setattr(
        "aigate.resolver.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(responses),
    )

    package = await resolve_package("http", None, "pub")

    assert package.ecosystem == "pub"
    assert package.version == "1.2.1"
    assert package.repository == "https://github.com/dart-lang/http/tree/master/pkgs/http"


@pytest.mark.asyncio
async def test_download_pub_source(monkeypatch):
    package = PackageInfo(name="http", version="1.2.1", ecosystem="pub")
    responses = {
        "https://pub.dev/api/packages/http/versions/1.2.1": _FakeResponse(
            json_data={
                "archive_url": "https://pub.dev/api/archives/http-1.2.1.tar.gz",
            }
        ),
        "https://pub.dev/api/archives/http-1.2.1.tar.gz": _FakeResponse(content=b"archive-bytes"),
    }

    monkeypatch.setattr(
        "aigate.resolver.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(responses),
    )
    monkeypatch.setattr(
        "aigate.resolver._extract_archive",
        lambda content, filename: {"lib/http.dart": f"{filename}:{content.decode()}"},
    )

    files = await download_source(package)

    assert files == {
        "lib/http.dart": "https://pub.dev/api/archives/http-1.2.1.tar.gz:archive-bytes"
    }
