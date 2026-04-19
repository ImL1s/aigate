"""Tests for crates.io resolver + Cargo.lock parsing + crates prefilter signals.

Phase 2 opensrc-integration-plan coverage:

* ``_resolve_crates`` happy path (version + versionless).
* 404 handling for unknown crate.
* Yanked-version warning propagates via the stdlib logger.
* Source / description / repository extraction from the crates.io JSON.
* Cargo.lock fixture → ``_parse_lockfile`` returns only registry packages.
* Archive ≤ 200MB ends up in ``download_source`` extracts.
* Archive > 200MB raises ``archive_oversized`` ValueError (upstream →
  NEEDS_HUMAN_REVIEW).
* ``build.rs`` presence → HIGH risk signal.
* ``proc-macro = true`` in ``Cargo.toml`` → HIGH risk signal.
"""

from __future__ import annotations

import io
import logging
import tarfile

import httpx
import pytest

from aigate.config import Config
from aigate.models import PackageInfo, RiskLevel
from aigate.prefilter import check_crates_risks, run_prefilter
from aigate.resolver import (
    CRATES_API,
    MAX_CRATES_ARCHIVE_SIZE,
    _download_crates_source,
    _resolve_crates,
    download_source,
    resolve_package,
)

# ---------------------------------------------------------------------------
# Async client fakes — mirror the pattern already used in test_resolver.py
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
                request=httpx.Request("GET", "https://crates.io"),
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


# ---------------------------------------------------------------------------
# Fixtures for archive bytes
# ---------------------------------------------------------------------------


def _make_crate_tarball(files: dict[str, str]) -> bytes:
    """Produce a .crate-compatible gzipped tarball in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# _resolve_crates
# ---------------------------------------------------------------------------


class TestResolveCrates:
    @pytest.mark.asyncio
    async def test_resolve_crates_happy_path_versionless(self, monkeypatch):
        """versionless lookup picks ``max_stable_version`` and extracts metadata."""
        responses = {
            f"{CRATES_API}/serde": _FakeResponse(
                json_data={
                    "crate": {
                        "name": "serde",
                        "max_stable_version": "1.0.200",
                        "max_version": "1.0.200",
                        "description": "Serialization framework",
                        "homepage": "https://serde.rs",
                        "repository": "https://github.com/serde-rs/serde",
                    },
                    "versions": [
                        {
                            "num": "1.0.200",
                            "yanked": False,
                            "authors": ["David Tolnay", "Erick Tryzelaar"],
                        },
                        {
                            "num": "1.0.199",
                            "yanked": False,
                            "authors": ["David Tolnay"],
                        },
                    ],
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = await _resolve_crates("serde", None)

        assert pkg.name == "serde"
        assert pkg.ecosystem == "crates"
        assert pkg.version == "1.0.200"
        assert pkg.description == "Serialization framework"
        assert pkg.homepage == "https://serde.rs"
        assert pkg.repository == "https://github.com/serde-rs/serde"
        assert "David Tolnay" in pkg.author
        # aigate never runs cargo build; has_install_scripts stays False —
        # build.rs / proc-macro risk is surfaced via prefilter instead.
        assert pkg.has_install_scripts is False

    @pytest.mark.asyncio
    async def test_resolve_crates_specific_version(self, monkeypatch):
        """version-specific endpoint returns a ``version`` object."""
        responses = {
            f"{CRATES_API}/serde/1.0.200": _FakeResponse(
                json_data={
                    "version": {
                        "num": "1.0.200",
                        "yanked": False,
                        "authors": ["David Tolnay"],
                        "description": "Serialization framework",
                        "repository": "https://github.com/serde-rs/serde",
                    }
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        pkg = await _resolve_crates("serde", "1.0.200")

        assert pkg.version == "1.0.200"
        assert pkg.repository == "https://github.com/serde-rs/serde"

    @pytest.mark.asyncio
    async def test_resolve_crates_404_raises(self, monkeypatch):
        """Unknown crate → HTTPStatusError bubbles up to the CLI."""
        responses = {
            f"{CRATES_API}/nonexistent_crate_xxx": _FakeResponse(status=404),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        with pytest.raises(httpx.HTTPStatusError):
            await resolve_package("nonexistent_crate_xxx", None, "crates")

    @pytest.mark.asyncio
    async def test_resolve_crates_yanked_warning(self, monkeypatch, caplog):
        """Yanked version logs a warning but still returns metadata."""
        responses = {
            f"{CRATES_API}/evil/9.9.9": _FakeResponse(
                json_data={
                    "version": {
                        "num": "9.9.9",
                        "yanked": True,
                        "authors": ["nobody"],
                    }
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        with caplog.at_level(logging.WARNING, logger="aigate.resolver"):
            pkg = await _resolve_crates("evil", "9.9.9")

        assert pkg.version == "9.9.9"
        assert any("yanked" in rec.message for rec in caplog.records)

    @pytest.mark.asyncio
    async def test_resolve_crates_metadata_defaults_when_fields_missing(self, monkeypatch):
        """Crate with bare-minimum JSON still produces a coherent PackageInfo."""
        responses = {
            f"{CRATES_API}/bare": _FakeResponse(
                json_data={
                    "crate": {"name": "bare", "max_stable_version": "0.1.0"},
                    "versions": [{"num": "0.1.0", "yanked": False}],
                }
            )
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        pkg = await _resolve_crates("bare", None)
        assert pkg.version == "0.1.0"
        assert pkg.description == ""
        assert pkg.repository == ""
        assert pkg.homepage == ""


# ---------------------------------------------------------------------------
# _download_crates_source
# ---------------------------------------------------------------------------


class TestDownloadCratesSource:
    @pytest.mark.asyncio
    async def test_download_crates_under_cap_extracts_files(self, monkeypatch):
        """≤200MB archive extracts Cargo.toml + src/*.rs normally."""
        archive = _make_crate_tarball(
            {
                "serde-1.0.200/Cargo.toml": '[package]\nname = "serde"\nversion = "1.0.200"\n',
                "serde-1.0.200/src/lib.rs": "pub fn hello() {}\n",
            }
        )
        package = PackageInfo(name="serde", version="1.0.200", ecosystem="crates")
        responses = {
            f"{CRATES_API}/serde/1.0.200/download": _FakeResponse(content=archive),
        }
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        files = await _download_crates_source(package)

        assert "serde-1.0.200/Cargo.toml" in files
        assert "serde-1.0.200/src/lib.rs" in files
        assert "pub fn hello()" in files["serde-1.0.200/src/lib.rs"]

    @pytest.mark.asyncio
    async def test_download_crates_oversized_raises(self, monkeypatch):
        """>200MB archive raises archive_oversized (Principle 2 / PRD §2.5 S3)."""
        # Build a tiny archive, then artificially shrink the size cap so we
        # exercise the cap logic without allocating 200MB.
        archive = _make_crate_tarball({"x-0.1.0/Cargo.toml": '[package]\nname = "x"\n'})
        package = PackageInfo(name="x", version="0.1.0", ecosystem="crates")
        responses = {f"{CRATES_API}/x/0.1.0/download": _FakeResponse(content=archive)}
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )

        with pytest.raises(ValueError, match="archive_oversized"):
            await _download_crates_source(package, max_archive_size=1)  # 1 byte cap

    @pytest.mark.asyncio
    async def test_download_crates_uses_default_200mb_cap_if_none(self, monkeypatch):
        """When max_archive_size is None → use MAX_CRATES_ARCHIVE_SIZE (200MB)."""
        assert MAX_CRATES_ARCHIVE_SIZE == 200 * 1024 * 1024
        # A tiny archive well under 200MB should succeed.
        archive = _make_crate_tarball({"tiny-1.0.0/Cargo.toml": '[package]\nname = "tiny"\n'})
        package = PackageInfo(name="tiny", version="1.0.0", ecosystem="crates")
        responses = {f"{CRATES_API}/tiny/1.0.0/download": _FakeResponse(content=archive)}
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        files = await _download_crates_source(package, max_archive_size=None)
        assert "tiny-1.0.0/Cargo.toml" in files

    @pytest.mark.asyncio
    async def test_download_source_dispatches_crates(self, monkeypatch):
        """``download_source`` honors ``ecosystem=crates`` and threads the cap."""
        archive = _make_crate_tarball({"pkg-1.0/Cargo.toml": '[package]\nname = "pkg"\n'})
        package = PackageInfo(name="pkg", version="1.0", ecosystem="crates")
        responses = {f"{CRATES_API}/pkg/1.0/download": _FakeResponse(content=archive)}
        monkeypatch.setattr(
            "aigate.resolver.httpx.AsyncClient",
            lambda **_: _FakeAsyncClient(responses),
        )
        files = await download_source(package, max_archive_size_crates=10 * 1024 * 1024)
        assert "pkg-1.0/Cargo.toml" in files


# ---------------------------------------------------------------------------
# Cargo.lock lockfile parsing
# ---------------------------------------------------------------------------


class TestCargoLockParsing:
    def test_cargo_lock_registry_entries_only(self, tmp_path):
        """Only registry+ entries are emitted; git+ and path deps are skipped."""
        lockfile = tmp_path / "Cargo.lock"
        lockfile.write_text(
            """\
version = 3

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.37.0"
source = "registry+sparse+https://index.crates.io/"

[[package]]
name = "my-local-crate"
version = "0.1.0"
# no source → workspace / path dep, skip

[[package]]
name = "some-git-crate"
version = "0.1.0"
source = "git+https://github.com/someone/crate.git#abc123"
"""
        )

        from aigate.cli import _parse_lockfile

        packages = _parse_lockfile(str(lockfile))
        names = {p[0]: p[1] for p in packages}
        assert names == {"serde": "1.0.200", "tokio": "1.37.0"}
        assert "my-local-crate" not in names
        assert "some-git-crate" not in names

    def test_cargo_lock_empty(self, tmp_path):
        """Empty Cargo.lock returns empty list."""
        lockfile = tmp_path / "Cargo.lock"
        lockfile.write_text("version = 3\n")
        from aigate.cli import _parse_lockfile

        assert _parse_lockfile(str(lockfile)) == []

    def test_infer_ecosystem_cargo_lock(self):
        """_infer_ecosystem maps Cargo.lock → crates."""
        from aigate.cli import _infer_ecosystem

        assert _infer_ecosystem("Cargo.lock") == "crates"
        assert _infer_ecosystem("./subdir/Cargo.lock") == "crates"


# ---------------------------------------------------------------------------
# Prefilter signals — build.rs / proc-macro
# ---------------------------------------------------------------------------


class TestCratesPrefilterSignals:
    def test_build_rs_presence_emits_high(self):
        """build.rs presence → HIGH risk signal."""
        signals = check_crates_risks(
            {
                "serde-1.0.200/Cargo.toml": '[package]\nname = "serde"\n',
                "serde-1.0.200/build.rs": "fn main() {}\n",
            }
        )
        assert any("build.rs" in s and "HIGH" in s for s in signals)

    def test_build_rs_with_reqwest_emits_network_signal(self):
        """build.rs + reqwest/Command → HIGH network-at-build-time signal."""
        signals = check_crates_risks(
            {
                "evil-1.0.0/build.rs": (
                    "use reqwest;\n"
                    "fn main() {\n"
                    '    reqwest::blocking::get("https://evil.com").unwrap();\n'
                    "}\n"
                ),
            }
        )
        assert any("build.rs" in s for s in signals)
        assert any("reqwest" in s for s in signals)

    def test_proc_macro_true_emits_high(self):
        """proc-macro = true in Cargo.toml → HIGH."""
        signals = check_crates_risks(
            {
                "macro-1.0.0/Cargo.toml": (
                    '[package]\nname = "macro"\nversion = "1.0.0"\n\n[lib]\nproc-macro = true\n'
                ),
            }
        )
        assert any("proc-macro" in s and "HIGH" in s for s in signals)

    def test_clean_crate_no_signals(self):
        """A plain library without build.rs or proc-macro → no crates-specific signals."""
        signals = check_crates_risks(
            {
                "pure-1.0.0/Cargo.toml": '[package]\nname = "pure"\n',
                "pure-1.0.0/src/lib.rs": "pub fn a() {}\n",
            }
        )
        assert signals == []

    def test_run_prefilter_crates_integration(self):
        """Full run_prefilter pipes crates signals into the result."""
        pkg = PackageInfo(name="evil", version="1.0.0", ecosystem="crates")
        source = {
            "evil-1.0.0/Cargo.toml": '[package]\nname = "evil"\n',
            "evil-1.0.0/build.rs": 'fn main() { println!("boom"); }\n',
        }
        result = run_prefilter(pkg, Config.default(), source)
        assert any("build.rs" in s for s in result.risk_signals)
        # One HIGH signal → HIGH risk level, AI review needed.
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert result.needs_ai_review is True
