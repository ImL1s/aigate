"""Package resolver — fetch metadata and source from registries."""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import tarfile
import zipfile
from pathlib import Path

import httpx

from .models import PackageInfo

logger = logging.getLogger(__name__)


class ExtractionError(Exception):
    """Raised when archive extraction fails (corrupt, unsupported, etc.)."""


class SourceUnavailableError(Exception):
    """Raised when source bytes cannot be fetched and the caller MUST NOT claim SAFE.

    Phase 3 (opensrc-integration-plan §3.3, Architect P1 #3): upstream surfaces
    this as ``PrefilterResult.source_unavailable=True`` and NEEDS_HUMAN_REVIEW.
    """


PYPI_API = "https://pypi.org/pypi"
NPM_API = "https://registry.npmjs.org"
PUB_API = "https://pub.dev/api/packages"
CRATES_API = "https://crates.io/api/v1/crates"
COCOAPODS_CDN = "https://cdn.cocoapods.org/Specs"
GITHUB_API = "https://api.github.com"
# JSR (jsr.io) — Deno/TS registry. We hit the **npm-compat** packument served
# at ``npm.jsr.io`` (Phase 4, opensrc-integration-plan §3.4). Packument shape is
# npm-compatible so extraction reuses the existing tarball path.
JSR_NPM_API = "https://npm.jsr.io"

# Override for E2E sandbox testing with local pypiserver
_E2E_PYPI_URL = os.environ.get("AIGATE_E2E_PYPI_URL")
MAX_ARCHIVE_SIZE = 50 * 1024 * 1024  # 50MB — reject larger archives to prevent OOM

# Crates.io archives are larger than npm/pypi norms (large SDKs, ML crates w/ bundled
# assets routinely exceed 50MB). Per opensrc-integration-plan §2.5 S3: raise to 200MB
# for crates to avoid false-blocking legitimate packages (Principle 2). Archives
# exceeding this still return NEEDS_HUMAN_REVIEW — never SAFE.
MAX_CRATES_ARCHIVE_SIZE = 200 * 1024 * 1024  # 200MB


def _jsr_to_npm_name(name: str) -> str:
    """Rewrite a JSR package name (``@scope/pkg``) to its npm-compat form.

    JSR's npm bridge at ``npm.jsr.io`` serves every JSR package under the
    ``@jsr`` scope, flattening ``@scope/pkg`` to ``@jsr/scope__pkg`` so npm
    clients can consume it. When the input already starts with ``@jsr/`` we
    pass it through unchanged (idempotent).

    Non-scoped names are rejected by the JSR registry policy (all JSR
    packages are scoped) — caller's responsibility to pass a scoped name;
    here we just return the stripped name unchanged for debuggability.
    """
    raw = name.strip()
    if raw.startswith("@jsr/"):
        return raw
    if raw.startswith("@") and "/" in raw:
        scope, pkg = raw[1:].split("/", 1)
        return f"@jsr/{scope}__{pkg}"
    return raw


async def resolve_package(
    name: str,
    version: str | None,
    ecosystem: str,
    client: httpx.AsyncClient | None = None,
) -> PackageInfo:
    """Resolve package metadata from registry."""
    logger.debug("Resolving package: %s/%s (ecosystem=%s)", name, version or "latest", ecosystem)
    if ecosystem == "pypi":
        return await _resolve_pypi(name, version, client=client)
    elif ecosystem == "npm":
        return await _resolve_npm(name, version, client=client)
    elif ecosystem == "pub":
        return await _resolve_pub(name, version, client=client)
    elif ecosystem == "crates" or ecosystem == "cargo":
        return await _resolve_crates(name, version, client=client)
    elif ecosystem == "cocoapods" or ecosystem == "pods":
        return await _resolve_cocoapods(name, version, client=client)
    elif ecosystem == "jsr":
        return await _resolve_jsr(name, version, client=client)
    else:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")


async def _resolve_pypi(
    name: str, version: str | None, *, client: httpx.AsyncClient | None = None
) -> PackageInfo:
    """Resolve from PyPI JSON API."""
    url = f"{PYPI_API}/{name}/json" if not version else f"{PYPI_API}/{name}/{version}/json"
    if client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()

    info = data["info"]
    latest_version = version or info.get("version", "")
    has_scripts = any(url_info.get("packagetype") == "sdist" for url_info in data.get("urls", []))

    return PackageInfo(
        name=name,
        version=latest_version,
        ecosystem="pypi",
        author=info.get("author", "") or info.get("author_email", ""),
        description=info.get("summary", ""),
        homepage=info.get("home_page", "") or info.get("project_url", ""),
        repository=_extract_repo_url(info.get("project_urls", {})),
        has_install_scripts=has_scripts,
        dependencies=info.get("requires_dist", []) or [],
        metadata={"info": info},
    )


async def _resolve_npm(
    name: str, version: str | None, *, client: httpx.AsyncClient | None = None
) -> PackageInfo:
    """Resolve from npm registry."""
    url = f"{NPM_API}/{name}"
    if client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()

    latest_version = version or data.get("dist-tags", {}).get("latest", "")
    version_data = data.get("versions", {}).get(latest_version, {})
    scripts = version_data.get("scripts", {})
    has_scripts = bool(
        scripts.get("preinstall") or scripts.get("postinstall") or scripts.get("install")
    )

    return PackageInfo(
        name=name,
        version=latest_version,
        ecosystem="npm",
        author=_extract_npm_author(version_data),
        description=version_data.get("description", ""),
        homepage=version_data.get("homepage", ""),
        repository=_extract_npm_repo(version_data),
        has_install_scripts=has_scripts,
        dependencies=list(version_data.get("dependencies", {}).keys()),
        metadata={"version_data": version_data},
    )


async def _resolve_pub(
    name: str, version: str | None, *, client: httpx.AsyncClient | None = None
) -> PackageInfo:
    """Resolve from pub.dev API."""
    url = f"{PUB_API}/{name}" if not version else f"{PUB_API}/{name}/versions/{version}"
    if client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()

    version_data = data.get("latest", {}) if not version else data
    pubspec = version_data.get("pubspec", {})
    latest_version = version or version_data.get("version", pubspec.get("version", ""))

    return PackageInfo(
        name=name,
        version=latest_version,
        ecosystem="pub",
        author=str(pubspec.get("publisher", "")),
        description=pubspec.get("description", ""),
        homepage=pubspec.get("homepage", "") or pubspec.get("repository", ""),
        repository=pubspec.get("repository", ""),
        has_install_scripts=False,
        dependencies=list((pubspec.get("dependencies") or {}).keys()),
        metadata={"version_data": version_data},
    )


async def _resolve_crates(
    name: str, version: str | None, *, client: httpx.AsyncClient | None = None
) -> PackageInfo:
    """Resolve from crates.io registry API.

    Uses ``GET /api/v1/crates/{name}`` (or ``{name}/{version}``). For the
    version-less form the response includes a ``crate`` section for package
    metadata and a ``versions`` array; we select the latest non-yanked version.

    Crates don't have an install-script step aigate executes, but ``build.rs``
    + proc-macros still run at ``cargo build`` time — the prefilter flags
    those via crates-specific rules (see ``rules/builtin/crates_rules.yml``).
    """
    # Version-specific endpoint returns ``{ "version": {...} }``. Without a
    # version we hit the crate-wide endpoint which carries the full payload.
    url = f"{CRATES_API}/{name}" if not version else f"{CRATES_API}/{name}/{version}"
    if client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()

    crate_data = data.get("crate") or {}
    versions = data.get("versions") or []

    version_entry: dict = {}
    if version:
        # crates.io returns a single ``version`` object at the top level for
        # version-specific queries.
        version_entry = data.get("version") or {}
        latest_version = version_entry.get("num", version)
    else:
        # Prefer ``max_stable_version`` / ``max_version`` from crate_data,
        # fall back to the first non-yanked entry in versions.
        latest_version = crate_data.get("max_stable_version") or crate_data.get("max_version") or ""
        for entry in versions:
            if entry.get("num") == latest_version:
                version_entry = entry
                break
        if not version_entry and versions:
            for entry in versions:
                if not entry.get("yanked"):
                    version_entry = entry
                    latest_version = entry.get("num", latest_version)
                    break

    # Yanked-version warning: log but still return metadata — the caller
    # decides whether to proceed (scan will flag it via risk signal).
    if version_entry.get("yanked"):
        logger.warning("crates.io: %s==%s is yanked (unsafe to install)", name, latest_version)

    repository = version_entry.get("repository") or crate_data.get("repository") or ""
    homepage = crate_data.get("homepage", "") or ""
    description = crate_data.get("description", "") or version_entry.get("description", "")

    # ``authors`` not available on the ``crate`` summary endpoint — it's on
    # the individual version object (sometimes). Fall back to empty string.
    author = ""
    if isinstance(version_entry.get("authors"), list):
        author = ", ".join(a for a in version_entry["authors"] if isinstance(a, str))
    elif isinstance(version_entry.get("published_by"), dict):
        pb = version_entry["published_by"]
        author = pb.get("name") or pb.get("login") or ""

    return PackageInfo(
        name=name,
        version=latest_version,
        ecosystem="crates",
        author=author,
        description=description,
        homepage=homepage,
        repository=repository,
        # aigate never runs cargo build. We still flag build.rs / proc-macro via
        # prefilter risk signals — those run at compile time, not install time.
        has_install_scripts=False,
        dependencies=[],
        metadata={"crate": crate_data, "version_entry": version_entry},
    )


async def _resolve_jsr(
    name: str, version: str | None, *, client: httpx.AsyncClient | None = None
) -> PackageInfo:
    """Resolve a JSR (jsr.io) package via its npm-compat packument.

    Phase 4 (opensrc-integration-plan §3.4). JSR (Deno's TS-native registry) is
    a superset of npm — its npm-compat endpoint at ``https://npm.jsr.io`` serves
    a standard npm packument with ``versions[].dist.tarball`` pointing at a
    gzipped tar. aigate re-uses the npm extract path; the only JSR-specific bit
    is the ``@scope/pkg`` -> ``@jsr/scope__pkg`` name rewrite.
    """
    npm_name = _jsr_to_npm_name(name)
    url = f"{JSR_NPM_API}/{npm_name}"
    if client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()

    latest_version = version or data.get("dist-tags", {}).get("latest", "")
    version_data = data.get("versions", {}).get(latest_version, {}) or {}

    # JSR packuments generally do not include npm-style install scripts, but
    # honor them if present for forward compatibility.
    scripts = version_data.get("scripts", {}) or {}
    has_scripts = bool(
        scripts.get("preinstall") or scripts.get("postinstall") or scripts.get("install")
    )

    return PackageInfo(
        name=name,  # Preserve original JSR ``@scope/pkg`` for UX / cache keys
        version=latest_version,
        ecosystem="jsr",
        author=_extract_npm_author(version_data),
        description=version_data.get("description", ""),
        homepage=version_data.get("homepage", "") or "",
        repository=_extract_npm_repo(version_data),
        has_install_scripts=has_scripts,
        dependencies=list((version_data.get("dependencies") or {}).keys()),
        metadata={"version_data": version_data, "npm_name": npm_name},
    )


async def _download_jsr_source(
    package: PackageInfo, *, client: httpx.AsyncClient | None = None
) -> dict[str, str]:
    """Download a JSR package tarball via the npm.jsr.io packument.

    Mirrors ``_download_npm_source`` exactly, only the base URL differs.
    Factored separately (not a call-through) so a future JSR divergence
    (e.g. per-file ``jsr.io`` API) can land without touching npm.
    """
    npm_name = _jsr_to_npm_name(package.name)
    url = f"{JSR_NPM_API}/{npm_name}/{package.version}"
    if client:
        resp = await client.get(url)
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
    resp.raise_for_status()
    data = resp.json()

    tarball_url = data.get("dist", {}).get("tarball")
    if not tarball_url:
        return {}

    if client:
        resp = await client.get(tarball_url)
    else:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
            resp = await c.get(tarball_url)
    resp.raise_for_status()
    content = resp.content
    if len(content) > MAX_ARCHIVE_SIZE:
        raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    return _extract_archive(content, tarball_url)


async def download_source(
    package: PackageInfo,
    dest: Path | None = None,
    client: httpx.AsyncClient | None = None,
    *,
    max_archive_size_crates: int | None = None,
    github_token: str | None = None,
) -> dict[str, str]:
    """Download and extract package source, return {filepath: content} dict.

    Args:
        package: PackageInfo with ecosystem + name + version.
        dest: reserved — written to disk only on demand, unused today.
        client: optional shared httpx client (connection pooling).
        max_archive_size_crates: override for the crates 200MB archive cap,
            plumbed through from ``Config.resolver.max_archive_size_crates``.
        github_token: optional GitHub PAT for authed rate-limit window.
            Required for most git-sourced CocoaPods (unauth 60/hr is not
            enough in CI). Absent + 403 -> ``SourceUnavailableError``.
    """
    logger.debug(
        "Downloading source: %s==%s (%s)", package.name, package.version, package.ecosystem
    )
    if package.ecosystem == "pypi":
        return await _download_pypi_source(package, client=client)
    elif package.ecosystem == "npm":
        return await _download_npm_source(package, client=client)
    elif package.ecosystem == "pub":
        return await _download_pub_source(package, client=client)
    elif package.ecosystem in ("crates", "cargo"):
        return await _download_crates_source(
            package, client=client, max_archive_size=max_archive_size_crates
        )
    elif package.ecosystem in ("cocoapods", "pods"):
        return await _download_cocoapods_source(package, client=client, github_token=github_token)
    elif package.ecosystem == "jsr":
        return await _download_jsr_source(package, client=client)
    else:
        raise ValueError(f"Unsupported ecosystem: {package.ecosystem}")


async def _download_pypi_source(
    package: PackageInfo, *, client: httpx.AsyncClient | None = None
) -> dict[str, str]:
    """Download PyPI sdist/wheel and extract text files."""
    url = f"{PYPI_API}/{package.name}/{package.version}/json"

    async def _get(u: str, **kw: object) -> httpx.Response:
        if client:
            return await client.get(u, **kw)  # type: ignore[arg-type]
        async with httpx.AsyncClient(
            timeout=kw.pop("timeout", 60), follow_redirects=kw.pop("follow_redirects", False)
        ) as c:  # type: ignore[arg-type]
            return await c.get(u)

    resp = await _get(url, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    # Prefer sdist over wheel (has setup.py)
    urls = data.get("urls", [])
    download_url = None
    for u in urls:
        if u.get("packagetype") == "sdist":
            download_url = u["url"]
            break
    if not download_url and urls:
        download_url = urls[0]["url"]
    if not download_url:
        return {}

    resp = await _get(download_url, timeout=120, follow_redirects=True)
    resp.raise_for_status()
    content = resp.content
    if len(content) > MAX_ARCHIVE_SIZE:
        raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    return _extract_archive(content, download_url)


async def _download_npm_source(
    package: PackageInfo, *, client: httpx.AsyncClient | None = None
) -> dict[str, str]:
    """Download npm tarball and extract text files."""
    url = f"{NPM_API}/{package.name}/{package.version}"
    if client:
        resp = await client.get(url)
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
    resp.raise_for_status()
    data = resp.json()

    tarball_url = data.get("dist", {}).get("tarball")
    if not tarball_url:
        return {}

    if client:
        resp = await client.get(tarball_url)
    else:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
            resp = await c.get(tarball_url)
    resp.raise_for_status()
    content = resp.content
    if len(content) > MAX_ARCHIVE_SIZE:
        raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    return _extract_archive(content, tarball_url)


async def _download_pub_source(
    package: PackageInfo, *, client: httpx.AsyncClient | None = None
) -> dict[str, str]:
    """Download pub.dev tarball and extract text files."""
    url = f"{PUB_API}/{package.name}/versions/{package.version}"
    if client:
        resp = await client.get(url)
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
    resp.raise_for_status()
    data = resp.json()

    tarball_url = data.get("archive_url")
    if not tarball_url:
        return {}

    if client:
        resp = await client.get(tarball_url)
    else:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
            resp = await c.get(tarball_url)
    resp.raise_for_status()
    content = resp.content
    if len(content) > MAX_ARCHIVE_SIZE:
        raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    return _extract_archive(content, tarball_url)


async def _download_crates_source(
    package: PackageInfo,
    *,
    client: httpx.AsyncClient | None = None,
    max_archive_size: int | None = None,
) -> dict[str, str]:
    """Download a ``.crate`` tarball from crates.io and extract text files.

    The download endpoint redirects to a signed static.crates.io URL; we
    follow redirects. ``.crate`` files are gzipped tarballs (same format as
    ``.tar.gz``), so we reuse ``_extract_archive`` with a ``.tar.gz``
    filename hint.

    Args:
        package: PackageInfo for the crate (name + version required).
        client: Optional shared httpx client.
        max_archive_size: Optional override for the 200MB cap (see
            ``MAX_CRATES_ARCHIVE_SIZE``). The caller is responsible for
            threading this through from ``Config.max_archive_size_crates``.

    Raises:
        ValueError: When the archive exceeds the size cap. Upstream converts
            this to ``archive_oversized`` + NEEDS_HUMAN_REVIEW per plan §2.5.
    """
    size_cap = max_archive_size if max_archive_size is not None else MAX_CRATES_ARCHIVE_SIZE

    # Direct download URL — crates.io responds with a 302 to static.crates.io.
    download_url = f"{CRATES_API}/{package.name}/{package.version}/download"

    if client:
        resp = await client.get(download_url)
    else:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
            resp = await c.get(download_url)
    resp.raise_for_status()
    content = resp.content

    if len(content) > size_cap:
        # Per PRD §2.5 S3: oversize must never produce SAFE. Raise
        # ``archive_oversized`` so the caller surfaces NEEDS_HUMAN_REVIEW.
        raise ValueError(f"archive_oversized: {len(content)} bytes exceeds crates cap {size_cap}")

    # ``.crate`` files are gzipped tar archives — pass a .tar.gz filename hint.
    archive_name = f"{package.name}-{package.version}.tar.gz"
    return _extract_archive(content, archive_name)


# ---------------------------------------------------------------------------
# CocoaPods — Phase 3 of opensrc-integration-plan
# ---------------------------------------------------------------------------


def _cocoapods_shard(name: str) -> str:
    """Compute the CDN shard for a pod — first 3 MD5 hex chars of the name.

    CocoaPods CDN serves podspec JSON at
    ``{CDN}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json`` where
    ``a/b/c`` are the first three hex characters of ``md5(name)``. Verified
    against the live CDN (e.g. ``AFNetworking`` -> ``a75/d9a/e0a/`` etc).
    """
    digest = hashlib.md5(name.encode("utf-8")).hexdigest()  # noqa: S324 — not crypto, just a shard key
    return f"{digest[0]}/{digest[1]}/{digest[2]}"


def _derive_github_repo(git_url: str) -> tuple[str, str, str] | None:
    """Parse ``owner/repo`` from a git URL suitable for GitHub's tarball API.

    Returns ``(host, owner, repo)`` for known hosts, else None. Supports:

    * ``https://github.com/owner/repo(.git)?``
    * ``git@github.com:owner/repo(.git)?``
    * ``git+https://github.com/...``
    * gitlab.com (same shape, but the caller may choose not to use it)
    """
    if not git_url:
        return None
    url = git_url.strip()
    for prefix in ("git+",):
        if url.startswith(prefix):
            url = url[len(prefix) :]
    # SSH form: git@host:owner/repo.git
    ssh = re.match(
        r"^git@(?P<host>github\.com|gitlab\.com)[:/](?P<owner>[^/]+)/(?P<repo>[^/\s#?]+?)(?:\.git)?$",
        url,
    )
    if ssh:
        return ssh.group("host"), ssh.group("owner"), ssh.group("repo")
    https = re.match(
        r"^https?://(?P<host>github\.com|gitlab\.com)/(?P<owner>[^/]+)/(?P<repo>[^/\s#?]+?)(?:\.git)?(?:[/?#].*)?$",
        url,
    )
    if https:
        return https.group("host"), https.group("owner"), https.group("repo")
    return None


async def _resolve_cocoapods(
    name: str, version: str | None, *, client: httpx.AsyncClient | None = None
) -> PackageInfo:
    """Resolve a pod via the CocoaPods CDN podspec JSON.

    URL: ``{COCOAPODS_CDN}/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json``.
    Versionless lookup not supported by the CDN — we fetch the per-shard
    versions listing instead (``{CDN}/{shard}/{name}/{name}.podspec.json``)
    is NOT a valid endpoint; for v1 we require an explicit version.
    """
    if not version:
        # No cheap versionless listing on the CDN. Surface a clear error so
        # callers know to pass -v / parse Podfile.lock rather than silently
        # guessing.
        raise ValueError("CocoaPods resolution requires an explicit version (pass -v X.Y.Z)")

    shard = _cocoapods_shard(name)
    url = f"{COCOAPODS_CDN}/{shard}/{name}/{version}/{name}.podspec.json"

    if client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    else:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()

    authors = data.get("authors") or {}
    if isinstance(authors, dict):
        author_str = ", ".join(authors.keys())
    elif isinstance(authors, list):
        author_str = ", ".join(str(a) for a in authors)
    else:
        author_str = str(authors or "")

    source = data.get("source") or {}
    repository = ""
    if isinstance(source, dict) and source.get("git"):
        repository = str(source["git"])
    homepage = str(data.get("homepage", "") or "")

    return PackageInfo(
        name=name,
        version=version,
        ecosystem="cocoapods",
        author=author_str,
        description=str(data.get("summary") or data.get("description", "") or ""),
        homepage=homepage,
        repository=repository,
        has_install_scripts=bool(
            source.get("prepare_command") if isinstance(source, dict) else False
        ),
        dependencies=list((data.get("dependencies") or {}).keys()),
        metadata={"podspec": data, "source": source},
    )


async def _download_cocoapods_source(
    package: PackageInfo,
    *,
    client: httpx.AsyncClient | None = None,
    github_token: str | None = None,
) -> dict[str, str]:
    """Download source for a CocoaPods package.

    Decision tree (PRD §3.3):

    * ``source.http`` with ``type: tar.gz|zip`` -> direct HTTPS download.
    * ``source.git`` + ``tag`` / ``commit`` / ``branch`` -> GitHub tarball
      detour. Needs GitHub API; rate-limited to 60/hr without token.
      On 403 / 429 -> raise ``SourceUnavailableError`` so the caller can
      surface NEEDS_HUMAN_REVIEW.
    * Unknown / unsupported shape -> raise ``SourceUnavailableError``.

    Divergence detection (T-COC-DIV-1/2): when we successfully fetch a
    GitHub tarball, we attach a synthetic ``.aigate-tarball-manifest`` file
    to the result so ``check_cocoapods_risks`` can inspect it. Specifically,
    if ``.gitattributes`` is absent from the tarball AND the podspec's
    ``source.source_files`` glob advertises paths missing from the tarball,
    that is a divergence signal. We stash the manifest inline rather than
    re-plumbing a second return channel through ``download_source``.
    """
    podspec = package.metadata.get("podspec") if package.metadata else None
    source = package.metadata.get("source") if package.metadata else None
    if not isinstance(source, dict):
        raise SourceUnavailableError(
            f"CocoaPods podspec for {package.name}@{package.version} has no usable source field"
        )

    # Case 1: http direct archive
    http_url = source.get("http")
    if isinstance(http_url, str) and http_url:
        return await _download_cocoapods_http(http_url, source, client=client)

    # Case 2: git+ref
    git_url = source.get("git")
    if isinstance(git_url, str) and git_url:
        parsed = _derive_github_repo(git_url)
        if parsed is None:
            raise SourceUnavailableError(f"Unsupported git host for CocoaPods source: {git_url}")
        host, owner, repo = parsed
        # Only github.com has a public tarball API exposed via api.github.com
        # that doesn't require a full git clone. gitlab.com hosts work via
        # ``/-/archive/<ref>/<name>-<ref>.tar.gz`` but require no API auth.
        if host != "github.com":
            raise SourceUnavailableError(
                f"CocoaPods git source on {host} not supported without GITHUB_TOKEN-equivalent auth"
            )
        ref = source.get("tag") or source.get("commit") or source.get("branch") or package.version
        return await _fetch_github_tarball(
            owner=owner,
            repo=repo,
            ref=str(ref),
            package_name=package.name,
            source=source,
            podspec=podspec,
            client=client,
            github_token=github_token,
        )

    raise SourceUnavailableError(
        f"CocoaPods podspec for {package.name}@{package.version} has no http or git source"
    )


async def _download_cocoapods_http(
    http_url: str,
    source: dict,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, str]:
    """Download direct-HTTP CocoaPods archive and extract."""
    if client:
        resp = await client.get(http_url)
    else:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
            resp = await c.get(http_url)
    resp.raise_for_status()
    content = resp.content
    if len(content) > MAX_ARCHIVE_SIZE:
        raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    # Detect archive type: explicit ``type`` hint first, fall back to URL suffix
    archive_type = str(source.get("type") or "").lower()
    if archive_type == "tgz":
        archive_type = "tar.gz"
    if not archive_type:
        lowered = http_url.lower()
        if lowered.endswith(".zip"):
            archive_type = "zip"
        elif lowered.endswith((".tar.gz", ".tgz")):
            archive_type = "tar.gz"
        elif lowered.endswith(".tar"):
            archive_type = "tar"
    archive_name = f"source.{archive_type or 'tar.gz'}"
    return _extract_archive(content, archive_name)


async def _fetch_github_tarball(
    *,
    owner: str,
    repo: str,
    ref: str,
    package_name: str,
    source: dict,
    podspec: dict | None,
    client: httpx.AsyncClient | None = None,
    github_token: str | None = None,
) -> dict[str, str]:
    """Fetch + extract a GitHub tarball at ref for a CocoaPods git source.

    On 403 / 404 / 429 (rate-limit without token), raise
    ``SourceUnavailableError`` — caller surfaces NEEDS_HUMAN_REVIEW rather
    than SAFE on uninspected bytes.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tarball/{ref}"
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    try:
        if client:
            resp = await client.get(url, headers=headers, follow_redirects=True)
        else:
            async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
                resp = await c.get(url, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status in (403, 404, 429):
            # 403 is the canonical unauth-rate-limit response; 404 happens when
            # a missing repo/tag *or* a token that lacks access hides the repo;
            # 429 is explicit rate-limiting. All three MUST NOT be laundered
            # into SAFE per PRD §3.3 + Architect P1 #3.
            raise SourceUnavailableError(
                f"GitHub rate-limit or unauthorized on {url} (HTTP {status}) — "
                "set GITHUB_TOKEN for authed 5000/hr window"
            ) from exc
        raise

    content = resp.content
    if len(content) > MAX_ARCHIVE_SIZE:
        raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    archive_name = f"{owner}-{repo}-{ref}.tar.gz"
    files = _extract_archive(content, archive_name)

    # Divergence detection (T-COC-DIV-1/2): a lightweight check comparing the
    # podspec's advertised source_files glob(s) to the actual tarball file list.
    # Detection needs the full tarball file list (including .gitattributes which
    # the default whitelist may drop), so we peek at the archive separately.
    tarball_manifest = _list_tarball_members(content, archive_name)
    divergence = _detect_podspec_divergence(
        source=source,
        files=files,
        tarball_manifest=tarball_manifest,
    )
    if divergence:
        # Add a pseudo-file so the prefilter can see the signal inline.
        files["__aigate__/cocoapods-divergence.txt"] = divergence

    return files


def _list_tarball_members(content: bytes, archive_name: str) -> dict[str, bytes]:
    """Return ``{member_name: bytes or empty}`` for every file in a tarball.

    Unlike ``_extract_archive`` this does not filter by extension — divergence
    detection needs to see files like ``.gitattributes`` that the text-file
    whitelist drops. Returns empty dict on extraction failure.
    """
    manifest: dict[str, bytes] = {}
    try:
        if archive_name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    if not _is_path_safe(member.name):
                        continue
                    try:
                        f = tar.extractfile(member)
                        if f is None:
                            manifest[member.name] = b""
                        else:
                            # Cap per-member at 64KB — we only inspect for substrings.
                            manifest[member.name] = f.read(64 * 1024)
                    except Exception:
                        manifest[member.name] = b""
    except (tarfile.TarError, EOFError, OSError):
        return {}
    return manifest


# Top-level directories we expect to see inside GitHub tarballs. The archive
# root is a single ``<owner>-<repo>-<sha>/`` directory; anything inside that
# should correspond to paths the podspec advertises.
def _detect_podspec_divergence(
    source: dict,
    files: dict[str, str],
    tarball_manifest: dict[str, bytes] | None = None,
) -> str | None:
    """Emit a one-line divergence message when the tarball looks suspicious.

    Heuristic:
    * If ``.gitattributes`` is in the tarball with ``export-ignore`` entries,
      skip — legitimate divergence-on-design (T-COC-DIV-2 control passes).
    * Else, if podspec declares ``source_files: "Classes/**"`` (or similar)
      and the tarball has no ``Classes/`` directory, emit the signal.
    * Else, no signal (lightweight detection per PRD §3.3 "keep lightweight").

    ``tarball_manifest`` is the raw archive file list (including files the
    text-file whitelist dropped, like ``.gitattributes``). When None we fall
    back to ``files`` only.
    """
    # Use the unfiltered manifest when available; it reveals .gitattributes.
    manifest_source: dict[str, str | bytes]
    if tarball_manifest:
        manifest_source = dict(tarball_manifest)
    else:
        manifest_source = dict(files)

    # Flatten top-level segments (strip root prefix like ``owner-repo-sha/``)
    seen_segments: set[str] = set()
    gitattributes_export_ignore = False
    for path, payload in manifest_source.items():
        # Skip our own synthetic files
        if path.startswith("__aigate__/"):
            continue
        parts = path.split("/", 2)
        if len(parts) >= 2:
            seen_segments.add(parts[1])
        if path.endswith(".gitattributes"):
            if isinstance(payload, bytes):
                needle = b"export-ignore"
                if needle in payload:
                    gitattributes_export_ignore = True
            else:
                if "export-ignore" in (payload or ""):
                    gitattributes_export_ignore = True

    if gitattributes_export_ignore:
        # Explanatory .gitattributes present -> no divergence signal
        return None

    # Parse podspec source_files into top-level segments
    source_files_field = source.get("source_files") if isinstance(source, dict) else None
    advertised: list[str] = []
    if isinstance(source_files_field, str):
        advertised = [source_files_field]
    elif isinstance(source_files_field, list):
        advertised = [str(x) for x in source_files_field if isinstance(x, str)]

    missing: list[str] = []
    for glob in advertised:
        top = glob.split("/", 1)[0].rstrip("*").strip()
        if not top or top == ".":
            continue
        if top in seen_segments:
            continue
        missing.append(top)

    if missing:
        return (
            "podspec-vs-tarball path divergence: podspec advertises "
            f"source_files paths {missing!r} that are missing from the GitHub tarball"
        )
    return None


def _is_path_safe(name: str) -> bool:
    """Reject path traversal and absolute paths."""
    if not name or name.startswith("/") or ".." in name.split("/"):
        return False
    return True


def _extract_archive(content: bytes, filename: str) -> dict[str, str]:
    """Extract text files from tar.gz or zip/whl archive.

    Files matching the extension whitelist are extracted directly.
    Files with unknown or no extension are content-sniffed: if they contain
    code (Python, JS, shell, etc.), they are extracted too — catching
    malicious files disguised with non-code extensions.
    """
    from .content_sniff import CODE_TYPES, sniff_content_type

    files: dict[str, str] = {}
    text_extensions = {
        ".dart",
        ".py",
        ".js",
        ".ts",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".cfg",
        ".ini",
        ".txt",
        ".md",
        ".rst",
        ".sh",
        ".bat",
        ".pth",
        # crates: Rust sources (Phase 2, opensrc-integration-plan).
        # Needed so build.rs / src/*.rs land in the extract for AI prompts.
        ".rs",
        # cocoapods: Swift / Obj-C / Obj-C++ sources (Phase 3).
        ".swift",
        ".m",
        ".mm",
        ".h",
        ".c",
        ".cc",
        ".cpp",
        ".podspec",
        ".gitattributes",
    }
    max_file_size = 512 * 1024  # 512KB per file

    # Dotfile basenames we explicitly want extracted (no file extension).
    # ``.gitattributes`` carries ``export-ignore`` directives needed for
    # cocoapods divergence detection (Phase 3 opensrc-integration-plan).
    dotfile_basenames = {".gitattributes"}

    def _should_extract(name: str, raw_bytes: bytes) -> tuple[bool, str | None]:
        """Return (should_extract, decoded_text_or_None)."""
        suffix = Path(name).suffix.lower()
        basename = name.rsplit("/", 1)[-1]
        if suffix in text_extensions or basename in dotfile_basenames:
            try:
                return True, raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                return False, None
        # Extension not in whitelist — try content sniffing
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            return False, None
        detected = sniff_content_type(text)
        if detected and detected in CODE_TYPES:
            return True, text
        return False, None

    max_total_size = 100 * 1024 * 1024  # 100MB cumulative extraction limit
    cumulative_size = 0

    try:
        if filename.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
                for member in tar.getmembers():
                    # Defense in depth: explicitly reject symlinks and hardlinks
                    if member.issym() or member.islnk():
                        continue
                    if not member.isfile() or member.size > max_file_size:
                        continue
                    if not _is_path_safe(member.name):
                        continue
                    cumulative_size += member.size
                    if cumulative_size > max_total_size:
                        logger.warning(
                            "Archive extraction limit reached (%d bytes), stopping",
                            cumulative_size,
                        )
                        break
                    f = tar.extractfile(member)
                    if f:
                        try:
                            raw = f.read()
                            ok, text = _should_extract(member.name, raw)
                            if ok and text is not None:
                                files[member.name] = text
                        except Exception:
                            logger.warning("Failed to extract %s", member.name)
        elif filename.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > max_file_size:
                        continue
                    if not _is_path_safe(info.filename):
                        continue
                    cumulative_size += info.file_size
                    if cumulative_size > max_total_size:
                        logger.warning(
                            "Archive extraction limit reached (%d bytes), stopping",
                            cumulative_size,
                        )
                        break
                    try:
                        raw = zf.read(info.filename)
                        ok, text = _should_extract(info.filename, raw)
                        if ok and text is not None:
                            files[info.filename] = text
                    except Exception:
                        logger.warning("Failed to extract %s", info.filename)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as exc:
        raise ExtractionError(f"Failed to extract {filename}: {exc}") from exc

    return files


SKIP_EXTENSIONS = {
    ".md",
    ".rst",
    ".txt",
    ".csv",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".lock",
    ".png",
    ".jpg",
    ".gif",
    ".ico",
}

MAX_LOCAL_SOURCE_SIZE = MAX_ARCHIVE_SIZE  # 50MB — same limit as archive downloads

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def read_local_source_files(path: Path) -> dict[str, str]:
    """Read source files from a local directory, returning per-file dict.

    Returns ``{relative_path: content}`` — same format as
    :func:`_extract_archive`, giving the prefilter per-file granularity for
    extension-mismatch detection.

    Files with skipped extensions or no extension are content-sniffed:
    if they contain code, they are included anyway.
    """
    from .content_sniff import CODE_TYPES, sniff_content_type

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if path.is_file():
        return {str(path): path.read_text(errors="replace")}

    cumulative_size = 0
    result: dict[str, str] = {}
    for root_str, dirs, files in os.walk(path):
        # Skip hidden / non-essential directories in-place so os.walk won't descend
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        root = Path(root_str)
        for fname in sorted(files):
            f = root / fname
            text: str | None = None  # will hold file content if already read

            if f.suffix in SKIP_EXTENSIONS or not f.suffix:
                # Sniff: read once, decide, reuse if code
                try:
                    text = f.read_text(errors="replace")
                    detected = sniff_content_type(text[:4096])
                    if detected not in CODE_TYPES:
                        continue  # Not code, skip
                    # Fall through — content is code despite extension
                except (OSError, UnicodeDecodeError):
                    continue

            try:
                if text is not None:
                    # Already read during sniffing — reuse
                    size = len(text.encode("utf-8", errors="replace"))
                else:
                    size = f.stat().st_size
                cumulative_size += size
                if cumulative_size > MAX_LOCAL_SOURCE_SIZE:
                    logger.warning(
                        "Local source size limit reached (%d bytes), stopping read",
                        MAX_LOCAL_SOURCE_SIZE,
                    )
                    return result
                if text is None:
                    text = f.read_text(errors="replace")
                rel = str(f.relative_to(path))
                result[rel] = text
            except (OSError, UnicodeDecodeError):
                continue
    return result


def read_local_source(path: Path) -> str:
    """Read source code from a local file or directory as a single string.

    This is a convenience wrapper around :func:`read_local_source_files`
    that concatenates all files into a single string with headers.
    """
    files = read_local_source_files(path)
    return "\n\n".join(f"# --- {name} ---\n{content}" for name, content in files.items())


def _extract_repo_url(project_urls: dict[str, str] | None) -> str:
    if not project_urls:
        return ""
    for key in ("Repository", "Source", "Source Code", "GitHub", "Homepage"):
        if key in project_urls:
            url = project_urls[key]
            if "github.com" in url or "gitlab.com" in url:
                return url
    return ""


def _extract_npm_author(data: dict) -> str:
    author = data.get("author", "")
    if isinstance(author, dict):
        return author.get("name", "")
    return str(author)


def _extract_npm_repo(data: dict) -> str:
    repo = data.get("repository", "")
    if isinstance(repo, dict):
        return repo.get("url", "")
    return str(repo)


# ---------------------------------------------------------------------------
# E2E sandbox helpers — download from local pypiserver
# ---------------------------------------------------------------------------

_HREF_RE = re.compile(r'href="([^"#]+\.tar\.gz)(?:#[^"]*)?"', re.IGNORECASE)


async def download_from_local_pypi(
    package_name: str,
    base_url: str | None = None,
) -> dict[str, str]:
    """Download a .tar.gz from a local pypiserver and extract text files.

    pypiserver serves ``/simple/<package>/`` with an HTML page containing
    ``<a href="...">`` links to archive files.  This helper fetches that
    index, finds the first ``.tar.gz`` link, downloads it, and returns
    extracted text files via ``_extract_archive()``.

    Args:
        package_name: The package name (used to build the index URL).
        base_url: The pypiserver simple-index URL, e.g.
            ``http://pypi:8080/simple/``.  Falls back to the
            ``AIGATE_E2E_PYPI_URL`` env var.

    Returns:
        ``{filepath: content}`` dict, same as ``download_source()``.

    Raises:
        ValueError: If no base URL is available or no .tar.gz found.
    """
    url = base_url or _E2E_PYPI_URL
    if not url:
        raise ValueError("No local PyPI URL provided. Set AIGATE_E2E_PYPI_URL or pass base_url.")

    # Ensure trailing slash on base, then append package name + /
    index_url = url.rstrip("/") + "/" + package_name + "/"
    logger.debug("Fetching local pypi index: %s", index_url)

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(index_url)
        resp.raise_for_status()
        html = resp.text

    # Parse href links to .tar.gz files
    matches = _HREF_RE.findall(html)
    if not matches:
        raise ValueError(f"No .tar.gz links found at {index_url}")

    # Use the first .tar.gz link
    tar_link = matches[0]

    # pypiserver may serve relative links (just the filename) or absolute
    if tar_link.startswith("http://") or tar_link.startswith("https://"):
        download_url = tar_link
    elif tar_link.startswith("/"):
        # Absolute path — combine with origin
        from urllib.parse import urlparse

        parsed = urlparse(url)
        download_url = f"{parsed.scheme}://{parsed.netloc}{tar_link}"
    else:
        # Relative path — resolve against the index URL
        download_url = index_url.rstrip("/") + "/" + tar_link

    logger.debug("Downloading archive: %s", download_url)

    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        resp = await client.get(download_url)
        resp.raise_for_status()
        content = resp.content
        if len(content) > MAX_ARCHIVE_SIZE:
            raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    # The filename for _extract_archive needs to end with .tar.gz
    archive_name = tar_link.rsplit("/", 1)[-1] if "/" in tar_link else tar_link
    return _extract_archive(content, archive_name)
