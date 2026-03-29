"""Package resolver — fetch metadata and source from registries."""

from __future__ import annotations

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

PYPI_API = "https://pypi.org/pypi"
NPM_API = "https://registry.npmjs.org"
PUB_API = "https://pub.dev/api/packages"

# Override for E2E sandbox testing with local pypiserver
_E2E_PYPI_URL = os.environ.get("AIGATE_E2E_PYPI_URL")
MAX_ARCHIVE_SIZE = 50 * 1024 * 1024  # 50MB — reject larger archives to prevent OOM


async def resolve_package(name: str, version: str | None, ecosystem: str) -> PackageInfo:
    """Resolve package metadata from registry."""
    logger.debug("Resolving package: %s/%s (ecosystem=%s)", name, version or "latest", ecosystem)
    if ecosystem == "pypi":
        return await _resolve_pypi(name, version)
    elif ecosystem == "npm":
        return await _resolve_npm(name, version)
    elif ecosystem == "pub":
        return await _resolve_pub(name, version)
    else:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")


async def _resolve_pypi(name: str, version: str | None) -> PackageInfo:
    """Resolve from PyPI JSON API."""
    url = f"{PYPI_API}/{name}/json" if not version else f"{PYPI_API}/{name}/{version}/json"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url)
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


async def _resolve_npm(name: str, version: str | None) -> PackageInfo:
    """Resolve from npm registry."""
    url = f"{NPM_API}/{name}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url)
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


async def _resolve_pub(name: str, version: str | None) -> PackageInfo:
    """Resolve from pub.dev API."""
    url = f"{PUB_API}/{name}" if not version else f"{PUB_API}/{name}/versions/{version}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url)
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


async def download_source(package: PackageInfo, dest: Path | None = None) -> dict[str, str]:
    """Download and extract package source, return {filepath: content} dict."""
    logger.debug(
        "Downloading source: %s==%s (%s)", package.name, package.version, package.ecosystem
    )
    if package.ecosystem == "pypi":
        return await _download_pypi_source(package)
    elif package.ecosystem == "npm":
        return await _download_npm_source(package)
    elif package.ecosystem == "pub":
        return await _download_pub_source(package)
    else:
        raise ValueError(f"Unsupported ecosystem: {package.ecosystem}")


async def _download_pypi_source(package: PackageInfo) -> dict[str, str]:
    """Download PyPI sdist/wheel and extract text files."""
    url = f"{PYPI_API}/{package.name}/{package.version}/json"
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(url)
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

    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        resp = await client.get(download_url)
        resp.raise_for_status()
        content = resp.content
        if len(content) > MAX_ARCHIVE_SIZE:
            raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    return _extract_archive(content, download_url)


async def _download_npm_source(package: PackageInfo) -> dict[str, str]:
    """Download npm tarball and extract text files."""
    url = f"{NPM_API}/{package.name}/{package.version}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()

    tarball_url = data.get("dist", {}).get("tarball")
    if not tarball_url:
        return {}

    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        resp = await client.get(tarball_url)
        resp.raise_for_status()
        content = resp.content
        if len(content) > MAX_ARCHIVE_SIZE:
            raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    return _extract_archive(content, tarball_url)


async def _download_pub_source(package: PackageInfo) -> dict[str, str]:
    """Download pub.dev tarball and extract text files."""
    url = f"{PUB_API}/{package.name}/versions/{package.version}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()

    tarball_url = data.get("archive_url")
    if not tarball_url:
        return {}

    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        resp = await client.get(tarball_url)
        resp.raise_for_status()
        content = resp.content
        if len(content) > MAX_ARCHIVE_SIZE:
            raise ValueError(f"Archive too large: {len(content)} bytes (max {MAX_ARCHIVE_SIZE})")

    return _extract_archive(content, tarball_url)


def _is_path_safe(name: str) -> bool:
    """Reject path traversal and absolute paths."""
    if not name or name.startswith("/") or ".." in name.split("/"):
        return False
    return True


def _extract_archive(content: bytes, filename: str) -> dict[str, str]:
    """Extract text files from tar.gz or zip/whl archive."""
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
    }
    max_file_size = 512 * 1024  # 512KB per file

    try:
        if filename.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile() or member.size > max_file_size:
                        continue
                    if not _is_path_safe(member.name):
                        continue
                    suffix = Path(member.name).suffix.lower()
                    if suffix not in text_extensions:
                        continue
                    f = tar.extractfile(member)
                    if f:
                        try:
                            files[member.name] = f.read().decode("utf-8", errors="replace")
                        except Exception:
                            pass
        elif filename.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > max_file_size:
                        continue
                    if not _is_path_safe(info.filename):
                        continue
                    suffix = Path(info.filename).suffix.lower()
                    if suffix not in text_extensions:
                        continue
                    try:
                        files[info.filename] = zf.read(info.filename).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        pass
    except Exception:
        pass

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


def read_local_source(path: Path) -> str:
    """Read source code from a local file or directory for analysis."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if path.is_file():
        return path.read_text(errors="replace")

    cumulative_size = 0
    parts: list[str] = []
    for root_str, dirs, files in os.walk(path):
        # Skip hidden / non-essential directories in-place so os.walk won't descend
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        root = Path(root_str)
        for fname in sorted(files):
            f = root / fname
            if f.suffix in SKIP_EXTENSIONS:
                continue
            try:
                size = f.stat().st_size
                cumulative_size += size
                if cumulative_size > MAX_LOCAL_SOURCE_SIZE:
                    logger.warning(
                        "Local source size limit reached (%d bytes), stopping read",
                        MAX_LOCAL_SOURCE_SIZE,
                    )
                    return "\n\n".join(parts)
                text = f.read_text(errors="replace")
                parts.append(f"# --- {f.relative_to(path)} ---\n{text}")
            except (OSError, UnicodeDecodeError):
                continue
    return "\n\n".join(parts)


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

_HREF_RE = re.compile(r'href="([^"]+\.tar\.gz)"', re.IGNORECASE)


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
