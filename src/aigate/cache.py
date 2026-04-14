"""File-based analysis cache for aigate."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from .models import AnalysisReport

logger = logging.getLogger(__name__)


def _cache_dir(config_cache_dir: str) -> Path:
    p = Path(config_cache_dir).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cache_key(name: str, version: str, ecosystem: str, provenance: str = "registry") -> str:
    raw = f"{ecosystem}:{name}:{version}:{provenance}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_cached(
    name: str,
    version: str,
    ecosystem: str,
    cache_dir: str,
    ttl_hours: int,
    provenance: str = "registry",
) -> dict | None:
    """Return cached analysis dict or None if missing/expired."""
    d = _cache_dir(cache_dir)
    key = _cache_key(name, version, ecosystem, provenance)
    path = d / f"{key}.json"
    if not path.exists():
        logger.debug("Cache miss: %s/%s/%s", ecosystem, name, version)
        return None
    try:
        data = json.loads(path.read_text())
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > ttl_hours * 3600:
            logger.debug("Cache expired: %s/%s/%s", ecosystem, name, version)
            path.unlink(missing_ok=True)
            return None
        logger.debug("Cache hit: %s/%s/%s", ecosystem, name, version)
        return data
    except (json.JSONDecodeError, OSError):
        return None


def set_cached(
    name: str,
    version: str,
    ecosystem: str,
    report: AnalysisReport,
    cache_dir: str,
    provenance: str = "registry",
) -> None:
    """Write analysis result to cache using atomic write.

    Writes to a temporary file first, then atomically replaces the target.
    This prevents concurrent readers from seeing partial/corrupt JSON.
    """
    d = _cache_dir(cache_dir)
    key = _cache_key(name, version, ecosystem, provenance)
    path = d / f"{key}.json"
    data = asdict(report)
    data["_cached_at"] = time.time()
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=d, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            fd = None  # os.fdopen takes ownership of fd
            json.dump(data, f, default=str)
        os.replace(tmp_path, path)  # Atomic on POSIX
        tmp_path = None  # Successfully replaced, no cleanup needed
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
