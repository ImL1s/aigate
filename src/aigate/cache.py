"""File-based analysis cache for aigate."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path

from .models import AnalysisReport


def _cache_dir(config_cache_dir: str) -> Path:
    p = Path(config_cache_dir).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cache_key(name: str, version: str, ecosystem: str) -> str:
    raw = f"{ecosystem}:{name}:{version}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_cached(
    name: str,
    version: str,
    ecosystem: str,
    cache_dir: str,
    ttl_hours: int,
) -> dict | None:
    """Return cached analysis dict or None if missing/expired."""
    d = _cache_dir(cache_dir)
    key = _cache_key(name, version, ecosystem)
    path = d / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > ttl_hours * 3600:
            path.unlink(missing_ok=True)
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def set_cached(
    name: str,
    version: str,
    ecosystem: str,
    report: AnalysisReport,
    cache_dir: str,
) -> None:
    """Write analysis result to cache."""
    d = _cache_dir(cache_dir)
    key = _cache_key(name, version, ecosystem)
    path = d / f"{key}.json"
    data = asdict(report)
    data["_cached_at"] = time.time()
    try:
        path.write_text(json.dumps(data, default=str))
    except OSError:
        pass
