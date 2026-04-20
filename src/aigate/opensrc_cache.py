"""opensrc-compatible cache emission — aigate as producer.

Phase 1 of opensrc-integration-plan. aigate writes scanned tarball bytes to
``~/.opensrc/repos/<host>/<owner>/<repo>/<version>/`` matching opensrc's real
git-based layout (verified via live probe — see ``.omc/plans/opensrc-probe.md``).

Key invariants:

* Pure Python — no ``npx opensrc`` shell-out.
* Atomic-replace idiom for ``sources.json`` writes (tempfile + ``os.replace``),
  matching ``cache.py:76-83``. No flock.
* 3-retry optimistic concurrency via ``asyncio.to_thread`` for async callers.
* Per-package ``aigate-provenance.json`` sentinel records tarball SHA256 so
  re-emits are idempotent and opensrc-written bytes are never silently
  overwritten (collision policy, §3.1 T-COL-1..6).
* ``should_emit`` gates: config enabled + CLI flag + verdict != MALICIOUS +
  ``source_unavailable != True`` + collision policy approves.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config, EmitOpensrcConfig
from .models import AnalysisReport, OpensrcEmitResult, PackageInfo, RiskLevel, Verdict

logger = logging.getLogger(__name__)

SENTINEL_FILENAME = "aigate-provenance.json"
SOURCES_JSON = "sources.json"
MAX_RETRIES = 3
BACKOFF_BASE = 0.05  # 50ms base, exponential: 50/100/200 + jitter

# Supported git hosts for URL parsing — mirrors _extract_repo_url()
_GIT_HOST_RE = re.compile(
    r"(?:git\+)?(?:https?://|git@)(?P<host>github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)"
    r"[/:](?P<owner>[^/]+)/(?P<repo>[^/\s#?]+?)(?:\.git)?(?:[/#?].*)?$"
)


@dataclass(frozen=True)
class EmitAction:
    """Result of a collision-policy evaluation."""

    write: bool
    reason: str
    update_timestamp_only: bool = False  # Idempotent same-SHA re-emit


def default_cache_root() -> Path:
    """Return the default opensrc cache root (``~/.opensrc``)."""
    return Path.home() / ".opensrc"


def _resolve_cache_root(emit_config: EmitOpensrcConfig) -> Path:
    if emit_config.cache_dir:
        return Path(emit_config.cache_dir).expanduser()
    return default_cache_root()


def _normalize_ecosystem(ecosystem: str) -> str:
    """Emit opensrc ``registry`` enum — lowercase, as-is per coordinator decision.

    Open-questions #8 (2026-04-20): emit as-is lowercase ecosystem name (``pub``,
    ``cocoapods``, ``crates``, ``jsr``). Stock opensrc may filter non-native
    entries; aigate-provenance sibling file still preserves fidelity.
    """
    return ecosystem.lower().strip()


def derive_path(package: PackageInfo) -> tuple[str, bool]:
    """Derive opensrc-compatible path for a package.

    Returns ``(relative_path, used_fallback)``. The relative path is always
    relative to ``~/.opensrc/``. Prefers ``repos/<host>/<owner>/<repo>/<ver>/``
    (git-based, opensrc-native). Falls back to
    ``repos/registry.<ecosystem>/<pkg>/<ver>/`` when no git URL is known
    (architect-approved fallback shape).
    """
    version = package.version or "latest"

    parsed = _parse_git_url(package.repository or "")
    if parsed:
        host, owner, repo = parsed
        return f"repos/{host}/{owner}/{repo}/{version}", False

    # Fallback: registry-local path for non-git packages
    eco = _normalize_ecosystem(package.ecosystem) or "unknown"
    # Preserve @scope/name as-is (matches opensrc's npm-style spec),
    # but keep the segment filesystem-safe.
    safe_name = package.name.strip()
    # Strip any leading slashes / .. while preserving @scope/name
    safe_name = safe_name.replace("..", "").lstrip("/")
    return f"repos/registry.{eco}/{safe_name}/{version}", True


def _parse_git_url(url: str) -> tuple[str, str, str] | None:
    """Extract ``(host, owner, repo)`` from a git URL, or None."""
    if not url:
        return None
    # Normalize ``git+https://...`` and ``git://...`` prefixes
    url = url.strip()
    if url.startswith("git://"):
        url = "https://" + url[len("git://") :]
    match = _GIT_HOST_RE.search(url)
    if not match:
        return None
    return match.group("host"), match.group("owner"), match.group("repo")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> dict[str, Any] | None:
    """Read a JSON file, returning None on error (corruption / missing)."""
    if not path.exists():
        return None
    try:
        raw = path.read_text()
        if not raw.strip():
            return None
        return json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read %s (%s); treating as empty", path, exc)
        return None


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically — tempfile + os.replace, matching cache.py:76-83."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = None
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            fd = None  # os.fdopen takes ownership
            json.dump(data, f, default=str, indent=2)
        os.replace(tmp_path, path)
        tmp_path = None
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _collision_policy(
    target_dir: Path,
    incoming_sha256: str,
    incoming_verdict: Verdict,
    policy: str,
) -> EmitAction:
    """Decide whether to write bytes based on collision + policy (T-COL-1..6).

    Args:
        target_dir: ``~/.opensrc/repos/<...>/<version>/`` directory.
        incoming_sha256: sha256 of the tarball aigate just fetched.
        incoming_verdict: consensus verdict of the current scan.
        policy: one of ``refuse``, ``overwrite``, ``prefer-aigate``.

    Returns:
        ``EmitAction`` describing write/skip decision.
    """
    # Gate: never emit on MALICIOUS regardless of collision state (T-COL-6)
    if incoming_verdict == Verdict.MALICIOUS:
        return EmitAction(
            write=False,
            reason="verdict_malicious",
        )

    if not target_dir.exists():
        # T-COL-1 fresh directory
        return EmitAction(write=True, reason="fresh_directory")

    sentinel = target_dir / SENTINEL_FILENAME
    existing = _read_json(sentinel) if sentinel.exists() else None

    if existing is None:
        # Directory exists but no aigate sentinel -> opensrc-origin (or unknown)
        if policy == "overwrite":
            return EmitAction(write=True, reason="overwrite_forced")
        # T-COL-4 / T-COL-5 — default refuse, force only via policy
        return EmitAction(
            write=False,
            reason="collision_unknown_origin",
        )

    # Directory has an aigate sentinel from a prior scan
    existing_sha = existing.get("tarball_sha256")
    if existing_sha == incoming_sha256:
        # T-COL-2 idempotent no-op: same bytes already emitted
        return EmitAction(
            write=False,
            reason="idempotent_same_sha",
            update_timestamp_only=True,
        )

    # Different SHA — newer scan of same (name, version), e.g. tarball republish
    # T-COL-3: overwrite when verdict is SAFE / NEEDS_HUMAN_REVIEW
    # Policy `refuse` still allows self-overwrite (we own the sentinel)
    return EmitAction(write=True, reason="aigate_reemit")


def should_emit(
    report: AnalysisReport,
    config: Config,
    flag_override: bool | None = None,
) -> tuple[bool, str]:
    """Gate aigate→opensrc emission.

    Returns ``(emit, reason)``. ``reason`` is a short stable string suitable
    for logging / OpensrcEmitResult.

    Gates (from PRD §3.1 + open-questions #10):
        1. Config ``emit_opensrc.enabled`` is true OR ``flag_override`` is True.
        2. ``flag_override`` is not explicitly False.
        3. Consensus verdict is not MALICIOUS (and, per critic nit, not
           ERROR — no bytes to emit).
        4. No ``source_unavailable`` risk signal present (bytes not inspected).
    """
    # CLI flag: True forces on, False forces off, None defers to config
    if flag_override is False:
        return False, "flag_off"

    emit_config = config.emit_opensrc
    if flag_override is not True and not emit_config.enabled:
        return False, "disabled"

    if report.consensus and report.consensus.final_verdict == Verdict.MALICIOUS:
        return False, "verdict_malicious"

    if report.consensus and report.consensus.final_verdict == Verdict.ERROR:
        return False, "verdict_error"

    # Cross-ecosystem source_unavailable gate (open-questions #10)
    if _is_source_unavailable(report):
        return False, "source_unavailable"

    # Skip-AI fallthrough: when consensus is None (e.g. --skip-ai run) and
    # the prefilter alone flagged HIGH/CRITICAL, the package is malicious
    # by aigate's own exit code (2). Emitting those bytes to ~/.opensrc/
    # would turn the cache into a malware-distribution vector for AI agents
    # that read it. Reviewer IMP-4 / US-003.
    if report.consensus is None and report.prefilter.risk_level in (
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    ):
        return False, "prefilter_high_risk"

    return True, "ok"


def _is_source_unavailable(report: AnalysisReport) -> bool:
    """Detect ``source_unavailable`` flag anywhere in the report.

    Phase 3 (v2): ``PrefilterResult.source_unavailable`` is the authoritative
    structured flag. We *also* scan the legacy risk-signal strings for
    backward compatibility with pre-Phase-3 fixtures and consensus-level
    signals propagated from AI models.
    """
    if getattr(report.prefilter, "source_unavailable", False):
        return True
    needle = "source_unavailable"
    signals = list(report.prefilter.risk_signals or [])
    if report.consensus:
        signals.extend(report.consensus.risk_signals or [])
    for sig in signals:
        s = sig if isinstance(sig, str) else str(sig)
        if needle in s:
            return True
    return False


@dataclass
class EmitContext:
    """Bundle of inputs to ``emit_to_opensrc_cache``."""

    package: PackageInfo
    source_files: dict[str, str] = field(default_factory=dict)
    tarball_bytes: bytes | None = None
    report: AnalysisReport | None = None
    config: Config | None = None


def _compute_sha256(tarball_bytes: bytes | None, source_files: dict[str, str]) -> str:
    """Compute a deterministic SHA256 for provenance.

    Prefers the raw tarball bytes; falls back to a stable hash of the
    extracted file tree when tarball bytes are unavailable.
    """
    if tarball_bytes is not None:
        return hashlib.sha256(tarball_bytes).hexdigest()
    h = hashlib.sha256()
    for name in sorted(source_files):
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(source_files[name].encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()


def _write_source_files(target_dir: Path, source_files: dict[str, str]) -> int:
    """Write extracted source files under ``target_dir``. Returns file count."""
    count = 0
    for rel_path, content in source_files.items():
        # Strip any leading package-version/ prefix only if present — many
        # registry tarballs use ``<pkg>-<ver>/...`` top-level dirs; keep them
        # as-is for opensrc-compatibility. Security: reject traversal.
        if rel_path.startswith("/") or ".." in rel_path.split("/"):
            continue
        out = target_dir / rel_path
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8", errors="replace")
            count += 1
        except OSError as exc:
            logger.warning("Failed writing %s: %s", out, exc)
    return count


def _write_sentinel(
    target_dir: Path,
    package: PackageInfo,
    tarball_sha256: str,
    verdict: str,
    tarball_url: str | None = None,
) -> None:
    sentinel = target_dir / SENTINEL_FILENAME
    payload = {
        "producer": "aigate",
        "version": __version__,
        "source": "tarball",
        "tarball_url": tarball_url or "",
        "tarball_sha256": tarball_sha256,
        "ecosystem": _normalize_ecosystem(package.ecosystem),
        "package_name": package.name,
        "package_version": package.version,
        "fetched_at": _now_iso(),
        "scanned_at": _now_iso(),
        "scan_verdict": verdict,
    }
    _atomic_write_json(sentinel, payload)


_SOURCES_LOCK = None  # Lazily-initialized per-process lock for sources.json


def _get_sources_lock():
    """Lazy-init a threading.Lock to serialize same-process writers.

    Cross-process races remain bounded by atomic-replace + optimistic re-read;
    same-process thread races (from ``asyncio.to_thread``) are serialized here
    to guarantee merge correctness under ``asyncio.gather``.
    """
    global _SOURCES_LOCK
    if _SOURCES_LOCK is None:
        import threading

        _SOURCES_LOCK = threading.Lock()
    return _SOURCES_LOCK


SOURCES_LOCK_FILENAME = ".sources.json.lock"


def _update_sources_json(
    cache_root: Path,
    package: PackageInfo,
    rel_path: str,
) -> None:
    """Merge the current package entry into ``sources.json`` under a
    cross-process file lock.

    Concurrency model (Reviewer CRITICAL-1):

    * Same-process threads serialize via ``_SOURCES_LOCK`` (cheap, in-memory).
    * Cross-process writers serialize via ``fcntl.flock(LOCK_EX)`` on a
      sidecar lockfile (``.sources.json.lock``) for the *entire*
      read-modify-write critical section. POSIX only; aigate targets
      macOS + Linux. On Windows the flock call would fail and we'd fall
      back to optimistic concurrency (retry loop).
    * Atomic-replace (``tempfile`` + ``os.replace``) protects against
      torn writes within the locked window.

    Earlier (v1) implementation used a re-read drift check with
    optimistic-concurrency backoff. That had an unbounded TOCTOU window
    between the drift check and ``os.replace``: a probe with 8 worker
    processes lost ~56% of writes. flock fixes this for POSIX.
    """
    sources_path = cache_root / SOURCES_JSON
    lock_path = cache_root / SOURCES_LOCK_FILENAME
    registry = _normalize_ecosystem(package.ecosystem)

    cache_root.mkdir(parents=True, exist_ok=True)

    with _get_sources_lock():
        try:
            import fcntl  # POSIX-only — Windows fallback below
        except ImportError:
            fcntl = None  # type: ignore[assignment]

        # Open the sidecar lockfile in append-create mode so it always exists.
        with open(lock_path, "a+") as lock_f:
            locked = False
            if fcntl is not None:
                try:
                    fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
                    locked = True
                except OSError as exc:
                    logger.warning(
                        "flock(LOCK_EX) failed on %s (%s); falling back to optimistic concurrency",
                        lock_path,
                        exc,
                    )

            try:
                if locked:
                    # Real cross-process exclusion — single attempt suffices.
                    _merge_and_write_sources(sources_path, package, rel_path, registry)
                else:
                    # Optimistic-concurrency fallback (Windows, locked-down FS, etc.)
                    _merge_and_write_sources_optimistic(sources_path, package, rel_path, registry)
            finally:
                if locked and fcntl is not None:
                    try:
                        fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass


def _merge_and_write_sources(
    sources_path: Path,
    package: PackageInfo,
    rel_path: str,
    registry: str,
) -> None:
    """Single-attempt read-merge-write. Caller already holds the file lock."""
    before = _read_json(sources_path)
    snapshot = before if before is not None else {"updatedAt": "", "packages": []}
    packages = list(snapshot.get("packages") or [])

    now = _now_iso()
    merged = False
    for entry in packages:
        if (
            entry.get("name") == package.name
            and entry.get("version") == package.version
            and entry.get("registry") == registry
        ):
            entry["path"] = rel_path
            entry["fetchedAt"] = now
            merged = True
            break
    if not merged:
        packages.append(
            {
                "name": package.name,
                "version": package.version,
                "registry": registry,
                "path": rel_path,
                "fetchedAt": now,
            }
        )

    new_payload = {"updatedAt": now, "packages": packages}
    try:
        _atomic_write_json(sources_path, new_payload)
    except OSError as exc:
        logger.warning("sources.json write failed: %s", exc)


def _merge_and_write_sources_optimistic(
    sources_path: Path,
    package: PackageInfo,
    rel_path: str,
    registry: str,
) -> None:
    """Optimistic-concurrency fallback when flock isn't available.

    Best-effort only — see _update_sources_json docstring. Lossy under
    heavy cross-process contention, but better than nothing on platforms
    that don't expose ``fcntl.flock`` (Windows).
    """
    for attempt in range(MAX_RETRIES):
        before = _read_json(sources_path)
        before_sig = None if before is None else before.get("updatedAt")
        _merge_and_write_sources(sources_path, package, rel_path, registry)
        post = _read_json(sources_path)
        post_sig = None if post is None else post.get("updatedAt")
        # If our write made it through (post matches the timestamp we wrote),
        # we're done. Otherwise back off and retry.
        if post is not None and post_sig != before_sig:
            return
        time.sleep(BACKOFF_BASE * (2**attempt) + random.uniform(0, BACKOFF_BASE))

    logger.warning(
        "sources.json optimistic update exhausted %d retries for %s@%s",
        MAX_RETRIES,
        package.name,
        package.version,
    )


def emit_to_opensrc_cache(
    package: PackageInfo,
    source_files: dict[str, str],
    report: AnalysisReport,
    config: Config,
    overwrite_policy: str | None = None,
    tarball_bytes: bytes | None = None,
    tarball_url: str | None = None,
) -> OpensrcEmitResult:
    """Emit package bytes + sentinel + sources.json entry under ``~/.opensrc/``.

    Synchronous — wrap in ``asyncio.to_thread`` from async code.

    Args:
        package: metadata (ecosystem/name/version/repository).
        source_files: ``{relative_path: content}`` from ``resolver.download_source``.
        report: the scan report (verdict gating, provenance).
        config: aigate Config (cache_dir, on_collision).
        overwrite_policy: CLI override — one of ``never|always|when-aigate-wins``,
            mapping to emit_opensrc.on_collision {refuse, overwrite, prefer-aigate}.
            When None, defers to ``config.emit_opensrc.on_collision``.
        tarball_bytes: raw tarball for SHA256 (preferred over synthesized hash).
        tarball_url: registry URL, recorded in the sentinel.

    Returns:
        ``OpensrcEmitResult`` describing what happened.
    """
    emit_config = config.emit_opensrc
    cache_root = _resolve_cache_root(emit_config)

    # Map CLI --opensrc-overwrite to config.on_collision
    policy_map = {
        "never": "refuse",
        "always": "overwrite",
        "when-aigate-wins": "prefer-aigate",
    }
    policy = policy_map.get(overwrite_policy or "", emit_config.on_collision)
    if policy not in {"refuse", "overwrite", "prefer-aigate"}:
        policy = "refuse"

    rel_path, used_fallback = derive_path(package)
    target_dir = cache_root / rel_path

    verdict = Verdict.SAFE
    if report.consensus:
        verdict = report.consensus.final_verdict

    sha256 = _compute_sha256(tarball_bytes, source_files)
    action = _collision_policy(target_dir, sha256, verdict, policy)

    if not action.write and not action.update_timestamp_only:
        logger.info(
            "opensrc-emit skipped for %s@%s: %s",
            package.name,
            package.version,
            action.reason,
        )
        return OpensrcEmitResult(
            emitted=False,
            path=rel_path,
            reason=action.reason,
            sha256=None,
        )

    try:
        if action.write:
            target_dir.mkdir(parents=True, exist_ok=True)
            _write_source_files(target_dir, source_files)
            _write_sentinel(
                target_dir,
                package,
                tarball_sha256=sha256,
                verdict=verdict.value,
                tarball_url=tarball_url,
            )

        # Always update sources.json (even for idempotent same-SHA no-op we refresh fetchedAt)
        _update_sources_json(cache_root, package, rel_path)
    except OSError as exc:
        logger.warning(
            "opensrc-emit write failed for %s@%s: %s", package.name, package.version, exc
        )
        return OpensrcEmitResult(
            emitted=False,
            path=rel_path,
            reason=f"write_error: {exc}",
            sha256=sha256,
        )

    reason = "emitted" if action.write else action.reason
    logger.info(
        "opensrc-emit %s %s@%s -> %s%s",
        reason,
        package.name,
        package.version,
        rel_path,
        " (fallback path)" if used_fallback else "",
    )
    return OpensrcEmitResult(
        emitted=action.write,
        path=rel_path,
        reason=reason,
        sha256=sha256,
    )


def list_filesystem_outputs(emit_config: EmitOpensrcConfig) -> dict[str, Any]:
    """Summarize ``~/.opensrc/`` for ``aigate doctor``.

    Returns a dict with per-origin counts, last-write timestamp, and total
    size. Safe to call even when the cache dir doesn't exist.
    """
    cache_root = _resolve_cache_root(emit_config)
    summary: dict[str, Any] = {
        "cache_dir": str(cache_root),
        "exists": cache_root.exists(),
        "aigate_origin": 0,
        "opensrc_origin": 0,
        "total_packages": 0,
        "last_write": None,
        "sources_json_valid": False,
    }
    if not cache_root.exists():
        return summary

    sources = _read_json(cache_root / SOURCES_JSON)
    if sources is not None:
        summary["sources_json_valid"] = True
        summary["last_write"] = sources.get("updatedAt")
        summary["total_packages"] = len(sources.get("packages") or [])

    repos_root = cache_root / "repos"
    if repos_root.exists():
        for dirpath, _dirs, files in os.walk(repos_root):
            if SENTINEL_FILENAME in files:
                summary["aigate_origin"] += 1
            else:
                # A leaf directory without a sentinel is presumed opensrc-origin.
                # Heuristic: count only directories that look like version dirs
                # (i.e. parent is a repo dir, which itself has siblings only).
                p = Path(dirpath)
                if p != repos_root and any(
                    (p / f).is_file() for f in files if not f.endswith(".tmp")
                ):
                    # Is this a leaf version dir? Approximate: no subdirs present.
                    if not any((p / d).is_dir() for d in _dirs):
                        summary["opensrc_origin"] += 1

    return summary
