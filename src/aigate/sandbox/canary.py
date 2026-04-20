"""Per-run canary scheme for decoy bind-mounts (PRD v3.1 §3.2 P0-1).

A CanaryScheme is generated fresh for every sandbox run:

- A 128-bit random ``run_token`` is written to a set of canary files
  that are then bind-mounted (Linux) or exposed through a scratch
  ``$HOME`` (macOS) over the sensitive paths a credential-stealer
  would read (``~/.ssh/id_rsa``, ``~/.aws/credentials``, etc.).
- Any observed READ of a canary file → ``canary_touched(HIGH)`` signal.
- Any outbound appearance of the token → ``canary_exfil(HIGH)`` signal.

The ``scheme_version`` integer feeds ``policy_hash`` (PRD §3.8) so
bumping the canary path set or sinkhole domain set naturally invalidates
the sandbox output cache.
"""

from __future__ import annotations

import secrets as _stdlib_secrets
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Defaults — update ``CANARY_SCHEME_VERSION`` whenever these sets change
# ---------------------------------------------------------------------------
CANARY_SCHEME_VERSION: int = 1

# Canonical list of sensitive paths a credential-stealer reads at install
# time. Each entry becomes a decoy file under
# ``/tmp/aigate-decoy-<run>/`` that bind-mounts over the real path inside
# the sandbox. The backend is responsible for the bind-mount / scratch
# HOME redirection; CanaryScheme only DECLARES intent.
DEFAULT_CANARY_PATHS: tuple[str, ...] = (
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.aws/credentials",
    "~/.npmrc",
    "~/.pypirc",
    "~/.docker/config.json",
    "~/.gitconfig",
    "~/.netrc",
    "~/.config/gh/hosts.yml",
    "/etc/shadow",
)

# Decoy autostart dirs — persistence_write(HIGH) when the package writes
# anywhere under these paths inside the sandbox.
DEFAULT_DECOY_AUTOSTART_DIRS: tuple[str, ...] = (
    "~/.config/autostart",
    "~/Library/LaunchAgents",
    "/etc/cron.d",
    "~/.config/systemd/user",
)

# DNS names answered by the in-sandbox sinkhole so the exfil request
# lands in mitmproxy instead of egressing to the real host. Keep as a
# conservative list of common C2 / exfil endpoints observed in real
# campaigns.
DEFAULT_SINKHOLE_DOMAINS: tuple[str, ...] = (
    "api.amazonaws.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "pastebin.com",
    "discord.com",
    "discordapp.com",
    "telegram.org",
    "ipinfo.io",
    "checkip.amazonaws.com",
)


@dataclass(frozen=True)
class CanaryScheme:
    """Per-run canary scheme (PRD v3.1 §3.2 dataclass).

    ``scheme_version`` is deliberately decoupled from any aigate version
    bump: it is incremented ONLY when the canary path set, sinkhole
    domain set, or decoy autostart set changes — because those changes
    affect what the sandbox actually observes, and therefore must
    invalidate the §3.8 sandbox output cache. See §3.8 "Exact cache-key
    input bytes" for how ``scheme_version`` feeds ``policy_hash``.
    """

    scheme_version: int = CANARY_SCHEME_VERSION
    run_token: str = ""
    canary_paths: dict[str, str] = field(default_factory=dict)
    sinkhole_domains: tuple[str, ...] = ()
    decoy_autostart_dirs: tuple[str, ...] = ()

    def contains_path(self, path: str) -> bool:
        """True iff ``path`` matches a canary file or autostart decoy dir.

        Uses ``startswith`` for autostart dirs so nested writes (``~/.config/
        autostart/evil.desktop``) still flag. Exact match for canary file
        paths so reading the parent dir listing does not false-positive.
        """
        if not path:
            return False
        if path in self.canary_paths:
            return True
        for decoy_dir in self.decoy_autostart_dirs:
            if path == decoy_dir or path.startswith(decoy_dir.rstrip("/") + "/"):
                return True
        return False


def generate_canary_scheme(
    run_dir: str = "/tmp/aigate-decoy",
    canary_paths: tuple[str, ...] = DEFAULT_CANARY_PATHS,
    sinkhole_domains: tuple[str, ...] = DEFAULT_SINKHOLE_DOMAINS,
    decoy_autostart_dirs: tuple[str, ...] = DEFAULT_DECOY_AUTOSTART_DIRS,
) -> CanaryScheme:
    """Build a fresh ``CanaryScheme`` with a 128-bit random run token.

    Pure-data: does NOT create filesystem entries — that is the
    backend's job. This function only mints the scheme that the
    backend mount / scratch-HOME logic will consume.

    The returned mapping uses the canary path as the KEY (the
    sandbox-visible path the malicious package reads) and the decoy
    backing file as the VALUE (the real file the bind-mount points to).
    """
    token = _stdlib_secrets.token_hex(16)  # 128 bits → 32 lowercase hex chars
    # Use the token as part of the decoy directory so runs cannot
    # collide even if /tmp cleanup is lazy.
    backing_root = f"{run_dir.rstrip('/')}-{token}"
    mapping = {path: f"{backing_root}/{_safe_filename(path)}" for path in canary_paths}
    return CanaryScheme(
        scheme_version=CANARY_SCHEME_VERSION,
        run_token=token,
        canary_paths=mapping,
        sinkhole_domains=tuple(sinkhole_domains),
        decoy_autostart_dirs=tuple(decoy_autostart_dirs),
    )


def _safe_filename(path: str) -> str:
    """Derive a decoy-file basename from a sensitive path.

    Replaces path separators and home-prefix tilde with underscores so
    every canary path produces a unique, filesystem-safe name under the
    per-run decoy directory.
    """
    cleaned = path.lstrip("~/").lstrip("/")
    return cleaned.replace("/", "_").replace(".", "_") or "canary"
