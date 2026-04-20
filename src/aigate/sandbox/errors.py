"""Sandbox-specific exceptions (PRD v3.1 §3.1 ``errors.py``).

Kept in a tiny module so backend code can raise without pulling in the
rest of the sandbox package.
"""

from __future__ import annotations


class SandboxError(Exception):
    """Base class for all sandbox-related failures."""


class SandboxUnavailable(SandboxError):  # noqa: N818 — PRD §3.1 names
    """Requested sandbox runtime is not usable on this host.

    Raised by ``runtime_select.detect_available()`` / backend
    ``check_available()`` when Docker is missing, Landlock kernel support
    is absent, or the required image digest cannot be pulled. Consumers
    map this to ``needs_review`` via ``has_observation_failure()`` rather
    than silently falling through to SAFE.
    """


class SandboxTimeout(SandboxError):  # noqa: N818 — PRD §3.1 names
    """Sandbox execution exceeded the configured wall-clock budget.

    The partial trace captured up to the timeout SHOULD still be
    returned by the backend; this exception is only raised when no
    partial trace is recoverable.
    """


class SandboxEscape(SandboxError):  # noqa: N818 — PRD §3.1 names
    """Observer detected an attempt to break out of the sandbox.

    Strong signal: fail-closed, never downgrade to SAFE. Examples:
    - child process accessing host PID namespace it should not see,
    - write to a path that should have been bind-mounted to a decoy,
    - syscall blocked by seccomp profile that bypassed the allowlist.
    """
