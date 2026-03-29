"""Tests for Cargo (Rust) interception in pretool-hook.sh.

Same testing strategy as test_hook_flutter.py: feed JSON via stdin, check stdout.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HOOK_SCRIPT = PROJECT_ROOT / "scripts" / "pretool-hook.sh"

DEFAULT_SAFE_AIGATE = (
    "#!/usr/bin/env zsh\n"
    """echo '{"decision":"safe","exit_code":0,"reason":"safe"}'\n"""
)


def _make_input(command: str) -> str:
    return json.dumps({"tool_input": {"command": command}})


def _run_hook(
    command: str,
    *,
    fake_aigate: str | None = None,
    timeout: int = 10,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    fd, fake_bin_path = tempfile.mkstemp(prefix="aigate_test_", suffix=".sh")
    try:
        content = (
            f"#!/usr/bin/env zsh\n{fake_aigate}\n"
            if fake_aigate is not None
            else DEFAULT_SAFE_AIGATE
        )
        os.write(fd, content.encode())
        os.close(fd)
        os.chmod(fake_bin_path, 0o755)
        env["AIGATE_BIN"] = fake_bin_path

        result = subprocess.run(
            ["zsh", str(HOOK_SCRIPT)],
            input=_make_input(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd or PROJECT_ROOT,
        )
    finally:
        try:
            os.unlink(fake_bin_path)
        except OSError:
            pass
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BLOCKING_AIGATE = textwrap.dedent("""\
    echo '{"decision":"malicious","exit_code":2,"reason":"blocked by test"}'
""")


# ---------------------------------------------------------------------------
# cargo add <crate> → check specific crate
# ---------------------------------------------------------------------------


class TestCargoAdd:
    """cargo add <crate> should emit check for the crate."""

    def test_cargo_add_serde(self):
        r = _run_hook("cargo add serde", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "serde" in output["reason"]

    def test_cargo_add_multiple(self):
        r = _run_hook("cargo add tokio serde", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"

    def test_cargo_add_with_features_flag(self):
        """--features is a boolean-style flag, crate name should still be extracted."""
        r = _run_hook("cargo add serde --features derive", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "serde" in output["reason"]


# ---------------------------------------------------------------------------
# cargo install <crate> → check specific crate
# ---------------------------------------------------------------------------


class TestCargoInstall:
    """cargo install <crate> should emit check for the crate."""

    def test_cargo_install_ripgrep(self):
        r = _run_hook("cargo install ripgrep", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "ripgrep" in output["reason"]

    def test_cargo_install_multiple(self):
        r = _run_hook("cargo install cargo-edit cargo-watch", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"


# ---------------------------------------------------------------------------
# Flags that take a value should be skipped (--git, --path, etc.)
# ---------------------------------------------------------------------------


class TestCargoSkipFlags:
    """Flags like --git, --path, --registry should skip their value."""

    def test_cargo_add_git_skipped(self):
        """cargo add --git <url> should not treat the URL as a crate name."""
        r = _run_hook("cargo add --git https://github.com/foo/bar", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_cargo_add_path_skipped(self):
        """cargo add --path ./local-crate should not trigger check."""
        r = _run_hook("cargo add --path ./local-crate", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_cargo_install_version_skipped(self):
        """cargo install ripgrep --version 14.0.0 should check ripgrep but not 14.0.0."""
        r = _run_hook("cargo install ripgrep --version 14.0.0", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "ripgrep" in output["reason"]
        # "14.0.0" should NOT appear as a blocked package
        assert "14.0.0" not in output["reason"]

    def test_cargo_add_branch_skipped(self):
        """--branch value should be skipped."""
        r = _run_hook(
            "cargo add --git https://example.com/foo --branch main",
            fake_aigate=BLOCKING_AIGATE,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_cargo_add_registry_skipped(self):
        """--registry value should be skipped."""
        r = _run_hook("cargo add serde --registry my-registry", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "serde" in output["reason"]
        assert "my-registry" not in output["reason"]

    def test_cargo_add_tag_skipped(self):
        """--tag value should be skipped."""
        r = _run_hook(
            "cargo add --git https://example.com/foo --tag v1.0",
            fake_aigate=BLOCKING_AIGATE,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_cargo_add_rev_skipped(self):
        """--rev value should be skipped."""
        r = _run_hook(
            "cargo add --git https://example.com/foo --rev abc123",
            fake_aigate=BLOCKING_AIGATE,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Non-install cargo commands → should be ignored
# ---------------------------------------------------------------------------


class TestCargoNonInstall:
    """Non-install cargo commands should pass through silently."""

    def test_cargo_build(self):
        r = _run_hook("cargo build", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_cargo_test(self):
        r = _run_hook("cargo test", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_cargo_run(self):
        r = _run_hook("cargo run", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_cargo_clippy(self):
        r = _run_hook("cargo clippy", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_cargo_fmt(self):
        r = _run_hook("cargo fmt", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""
