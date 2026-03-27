"""Tests for the pretool-hook.sh shell script.

We test the hook by feeding it JSON via stdin and checking stdout/exit code.
The hook calls `aigate check` — we mock that by injecting a fake aigate script.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HOOK_SCRIPT = PROJECT_ROOT / "scripts" / "pretool-hook.sh"


def _make_input(command: str) -> str:
    """Build the JSON that Claude Code sends to a PreToolUse hook."""
    return json.dumps({"tool_input": {"command": command}})


def _run_hook(
    command: str,
    *,
    fake_aigate: str | None = None,
    timeout: int = 10,
) -> subprocess.CompletedProcess:
    """Run pretool-hook.sh with a given command string.

    Args:
        command: The shell command to embed in tool_input.
        fake_aigate: Optional shell script body for a fake aigate binary.
                     If None, a default "always safe" stub is used.
    """
    env = os.environ.copy()

    if fake_aigate is not None:
        # Create a temp fake aigate binary
        fake_bin = PROJECT_ROOT / ".test_fake_aigate"
        fake_bin.write_text(f"#!/usr/bin/env zsh\n{fake_aigate}\n")
        fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
        env["AIGATE_BIN"] = str(fake_bin)
    else:
        # Default: aigate that outputs safe JSON
        fake_bin = PROJECT_ROOT / ".test_fake_aigate"
        fake_bin.write_text(textwrap.dedent("""\
            #!/usr/bin/env zsh
            echo '{"prefilter":{"risk_level":"none","reason":"safe"}}'
        """))
        fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
        env["AIGATE_BIN"] = str(fake_bin)

    result = subprocess.run(
        ["zsh", str(HOOK_SCRIPT)],
        input=_make_input(command),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    # Cleanup
    fake_bin.unlink(missing_ok=True)
    return result


# ---------------------------------------------------------------------------
# Skip / passthrough tests (hook should output nothing and exit 0)
# ---------------------------------------------------------------------------

class TestSkipCases:
    """Commands that the hook should ignore (allow silently)."""

    def test_non_install_command(self):
        """Regular shell commands should pass through."""
        r = _run_hook("ls -la")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_install_requirements(self):
        """pip install -r requirements.txt should be skipped."""
        r = _run_hook("pip install -r requirements.txt")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_install_dot(self):
        """pip install . (local install) should be skipped."""
        r = _run_hook("pip install .")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_install_editable_dot(self):
        """pip install -e . should be skipped."""
        r = _run_hook("pip install -e .")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_install_upgrade_pip(self):
        """pip install --upgrade pip should be skipped (system package)."""
        r = _run_hook("pip install --upgrade pip")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_install_upgrade_setuptools(self):
        """pip install --upgrade setuptools should be skipped."""
        r = _run_hook("pip install --upgrade setuptools")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_bare_npm_install(self):
        """Bare `npm install` (no package name) should be skipped."""
        r = _run_hook("npm install")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_git_command(self):
        """Non-package-manager commands should pass through."""
        r = _run_hook("git status")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_empty_command(self):
        """Empty command should pass through."""
        r = _run_hook("")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_list(self):
        """pip list is not install — should skip."""
        r = _run_hook("pip list")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_install_local_path(self):
        """pip install ./local_pkg should be skipped."""
        r = _run_hook("pip install ./my_package")
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Safe package tests (aigate returns safe → hook outputs nothing)
# ---------------------------------------------------------------------------

class TestSafePackages:
    """When aigate says the package is safe, the hook should allow silently."""

    def test_pip_install_single_safe(self):
        r = _run_hook("pip install requests")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_install_with_version(self):
        r = _run_hook("pip install requests==2.31.0")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_npm_install_safe(self):
        r = _run_hook("npm install express")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_npm_i_shorthand(self):
        r = _run_hook("npm i lodash")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_yarn_add_safe(self):
        r = _run_hook("yarn add react")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pnpm_add_safe(self):
        r = _run_hook("pnpm add vue")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip3_install(self):
        r = _run_hook("pip3 install flask")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_python_m_pip_install(self):
        r = _run_hook("python -m pip install django")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_uv_pip_install(self):
        r = _run_hook("uv pip install httpx")
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Blocked package tests (aigate returns critical/high → hook blocks)
# ---------------------------------------------------------------------------

class TestBlockedPackages:
    """When aigate flags a package as critical/high, the hook should block."""

    CRITICAL_AIGATE = textwrap.dedent("""\
        echo '{"prefilter":{"risk_level":"critical","reason":"blocklisted package"}}'
    """)

    HIGH_AIGATE = textwrap.dedent("""\
        echo '{"prefilter":{"risk_level":"high","reason":"typosquat of requests"}}'
    """)

    def test_pip_install_blocked_critical(self):
        r = _run_hook("pip install evil-pkg", fake_aigate=self.CRITICAL_AIGATE)
        assert r.returncode == 0  # hook itself exits 0, but outputs block JSON
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "evil-pkg" in output["reason"]

    def test_pip_install_blocked_high(self):
        r = _run_hook("pip install requets", fake_aigate=self.HIGH_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "requets" in output["reason"]

    def test_npm_install_blocked(self):
        r = _run_hook("npm install evil-package", fake_aigate=self.CRITICAL_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"

    def test_multiple_packages_one_blocked(self):
        """When checking multiple packages, all should be checked.

        If the fake aigate always returns critical, all packages get blocked.
        """
        r = _run_hook("pip install safe-pkg evil-pkg", fake_aigate=self.CRITICAL_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        # Both packages should appear (since fake aigate blocks all)
        assert "safe-pkg" in output["reason"] or "evil-pkg" in output["reason"]

    def test_blocked_json_structure(self):
        """Verify the output JSON has the required fields."""
        r = _run_hook("pip install bad-lib", fake_aigate=self.CRITICAL_AIGATE)
        output = json.loads(r.stdout.strip())
        assert "decision" in output
        assert "reason" in output
        assert output["decision"] == "block"


# ---------------------------------------------------------------------------
# Medium/Low risk → allow (only critical/high should block)
# ---------------------------------------------------------------------------

class TestAllowedRiskLevels:
    """Medium and low risk should pass through (not block)."""

    MEDIUM_AIGATE = textwrap.dedent("""\
        echo '{"prefilter":{"risk_level":"medium","reason":"some signals"}}'
    """)

    LOW_AIGATE = textwrap.dedent("""\
        echo '{"prefilter":{"risk_level":"low","reason":"minor signals"}}'
    """)

    def test_medium_risk_allowed(self):
        r = _run_hook("pip install some-pkg", fake_aigate=self.MEDIUM_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_low_risk_allowed(self):
        r = _run_hook("pip install another-pkg", fake_aigate=self.LOW_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Edge cases: selective blocking with smart fake aigate
# ---------------------------------------------------------------------------

class TestSelectiveBlocking:
    """Test that the hook correctly checks each package individually."""

    # This fake aigate blocks only packages containing "evil"
    SELECTIVE_AIGATE = textwrap.dedent("""\
        # Read all args, find the package name (the argument after 'check')
        found_check=false
        pkg=""
        for arg in "$@"; do
          if $found_check && [[ "$arg" != -* ]]; then
            pkg="$arg"
            break
          fi
          if [[ "$arg" == "check" ]]; then
            found_check=true
          fi
        done
        if [[ "$pkg" == *evil* ]]; then
          echo '{"prefilter":{"risk_level":"critical","reason":"known malicious"}}'
        else
          echo '{"prefilter":{"risk_level":"none","reason":"safe"}}'
        fi
    """)

    def test_mixed_packages_only_evil_blocked(self):
        r = _run_hook("pip install requests evil-pkg flask", fake_aigate=self.SELECTIVE_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "evil-pkg" in output["reason"]

    def test_all_safe_packages_pass(self):
        r = _run_hook("pip install requests flask django", fake_aigate=self.SELECTIVE_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Command variations
# ---------------------------------------------------------------------------

class TestCommandVariations:
    """Various forms of pip/npm commands."""

    def test_pip_with_flags_before_package(self):
        """pip install --no-cache-dir requests"""
        r = _run_hook("pip install --no-cache-dir requests")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_with_index_url(self):
        """pip install -i https://pypi.org/simple requests"""
        r = _run_hook("pip install -i https://pypi.org/simple requests")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_npm_install_save_dev(self):
        """npm install --save-dev typescript"""
        r = _run_hook("npm install --save-dev typescript")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_npm_scoped_package(self):
        """npm install @types/node"""
        r = _run_hook("npm install @types/node")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_chained_command_with_pip(self):
        """cd /tmp && pip install requests"""
        r = _run_hook("cd /tmp && pip install requests")
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pip_install_wheel(self):
        """pip install --upgrade wheel should be skipped (system package)."""
        r = _run_hook("pip install --upgrade wheel")
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Malformed / error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Hook should handle errors gracefully (allow on error)."""

    FAILING_AIGATE = textwrap.dedent("""\
        exit 1
    """)

    def test_aigate_failure_allows(self):
        """If aigate fails, the hook should allow (fail-open)."""
        r = _run_hook("pip install some-pkg", fake_aigate=self.FAILING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_malformed_json_input(self):
        """If stdin is not valid JSON, exit gracefully."""
        env = os.environ.copy()
        fake_bin = PROJECT_ROOT / ".test_fake_aigate"
        fake_bin.write_text("#!/usr/bin/env zsh\necho '{}'\n")
        fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
        env["AIGATE_BIN"] = str(fake_bin)

        result = subprocess.run(
            ["zsh", str(HOOK_SCRIPT)],
            input="not valid json",
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        fake_bin.unlink(missing_ok=True)
        # Should exit 0 (allow) even on bad input
        assert result.returncode == 0
