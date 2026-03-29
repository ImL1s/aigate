"""Tests for Ruby/PHP/Go/.NET interception in pretool-hook.sh.

Same testing strategy as test_hook_cargo.py: feed JSON via stdin, check stdout.
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

SCAN_BLOCKING_AIGATE = textwrap.dedent("""\
    if [[ "$1" == "scan" ]]; then
      echo '{"decision":"malicious","exit_code":2,"reason":"lockfile blocked"}'
    else
      echo '{"decision":"safe","exit_code":0,"reason":"safe"}'
    fi
""")


# ===========================================================================
# Ruby: gem install, bundle add, bundle install
# ===========================================================================


class TestGemInstall:
    """gem install <gem> should emit check for the gem."""

    def test_gem_install_rails(self):
        r = _run_hook("gem install rails", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "rails" in output["reason"]

    def test_gem_install_multiple(self):
        r = _run_hook("gem install rails puma", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"

    def test_gem_install_with_version_flag(self):
        """--version value should be skipped."""
        r = _run_hook("gem install rails --version 7.1.0", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "rails" in output["reason"]
        assert "7.1.0" not in output["reason"]


class TestBundleAdd:
    """bundle add <gem> should emit check for the gem."""

    def test_bundle_add_puma(self):
        r = _run_hook("bundle add puma", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "puma" in output["reason"]

    def test_bundle_add_with_group(self):
        """--group value should be skipped — only rspec should be blocked."""
        r = _run_hook("bundle add rspec --group development", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "rspec" in output["reason"]
        assert "development" not in output["reason"]


class TestBundleInstall:
    """bundle install should scan Gemfile.lock."""

    def test_bundle_install_scans_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "Gemfile.lock").write_text("GEM\n  specs:\n    rails (7.1)\n")
            r = _run_hook(
                "bundle install",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=tmp_path,
            )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "Gemfile.lock" in output["reason"]

    def test_bundle_install_no_lockfile_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run_hook(
                "bundle install",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=Path(tmp),
            )
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ===========================================================================
# PHP: composer require, composer install
# ===========================================================================


class TestComposerRequire:
    """composer require <pkg> should emit check for the package."""

    def test_composer_require_guzzle(self):
        r = _run_hook("composer require guzzlehttp/guzzle", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "guzzlehttp/guzzle" in output["reason"]

    def test_composer_require_multiple(self):
        r = _run_hook(
            "composer require monolog/monolog phpunit/phpunit", fake_aigate=BLOCKING_AIGATE
        )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"

    def test_composer_require_with_dev_flag(self):
        """--dev flag should be skipped, package extracted."""
        r = _run_hook("composer require --dev phpunit/phpunit", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "phpunit/phpunit" in output["reason"]


class TestComposerInstall:
    """composer install should scan composer.lock."""

    def test_composer_install_scans_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "composer.lock").write_text('{"packages": []}')
            r = _run_hook(
                "composer install",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=tmp_path,
            )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "composer.lock" in output["reason"]

    def test_composer_install_no_lockfile_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run_hook(
                "composer install",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=Path(tmp),
            )
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ===========================================================================
# Go: go get, go install
# ===========================================================================


class TestGoGet:
    """go get <pkg> should emit check for the package."""

    def test_go_get_package(self):
        r = _run_hook("go get github.com/gin-gonic/gin", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "github.com/gin-gonic/gin" in output["reason"]

    def test_go_get_with_version(self):
        """go get pkg@version should strip version suffix."""
        r = _run_hook("go get github.com/gorilla/mux@v1.8.1", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "github.com/gorilla/mux" in output["reason"]
        assert "v1.8.1" not in output["reason"]

    def test_go_get_with_flag(self):
        """-u flag should be ignored."""
        r = _run_hook("go get -u github.com/gin-gonic/gin", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "github.com/gin-gonic/gin" in output["reason"]


class TestGoInstall:
    """go install <pkg> should emit check for the package."""

    def test_go_install_package(self):
        r = _run_hook("go install golang.org/x/tools/gopls@latest", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "golang.org/x/tools/gopls" in output["reason"]


class TestGoNonInstall:
    """Non-install go commands should pass through silently."""

    def test_go_build(self):
        r = _run_hook("go build ./...", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_go_test(self):
        r = _run_hook("go test ./...", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_go_run(self):
        r = _run_hook("go run main.go", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ===========================================================================
# .NET: dotnet add package
# ===========================================================================


class TestDotnetAddPackage:
    """dotnet add package <pkg> should emit check for the package."""

    def test_dotnet_add_package(self):
        r = _run_hook("dotnet add package Newtonsoft.Json", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "Newtonsoft.Json" in output["reason"]

    def test_dotnet_add_package_with_version(self):
        """--version value should be skipped."""
        r = _run_hook("dotnet add package Serilog --version 3.1.0", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "Serilog" in output["reason"]
        assert "3.1.0" not in output["reason"]

    def test_dotnet_add_project_package(self):
        """dotnet add <project> package <pkg> should also work."""
        r = _run_hook("dotnet add MyApp.csproj package AutoMapper", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "AutoMapper" in output["reason"]

    def test_dotnet_add_package_with_source(self):
        """--source value should be skipped."""
        r = _run_hook(
            "dotnet add package Polly --source https://nuget.org/v3/index.json",
            fake_aigate=BLOCKING_AIGATE,
        )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "Polly" in output["reason"]
        assert "https" not in output["reason"]


class TestDotnetNonPackage:
    """Non-package dotnet commands should pass through silently."""

    def test_dotnet_build(self):
        r = _run_hook("dotnet build", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_dotnet_run(self):
        r = _run_hook("dotnet run", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_dotnet_add_reference(self):
        """dotnet add reference should NOT trigger package check."""
        r = _run_hook("dotnet add reference ../Lib/Lib.csproj", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ===========================================================================
# Non-matching commands — should pass through for all ecosystems
# ===========================================================================


class TestNonMatchingCommands:
    """Random commands should not trigger any of the new patterns."""

    def test_ruby_command(self):
        r = _run_hook("ruby script.rb", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_php_command(self):
        r = _run_hook("php artisan migrate", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_go_mod_tidy(self):
        r = _run_hook("go mod tidy", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_dotnet_test(self):
        r = _run_hook("dotnet test", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""
