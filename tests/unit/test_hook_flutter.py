"""Tests for Flutter/Dart/CocoaPods/fvm interception in pretool-hook.sh.

Same testing strategy as test_hook_script.py: feed JSON via stdin, check stdout.
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


# ---------------------------------------------------------------------------
# flutter pub add / dart pub add → check specific package
# ---------------------------------------------------------------------------


class TestFlutterPubAdd:
    """flutter pub add <pkg> should emit check for the package."""

    def test_flutter_pub_add_http(self):
        r = _run_hook("flutter pub add http", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "http" in output["reason"]

    def test_flutter_pub_add_multiple(self):
        r = _run_hook("flutter pub add dio http", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"

    def test_dart_pub_add_dio(self):
        r = _run_hook("dart pub add dio", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "dio" in output["reason"]

    def test_flutter_pub_add_with_flags(self):
        """Flags like --dev should be skipped, package name extracted."""
        r = _run_hook("flutter pub add --dev mockito", fake_aigate=BLOCKING_AIGATE)
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "mockito" in output["reason"]


# ---------------------------------------------------------------------------
# flutter pub get / dart pub get → scan pubspec.lock
# ---------------------------------------------------------------------------


class TestFlutterPubGet:
    """Bare flutter/dart pub get should scan pubspec.lock."""

    def test_flutter_pub_get_scans_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "pubspec.lock").write_text("packages:\n  http:\n")
            r = _run_hook(
                "flutter pub get",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=tmp_path,
            )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "pubspec.lock" in output["reason"]

    def test_dart_pub_get_scans_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "pubspec.lock").write_text("packages:\n  dio:\n")
            r = _run_hook(
                "dart pub get",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=tmp_path,
            )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "pubspec.lock" in output["reason"]

    def test_flutter_pub_get_no_lockfile_skips(self):
        """If pubspec.lock does not exist, should pass through silently."""
        with tempfile.TemporaryDirectory() as tmp:
            r = _run_hook(
                "flutter pub get",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=Path(tmp),
            )
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# pod install / pod update → scan Podfile.lock
# ---------------------------------------------------------------------------


class TestPodInstall:
    """pod install/update should scan Podfile.lock."""

    def test_pod_install_scans_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "Podfile.lock").write_text("PODS:\n  - Alamofire\n")
            r = _run_hook(
                "pod install",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=tmp_path,
            )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "Podfile.lock" in output["reason"]

    def test_pod_update_scans_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "Podfile.lock").write_text("PODS:\n  - Firebase\n")
            r = _run_hook(
                "pod update",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=tmp_path,
            )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "Podfile.lock" in output["reason"]

    def test_pod_install_uses_cocoapods_ecosystem(self):
        """pod install should pass ecosystem=cocoapods, not pub (M-3)."""
        # Fake aigate that echoes all arguments in the reason field
        eco_check_aigate = (
            'echo \'{"decision":"malicious","exit_code":2,"reason":"args=\'"$*"\'"}\''
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "Podfile.lock").write_text("PODS:\n  - Alamofire\n")
            r = _run_hook(
                "pod install",
                fake_aigate=eco_check_aigate,
                cwd=tmp_path,
            )
        output = json.loads(r.stdout.strip())
        assert output["decision"] == "block"
        assert "cocoapods" in output["reason"]

    def test_pod_install_no_lockfile_skips(self):
        """If Podfile.lock does not exist, should pass through silently."""
        with tempfile.TemporaryDirectory() as tmp:
            r = _run_hook(
                "pod install",
                fake_aigate=SCAN_BLOCKING_AIGATE,
                cwd=Path(tmp),
            )
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# fvm install → should be ignored (safe, Flutter SDK management)
# ---------------------------------------------------------------------------


class TestFvmIgnored:
    """fvm install should NOT trigger aigate."""

    def test_fvm_install_version(self):
        r = _run_hook("fvm install 3.29.0", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_fvm_install_stable(self):
        r = _run_hook("fvm install stable", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Non-install flutter/dart commands → should be ignored
# ---------------------------------------------------------------------------


class TestFlutterNonInstall:
    """Non-install flutter/dart commands should pass through."""

    def test_flutter_build_ios(self):
        r = _run_hook("flutter build ios", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_flutter_run(self):
        r = _run_hook("flutter run", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_dart_analyze(self):
        r = _run_hook("dart analyze", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_flutter_clean(self):
        r = _run_hook("flutter clean", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""

    def test_pod_repo_update(self):
        """pod repo update is not install/update — should skip."""
        r = _run_hook("pod repo update", fake_aigate=BLOCKING_AIGATE)
        assert r.returncode == 0
        assert r.stdout.strip() == ""
