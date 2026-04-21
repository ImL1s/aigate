"""Unit tests for BirdcageBackend.check_available()."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from aigate.sandbox.birdcage_backend import BirdcageBackend


@pytest.fixture()
def backend() -> BirdcageBackend:
    return BirdcageBackend()


def test_birdcage_absent_returns_false(backend: BirdcageBackend) -> None:
    with patch("aigate.sandbox.birdcage_backend.shutil.which", return_value=None):
        assert backend.check_available() is False


def test_linux_no_observer_returns_false(backend: BirdcageBackend) -> None:
    with (
        patch("aigate.sandbox.birdcage_backend.shutil.which", return_value="/usr/bin/birdcage"),
        patch("aigate.sandbox.birdcage_backend.platform.system", return_value="Linux"),
        patch(
            "aigate.sandbox.birdcage_backend.detect_linux_connect_observer",
            return_value=None,
        ),
    ):
        assert backend.check_available() is False


def test_linux_with_strace_observer_returns_true(backend: BirdcageBackend) -> None:
    with (
        patch("aigate.sandbox.birdcage_backend.shutil.which", return_value="/usr/bin/birdcage"),
        patch("aigate.sandbox.birdcage_backend.platform.system", return_value="Linux"),
        patch(
            "aigate.sandbox.birdcage_backend.detect_linux_connect_observer",
            return_value="strace",
        ),
    ):
        assert backend.check_available() is True


def test_macos_returns_true_without_observer(backend: BirdcageBackend) -> None:
    with (
        patch("aigate.sandbox.birdcage_backend.shutil.which", return_value="/usr/bin/birdcage"),
        patch("aigate.sandbox.birdcage_backend.platform.system", return_value="Darwin"),
    ):
        assert backend.check_available() is True
