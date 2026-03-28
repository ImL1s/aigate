"""Tests for structured logging."""

from __future__ import annotations

import logging

from aigate.log import setup_logging


def test_setup_logging_default_level():
    logger = setup_logging()
    assert logger.name == "aigate"
    assert logger.level == logging.WARNING


def test_setup_logging_verbose():
    logger = setup_logging(verbose=True)
    assert logger.level == logging.DEBUG


def test_setup_logging_quiet():
    logger = setup_logging(quiet=True)
    assert logger.level == logging.ERROR


def test_setup_logging_file(tmp_path):
    log_file = tmp_path / "aigate.log"
    logger = setup_logging(log_file=str(log_file))
    logger.warning("test message")
    assert "test message" in log_file.read_text()


def test_verbose_and_quiet_conflict():
    """Quiet wins over verbose when both are set."""
    logger = setup_logging(verbose=True, quiet=True)
    assert logger.level == logging.ERROR
