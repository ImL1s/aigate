"""Structured logging for aigate."""

from __future__ import annotations

import logging
import sys


def setup_logging(
    *,
    verbose: bool = False,
    quiet: bool = False,
    log_file: str | None = None,
) -> logging.Logger:
    """Configure aigate logger.

    Args:
        verbose: Enable DEBUG level output.
        quiet: Suppress all output except errors. Takes precedence over verbose.
        log_file: Optional path to write logs to file.
    """
    logger = logging.getLogger("aigate")
    logger.handlers.clear()

    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    logger.setLevel(level)

    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(fmt)
    logger.addHandler(stderr_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger
