"""Output reporters for aigate."""

from .json_reporter import JsonReporter
from .terminal import TerminalReporter

__all__ = ["TerminalReporter", "JsonReporter"]
