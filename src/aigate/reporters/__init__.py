"""Output reporters for aigate."""

from .terminal import TerminalReporter
from .json_reporter import JsonReporter

__all__ = ["TerminalReporter", "JsonReporter"]
