"""Observer layer for aigate sandbox (Phase 2, REV-D).

Exports the transport-agnostic Observer ABC and ObserverSink hierarchy
from ``base``.  Concrete observer implementations live in their own
modules:
- ``strace``:    StraceObserver     (Phase 2, Task 2.2)
- ``bpftrace``:  BpftraceObserver   (Phase 2.5 stub, Task 2.3)
- ``mitmproxy``: MitmproxyObserver  (Phase 4 stub, Task 2.4)

IMPORTANT: keep imports lazy — this package is imported inside
``birdcage_backend.py`` which is itself lazily imported.  No heavy
third-party imports at module load.
"""

from __future__ import annotations

from .base import (
    FifoSink,
    JsonLineSink,
    Observer,
    ObserverSink,
    PerfBufferSink,
    SinkKind,
)

__all__ = [
    "Observer",
    "ObserverSink",
    "FifoSink",
    "JsonLineSink",
    "PerfBufferSink",
    "SinkKind",
]
