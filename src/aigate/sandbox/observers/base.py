"""Transport-agnostic Observer ABC + ObserverSink hierarchy (Phase 2, REV-D).

REV-D design commitments:
- ``parse_event`` takes **bytes** (not ``str``) to support stateful
  multi-line reassembly (strace ``<... resumed>``) without line-boundary
  assumptions.
- Parser state (partial-line buffer, pending resumptions) lives in
  Observer **instance** attributes — **no module-global buffers**.
  Two concurrent ``StraceObserver()`` instances must never share state.
- ``ObserverSink`` is a context-manager: ``__enter__`` allocates the
  transport (mkfifo, pipe fd); ``__exit__`` / ``cleanup()`` releases it
  atomically so callers never need bare ``os.unlink`` scattered around
  ``birdcage_backend.py``.

Phase 2 uses ``FifoSink`` only.  ``JsonLineSink`` is wired in Phase 2.5
(bpftrace); ``PerfBufferSink`` is a Phase 4 stub.
"""

from __future__ import annotations

import os
import shutil
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import ClassVar, Literal

from ..types import DynamicTraceEvent, SandboxCoverage

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

SinkKind = Literal["fifo", "json_stream", "perf_buffer"]


# ---------------------------------------------------------------------------
# ObserverSink hierarchy
# ---------------------------------------------------------------------------


class ObserverSink(ABC):
    """Transport-agnostic event sink: FIFO, JSON line stream, perf buffer.

    Each concrete sink is a context manager: ``__enter__`` allocates the
    kernel resource; ``__exit__`` delegates to ``cleanup()``.
    """

    @abstractmethod
    def argv_arg(self) -> str:
        """The argument value to embed in the observer command argv.

        For ``FifoSink`` this is the FIFO path (``-o <path>``).
        For ``JsonLineSink`` this is the write-end fd as a decimal string.
        """
        ...

    @abstractmethod
    async def read_until_closed(self) -> bytes:
        """Drain all bytes from the sink until the write end is closed.

        Implementations block until the observer subprocess exits or the
        write fd is explicitly closed.  Used by the async FIFO reader in
        ``birdcage_backend.py``; unit tests may mock this.
        """
        ...

    @abstractmethod
    def cleanup(self) -> None:
        """Release transport resources (unlink FIFO, close pipe fds, etc.).

        Must be **idempotent**: a second call after the resource is gone
        must not raise.
        """
        ...

    # Context-manager protocol — delegates to cleanup()

    def __enter__(self) -> ObserverSink:
        return self

    def __exit__(self, *_: object) -> None:
        self.cleanup()


class FifoSink(ObserverSink):
    """Named-pipe (FIFO) transport for ``strace -o <path>`` wiring.

    Lifecycle::

        with FifoSink("/tmp/aigate-observer.fifo") as sink:
            argv = observer.argv_prefix(sink)
            # ... launch subprocess ...
        # FIFO unlinked on __exit__ even if an exception is raised

    ``__enter__`` calls ``os.mkfifo``; ``__exit__`` calls ``cleanup()``.
    ``cleanup()`` is idempotent: a second call when the file is already
    gone does not raise.
    """

    def __init__(self, fifo_path: str) -> None:
        self.fifo_path = fifo_path
        self._created: bool = False

    def __enter__(self) -> FifoSink:  # type: ignore[override]
        os.mkfifo(self.fifo_path)
        self._created = True
        return self

    def argv_arg(self) -> str:
        return self.fifo_path

    async def read_until_closed(self) -> bytes:
        """Open the FIFO read-only (non-blocking) and drain until EOF.

        Opens with ``O_NONBLOCK`` to avoid a deadlock when the write end
        is not yet connected, then drains in a poll loop.

        NOTE (Phase 2, reviewer P2 PR #6 comment 3117032782): BirdcageBackend
        does NOT call this method. It runs its own inline per-chunk reader
        inside ``_run_inside_scratch`` (lines ~325–390) so it can call
        ``observer.parse_event(chunk, scrub)`` incrementally. This method
        stays for test utilities that want the whole-stream-then-close
        contract (e.g. isolated parser fuzzing). The sink lifecycle itself —
        mkfifo at ``__enter__`` and unlink at ``cleanup()`` — is authoritative
        regardless of which reader is used.
        """
        import asyncio

        loop = asyncio.get_running_loop()
        fd = os.open(self.fifo_path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = await loop.run_in_executor(None, os.read, fd, 65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except BlockingIOError:
                    await asyncio.sleep(0.01)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def cleanup(self) -> None:
        """Unlink the FIFO if it was created by this instance.  Idempotent."""
        if self._created:
            try:
                os.unlink(self.fifo_path)
            except FileNotFoundError:
                pass
            self._created = False


class JsonLineSink(ObserverSink):
    """Pipe-fd transport for bpftrace JSON-line output (Phase 2.5/3).

    The caller creates an ``os.pipe()`` pair; the **write** end fd is
    passed to the bpftrace subprocess via ``argv_arg()``.  The **read**
    end fd (``pipe_fd``) is consumed by ``read_until_closed()``.

    ``cleanup()`` closes the read-end fd; the caller is responsible for
    closing the write end (or it is inherited and closed by the subprocess).
    """

    def __init__(self, pipe_fd: int) -> None:
        self.pipe_fd = pipe_fd
        self._open: bool = True

    def argv_arg(self) -> str:
        return str(self.pipe_fd)

    async def read_until_closed(self) -> bytes:
        """Phase 2.5 — not yet wired; raises to prevent silent no-ops."""
        raise NotImplementedError("JsonLineSink.read_until_closed is Phase 2.5+")

    def cleanup(self) -> None:
        """Close the read-end fd.  Idempotent."""
        if self._open:
            try:
                os.close(self.pipe_fd)
            except OSError:
                pass
            self._open = False


class PerfBufferSink(ObserverSink):
    """eBPF perf-buffer transport (Phase 4 stub).

    Reserved for future in-kernel map polling via ``BPF_MAP_TYPE_PERF_EVENT_ARRAY``.
    All methods raise ``NotImplementedError`` except ``cleanup()`` which
    is a no-op so the context-manager protocol is safe.
    """

    def argv_arg(self) -> str:
        raise NotImplementedError("PerfBufferSink is a Phase 4+ stub")

    async def read_until_closed(self) -> bytes:
        raise NotImplementedError("PerfBufferSink is a Phase 4+ stub")

    def cleanup(self) -> None:
        pass  # nothing to release in Phase 4 stub


# ---------------------------------------------------------------------------
# Observer ABC
# ---------------------------------------------------------------------------


class Observer(ABC):
    """Abstract tracing-subprocess observer (Phase 2, REV-D).

    Implementations are **transport-agnostic**: ``sink_kind`` tells the
    caller which ``ObserverSink`` to allocate; ``argv_prefix(sink)``
    builds the full subprocess argv; ``parse_event(bytes, scrub)`` turns
    raw observer output into structured ``DynamicTraceEvent`` objects.

    REV-D invariant: ``parse_event`` takes **bytes**.  Each ``Observer``
    instance maintains its own partial-line / resumption-reassembly buffer
    in instance attributes.  **No module-global state is permitted.**

    Class attributes ``name`` and ``coverage`` must be defined on every
    concrete subclass (``ClassVar``).

    Concrete observers (Phase 2+):
    - ``StraceObserver``   — ``src/aigate/sandbox/observers/strace.py`` (Task 2.2)
    - ``BpftraceObserver`` — ``src/aigate/sandbox/observers/bpftrace.py`` (Task 2.3)
    - ``MitmproxyObserver``— ``src/aigate/sandbox/observers/mitmproxy.py`` (Task 2.4)
    """

    name: ClassVar[str]
    coverage: ClassVar[frozenset[SandboxCoverage]]

    @abstractmethod
    def argv_prefix(self, sink: ObserverSink) -> list[str]:
        """Return the argv list to prepend to the traced command.

        Example for strace::

            ["strace", "-f", "-e", "trace=connect,openat,write,execve,clone",
             "-o", sink.argv_arg(), "--"]

        The caller appends the birdcage argv after this prefix.
        """
        ...

    @abstractmethod
    def parse_event(
        self,
        raw: bytes,
        scrub: Iterable[str],
    ) -> DynamicTraceEvent | None:
        """Parse one raw byte-chunk into a structured event, or return None.

        **Must accept bytes** — never str.  May buffer partial lines
        internally (in instance state only); must reassemble multi-line
        continuations (e.g. strace ``<... resumed>``) before yielding.

        Returns ``None`` for unparseable chunks.  Callers count non-None
        returns as the numerator and every call as denominator for
        ``classify_parse_quality``.

        ``scrub`` is forwarded to ``secrets.redact_secrets`` so that
        ``target`` / ``raw`` fields are sanitised **before** the event is
        appended to ``DynamicTrace.events``.
        """
        ...

    @property
    @abstractmethod
    def sink_kind(self) -> SinkKind:
        """Transport kind: ``"fifo"``, ``"json_stream"``, or ``"perf_buffer"``."""
        ...

    @abstractmethod
    def check_available(self) -> bool:
        """Return True iff this observer can run on the current host.

        Cheap preflight — must NOT spawn subprocesses or open network
        connections.  Use ``shutil.which`` at most.
        """
        ...

    @abstractmethod
    async def cleanup(self) -> None:
        """Release any resources held by this observer instance.

        Called in the ``finally`` block of ``BirdcageBackend.run()``.
        Must be safe to call even if the observer never started.
        """
        ...

    # -------------------------------------------------------------------
    # Convenience helper (non-abstract, available to all subclasses)
    # -------------------------------------------------------------------

    def _binary_on_path(self) -> bool:
        """Return True iff ``self.name`` binary is on PATH.

        Subclasses may call this from ``check_available()`` or override
        with a richer probe (e.g. version-check, privilege check).
        """
        return shutil.which(self.name) is not None
