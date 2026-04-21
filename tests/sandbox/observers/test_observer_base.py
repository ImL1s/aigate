"""Tests for Observer ABC + ObserverSink hierarchy (Task 2.1, REV-D).

Acceptance criteria:
- Observer ABC cannot be instantiated directly.
- An Observer subclass missing any @abstractmethod raises TypeError.
- ObserverSink ABC cannot be instantiated directly.
- FifoSink creates its FIFO on __enter__ and removes it on __exit__.
- cleanup() is idempotent (double-call does not raise).
- sink_kind property returns a valid SinkKind Literal value.
- parse_event signature takes bytes (REV-D invariant).
- Observer instances carry per-instance state (no module-global buffers).
"""

from __future__ import annotations

import os
import stat as stat_mod
from collections.abc import Iterable

import pytest

from aigate.sandbox.observers.base import (
    FifoSink,
    JsonLineSink,
    Observer,
    ObserverSink,
    PerfBufferSink,
    SinkKind,
)
from aigate.sandbox.types import DynamicTraceEvent, SandboxCoverage

# ---------------------------------------------------------------------------
# Minimal concrete implementations for testing
# ---------------------------------------------------------------------------


class _MinimalObserver(Observer):
    """Minimal fully-concrete Observer for contract testing."""

    name = "test-observer"
    coverage = frozenset({SandboxCoverage.NETWORK_CAPTURE})

    def argv_prefix(self, sink: ObserverSink) -> list[str]:
        return ["test-observer", "--output", sink.argv_arg()]

    def parse_event(self, raw: bytes, scrub: Iterable[str]) -> DynamicTraceEvent | None:
        # Per-instance buffer to assert no module-global state
        if not hasattr(self, "_buf"):
            self._buf: bytes = b""
        self._buf += raw
        return None  # stub

    @property
    def sink_kind(self) -> SinkKind:
        return "fifo"

    def check_available(self) -> bool:
        return False

    async def cleanup(self) -> None:
        pass


class _MinimalSink(ObserverSink):
    """Concrete ObserverSink for ABC contract tests."""

    def argv_arg(self) -> str:
        return "/tmp/test.fifo"

    async def read_until_closed(self) -> bytes:
        return b""

    def cleanup(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Observer ABC — instantiation guards
# ---------------------------------------------------------------------------


class TestObserverABC:
    def test_cannot_instantiate_abstract_observer(self) -> None:
        with pytest.raises(TypeError):
            Observer()  # type: ignore[abstract]

    def test_missing_argv_prefix_raises(self) -> None:
        class BadObserver(Observer):
            name = "bad"
            coverage: frozenset[SandboxCoverage] = frozenset()

            def parse_event(self, raw: bytes, scrub: Iterable[str]) -> None:
                return None

            @property
            def sink_kind(self) -> SinkKind:
                return "fifo"

            def check_available(self) -> bool:
                return False

            async def cleanup(self) -> None:
                pass

            # argv_prefix NOT defined → abstract

        with pytest.raises(TypeError):
            BadObserver()  # type: ignore[abstract]

    def test_missing_parse_event_raises(self) -> None:
        class BadObserver(Observer):
            name = "bad"
            coverage: frozenset[SandboxCoverage] = frozenset()

            def argv_prefix(self, sink: ObserverSink) -> list[str]:
                return []

            @property
            def sink_kind(self) -> SinkKind:
                return "fifo"

            def check_available(self) -> bool:
                return False

            async def cleanup(self) -> None:
                pass

            # parse_event NOT defined → abstract

        with pytest.raises(TypeError):
            BadObserver()  # type: ignore[abstract]

    def test_missing_sink_kind_raises(self) -> None:
        class BadObserver(Observer):
            name = "bad"
            coverage: frozenset[SandboxCoverage] = frozenset()

            def argv_prefix(self, sink: ObserverSink) -> list[str]:
                return []

            def parse_event(self, raw: bytes, scrub: Iterable[str]) -> None:
                return None

            def check_available(self) -> bool:
                return False

            async def cleanup(self) -> None:
                pass

            # sink_kind property NOT defined → abstract

        with pytest.raises(TypeError):
            BadObserver()  # type: ignore[abstract]

    def test_missing_check_available_raises(self) -> None:
        class BadObserver(Observer):
            name = "bad"
            coverage: frozenset[SandboxCoverage] = frozenset()

            def argv_prefix(self, sink: ObserverSink) -> list[str]:
                return []

            def parse_event(self, raw: bytes, scrub: Iterable[str]) -> None:
                return None

            @property
            def sink_kind(self) -> SinkKind:
                return "fifo"

            async def cleanup(self) -> None:
                pass

            # check_available NOT defined → abstract

        with pytest.raises(TypeError):
            BadObserver()  # type: ignore[abstract]

    def test_missing_cleanup_raises(self) -> None:
        class BadObserver(Observer):
            name = "bad"
            coverage: frozenset[SandboxCoverage] = frozenset()

            def argv_prefix(self, sink: ObserverSink) -> list[str]:
                return []

            def parse_event(self, raw: bytes, scrub: Iterable[str]) -> None:
                return None

            @property
            def sink_kind(self) -> SinkKind:
                return "fifo"

            def check_available(self) -> bool:
                return False

            # cleanup NOT defined → abstract

        with pytest.raises(TypeError):
            BadObserver()  # type: ignore[abstract]

    def test_complete_subclass_instantiates(self) -> None:
        obs = _MinimalObserver()
        assert obs.name == "test-observer"

    # -------------------------------------------------------------------
    # REV-D: parse_event takes bytes, not str
    # -------------------------------------------------------------------

    def test_parse_event_accepts_bytes(self) -> None:
        obs = _MinimalObserver()
        result = obs.parse_event(b"some raw bytes\n", iter([]))
        assert result is None  # stub returns None

    def test_parse_event_does_not_accept_str_at_type_level(self) -> None:
        """Documented: parse_event signature is (bytes, ...). This test
        asserts the method can be called with bytes and accumulates to
        per-instance buffer (not a global).
        """
        obs = _MinimalObserver()
        obs.parse_event(b"chunk1", [])
        obs.parse_event(b"chunk2", [])
        assert obs._buf == b"chunk1chunk2"

    # -------------------------------------------------------------------
    # REV-D: parser state is per-instance
    # -------------------------------------------------------------------

    def test_parser_state_is_per_instance_not_global(self) -> None:
        """Two independent Observer instances must not share any buffer."""
        obs1 = _MinimalObserver()
        obs2 = _MinimalObserver()

        obs1.parse_event(b"alpha", [])
        obs2.parse_event(b"beta", [])

        assert obs1._buf == b"alpha"
        assert obs2._buf == b"beta"
        # Confirm they are independent objects
        assert obs1 is not obs2
        assert obs1.__dict__ is not obs2.__dict__

    # -------------------------------------------------------------------
    # sink_kind contract
    # -------------------------------------------------------------------

    def test_sink_kind_returns_valid_literal(self) -> None:
        obs = _MinimalObserver()
        assert obs.sink_kind in ("fifo", "json_stream", "perf_buffer")

    def test_sink_kind_is_property(self) -> None:
        # sink_kind must be a property, not a plain attribute
        assert isinstance(
            Observer.__dict__.get("sink_kind") or _MinimalObserver.__dict__.get("sink_kind"),
            property,
        )

    # -------------------------------------------------------------------
    # coverage class attribute
    # -------------------------------------------------------------------

    def test_coverage_is_frozenset(self) -> None:
        obs = _MinimalObserver()
        assert isinstance(obs.coverage, frozenset)

    def test_coverage_contains_sandbox_coverage_members(self) -> None:
        obs = _MinimalObserver()
        for item in obs.coverage:
            assert isinstance(item, SandboxCoverage)

    # -------------------------------------------------------------------
    # argv_prefix
    # -------------------------------------------------------------------

    def test_argv_prefix_returns_list_of_str(self) -> None:
        obs = _MinimalObserver()
        sink = _MinimalSink()
        argv = obs.argv_prefix(sink)
        assert isinstance(argv, list)
        assert all(isinstance(a, str) for a in argv)

    def test_argv_prefix_includes_sink_arg(self) -> None:
        obs = _MinimalObserver()
        sink = _MinimalSink()
        argv = obs.argv_prefix(sink)
        assert sink.argv_arg() in argv

    # -------------------------------------------------------------------
    # _binary_on_path convenience helper
    # -------------------------------------------------------------------

    def test_binary_on_path_returns_bool(self) -> None:
        obs = _MinimalObserver()
        result = obs._binary_on_path()
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# ObserverSink ABC — instantiation guard
# ---------------------------------------------------------------------------


class TestObserverSinkABC:
    def test_cannot_instantiate_abstract_sink(self) -> None:
        with pytest.raises(TypeError):
            ObserverSink()  # type: ignore[abstract]

    def test_concrete_sink_instantiates(self) -> None:
        sink = _MinimalSink()
        assert sink.argv_arg() == "/tmp/test.fifo"

    def test_cleanup_callable(self) -> None:
        sink = _MinimalSink()
        sink.cleanup()  # must not raise

    def test_context_manager_calls_cleanup_on_exit(self) -> None:
        called: list[bool] = []

        class TrackedSink(_MinimalSink):
            def cleanup(self) -> None:
                called.append(True)

        with TrackedSink():
            assert not called
        assert called == [True]

    def test_context_manager_calls_cleanup_on_exception(self) -> None:
        called: list[bool] = []

        class TrackedSink(_MinimalSink):
            def cleanup(self) -> None:
                called.append(True)

        with pytest.raises(RuntimeError):
            with TrackedSink():
                raise RuntimeError("test")
        assert called == [True]

    def test_context_manager_returns_self(self) -> None:
        sink = _MinimalSink()
        with sink as s:
            assert s is sink


# ---------------------------------------------------------------------------
# FifoSink
# ---------------------------------------------------------------------------


class TestFifoSink:
    def test_creates_fifo_on_enter(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        with FifoSink(fifo_path):
            assert os.path.exists(fifo_path)
            assert stat_mod.S_ISFIFO(os.stat(fifo_path).st_mode)

    def test_removes_fifo_on_exit(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        with FifoSink(fifo_path):
            pass
        assert not os.path.exists(fifo_path)

    def test_removes_fifo_on_exception(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        with pytest.raises(RuntimeError):
            with FifoSink(fifo_path):
                raise RuntimeError("boom")
        assert not os.path.exists(fifo_path)

    def test_argv_arg_returns_fifo_path(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        with FifoSink(fifo_path) as sink:
            assert sink.argv_arg() == fifo_path

    def test_cleanup_is_idempotent(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        sink = FifoSink(fifo_path)
        sink.__enter__()
        assert os.path.exists(fifo_path)
        sink.cleanup()
        assert not os.path.exists(fifo_path)
        sink.cleanup()  # second call must not raise

    def test_cleanup_before_enter_is_noop(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        sink = FifoSink(fifo_path)
        sink.cleanup()  # never entered — must not raise or create file
        assert not os.path.exists(fifo_path)

    def test_context_manager_returns_fifo_sink(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        with FifoSink(fifo_path) as sink:
            assert isinstance(sink, FifoSink)

    def test_argv_arg_is_string(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        with FifoSink(fifo_path) as sink:
            assert isinstance(sink.argv_arg(), str)

    def test_no_fifo_created_without_enter(self, tmp_path) -> None:
        fifo_path = str(tmp_path / "obs.fifo")
        _ = FifoSink(fifo_path)  # instantiate but do NOT enter
        assert not os.path.exists(fifo_path)


# ---------------------------------------------------------------------------
# JsonLineSink
# ---------------------------------------------------------------------------


class TestJsonLineSink:
    def test_argv_arg_returns_fd_as_string(self) -> None:
        r_fd, w_fd = os.pipe()
        try:
            sink = JsonLineSink(r_fd)
            assert sink.argv_arg() == str(r_fd)
        finally:
            os.close(w_fd)
            try:
                os.close(r_fd)
            except OSError:
                pass

    def test_cleanup_closes_fd(self) -> None:
        r_fd, w_fd = os.pipe()
        os.close(w_fd)
        sink = JsonLineSink(r_fd)
        sink.cleanup()
        with pytest.raises(OSError):
            os.fstat(r_fd)

    def test_cleanup_is_idempotent(self) -> None:
        r_fd, w_fd = os.pipe()
        os.close(w_fd)
        sink = JsonLineSink(r_fd)
        sink.cleanup()
        sink.cleanup()  # must not raise

    async def test_read_until_closed_raises_not_implemented(self) -> None:
        r_fd, w_fd = os.pipe()
        os.close(w_fd)
        sink = JsonLineSink(r_fd)
        try:
            with pytest.raises(NotImplementedError, match="Phase 2.5"):
                await sink.read_until_closed()
        finally:
            sink.cleanup()


# ---------------------------------------------------------------------------
# PerfBufferSink
# ---------------------------------------------------------------------------


class TestPerfBufferSink:
    def test_cleanup_does_not_raise(self) -> None:
        sink = PerfBufferSink()
        sink.cleanup()

    def test_argv_arg_raises_not_implemented(self) -> None:
        sink = PerfBufferSink()
        with pytest.raises(NotImplementedError):
            sink.argv_arg()

    async def test_read_until_closed_raises_not_implemented(self) -> None:
        sink = PerfBufferSink()
        with pytest.raises(NotImplementedError):
            await sink.read_until_closed()

    def test_context_manager_safe(self) -> None:
        """cleanup() is a no-op so context manager must not raise."""
        with PerfBufferSink():
            pass
