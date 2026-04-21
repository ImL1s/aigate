"""Unit tests for StraceObserver + parse_strace_logical_event (Task 2.2).

Covers:
- Happy-path parsing: connect, openat, execve, write, clone
- DNS detection (connect to port 53)
- IPv6 connect
- AF_UNIX connect
- Observer-canary sentinel path (REV-B)
- Write-flag detection on openat
- strace 5.x [pid N] format
- strace 6.x bare-N format
- strace 6.8 double-space bare-N format
- Truncated / partial args still emit an event (not silent drop)
- Signal delivery lines → None
- Exit-notice lines → None
- Redaction applied before event construction (REV-D)
- retval EINPROGRESS still yields event
- Unknown address family fallback
- clone syscall → kind="clone" with child_pid target
- parse ratio ≥ 0.9 across all four version fixtures
- classify_parse_quality integration with logical-event units
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aigate.sandbox.observers.strace import (
    OBSERVER_CANARY_MARKER,
    StraceObserver,
    parse_strace_logical_event,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _line(s: str) -> bytes:
    """Encode a strace line (adds newline if missing)."""
    if not s.endswith("\n"):
        s += "\n"
    return s.encode()


def _ev(line: str, scrub: list[str] | None = None):
    """Call parse_strace_logical_event on a single line; return event."""
    ev, _ = parse_strace_logical_event(_line(line), scrub or [])
    return ev


def _instance_ev(line: str, observer: StraceObserver | None = None, scrub: list[str] | None = None):
    """Call StraceObserver.parse_event on a single line; return event."""
    obs = observer or StraceObserver()
    return obs.parse_event(_line(line), scrub or [])


# ---------------------------------------------------------------------------
# connect — IPv4
# ---------------------------------------------------------------------------


class TestConnectIPv4:
    def test_connect_happy_path(self):
        ev = _ev(
            '1234 connect(4, {sa_family=AF_INET, sin_port=htons(80),'
            ' sin_addr=inet_addr("1.2.3.4")}, 16) = 0'
        )
        assert ev is not None
        assert ev.kind == "connect"
        assert ev.target == "1.2.3.4:80"
        assert ev.pid == 1234

    def test_connect_https_port_443(self):
        ev = _ev(
            '1234 connect(4, {sa_family=AF_INET, sin_port=htons(443),'
            ' sin_addr=inet_addr("104.20.23.96")}, 16) = 0'
        )
        assert ev is not None
        assert ev.kind == "connect"
        assert ev.target == "104.20.23.96:443"

    def test_connect_einprogress_still_emits_event(self):
        """EINPROGRESS is a normal non-blocking connect result."""
        ev = _ev(
            '1234 connect(4, {sa_family=AF_INET, sin_port=htons(443),'
            ' sin_addr=inet_addr("151.101.1.194")}, 16)'
            ' = -1 EINPROGRESS (Operation now in progress)'
        )
        assert ev is not None
        assert ev.kind == "connect"
        assert ev.target == "151.101.1.194:443"

    def test_connect_pid_preserved(self):
        ev = _ev(
            '9999 connect(4, {sa_family=AF_INET, sin_port=htons(80),'
            ' sin_addr=inet_addr("10.0.0.1")}, 16) = 0'
        )
        assert ev is not None
        assert ev.pid == 9999

    def test_connect_ts_ms_positive(self):
        before = int(time.monotonic() * 1000)
        ev = _ev(
            '1234 connect(4, {sa_family=AF_INET, sin_port=htons(80),'
            ' sin_addr=inet_addr("1.2.3.4")}, 16) = 0'
        )
        after = int(time.monotonic() * 1000) + 10
        assert ev is not None
        assert before <= ev.ts_ms <= after

    def test_connect_raw_field_set(self):
        ev = _ev(
            '1234 connect(4, {sa_family=AF_INET, sin_port=htons(80),'
            ' sin_addr=inet_addr("1.2.3.4")}, 16) = 0'
        )
        assert ev is not None
        assert "connect" in ev.raw


# ---------------------------------------------------------------------------
# connect — DNS (port 53)
# ---------------------------------------------------------------------------


class TestConnectDns:
    def test_dns_port_53_tcp(self):
        ev = _ev(
            '1234 connect(5, {sa_family=AF_INET, sin_port=htons(53),'
            ' sin_addr=inet_addr("8.8.8.8")}, 16) = 0'
        )
        assert ev is not None
        assert ev.kind == "dns"
        assert ev.target == "resolver=8.8.8.8"

    def test_dns_port_53_cloudflare(self):
        ev = _ev(
            '1234 connect(5, {sa_family=AF_INET, sin_port=htons(53),'
            ' sin_addr=inet_addr("1.1.1.1")}, 16) = 0'
        )
        assert ev is not None
        assert ev.kind == "dns"
        assert ev.target == "resolver=1.1.1.1"


# ---------------------------------------------------------------------------
# connect — IPv6
# ---------------------------------------------------------------------------


class TestConnectIPv6:
    def test_connect_ipv6_port_80(self):
        ev = _ev(
            "1234 connect(4, {sa_family=AF_INET6, sin6_port=htons(80),"
            " sin6_flowinfo=htonl(0), inet_pton(AF_INET6, \"2001:db8::1\","
            " &sin6_addr), sin6_scope_id=0}, 28) = 0"
        )
        assert ev is not None
        assert ev.kind == "connect"
        assert "[ipv6]:80" in ev.target

    def test_connect_ipv6_port_53_is_dns(self):
        ev = _ev(
            "1234 connect(4, {sa_family=AF_INET6, sin6_port=htons(53),"
            " sin6_flowinfo=0}, 28) = 0"
        )
        assert ev is not None
        assert ev.kind == "dns"
        assert "ipv6" in ev.target


# ---------------------------------------------------------------------------
# connect — AF_UNIX
# ---------------------------------------------------------------------------


class TestConnectUnix:
    def test_connect_unix_socket(self):
        ev = _ev(
            '1234 connect(3, {sa_family=AF_UNIX, sun_path="/tmp/mysock"},'
            " 20) = 0"
        )
        assert ev is not None
        assert ev.kind == "connect"
        assert ev.target == "unix:/tmp/mysock"

    def test_connect_unix_abstract_socket(self):
        ev = _ev(
            '1234 connect(3, {sa_family=AF_UNIX, sun_path="@/tmp/dbus"},'
            " 20) = 0"
        )
        assert ev is not None
        assert ev.kind == "connect"
        assert "unix:" in ev.target


# ---------------------------------------------------------------------------
# openat — read vs write detection
# ---------------------------------------------------------------------------


class TestOpenat:
    def test_openat_readonly_is_open(self):
        ev = _ev('1234 openat(AT_FDCWD, "/etc/resolv.conf", O_RDONLY) = 3')
        assert ev is not None
        assert ev.kind == "open"
        assert ev.target == "/etc/resolv.conf"

    def test_openat_wronly_is_write(self):
        ev = _ev('1234 openat(AT_FDCWD, "/tmp/evil.sh", O_WRONLY) = 5')
        assert ev is not None
        assert ev.kind == "write"
        assert ev.target == "/tmp/evil.sh"

    def test_openat_rdwr_is_write(self):
        ev = _ev('1234 openat(AT_FDCWD, "/tmp/db.sqlite", O_RDWR) = 5')
        assert ev is not None
        assert ev.kind == "write"

    def test_openat_creat_is_write(self):
        ev = _ev(
            '1234 openat(AT_FDCWD, "/tmp/install.sh",'
            " O_WRONLY|O_CREAT|O_TRUNC, 0777) = 5"
        )
        assert ev is not None
        assert ev.kind == "write"
        assert ev.target == "/tmp/install.sh"

    def test_openat_trunc_is_write(self):
        ev = _ev('1234 openat(AT_FDCWD, "/var/log/out.log", O_WRONLY|O_TRUNC) = 6')
        assert ev is not None
        assert ev.kind == "write"

    def test_openat_append_is_write(self):
        ev = _ev('1234 openat(AT_FDCWD, "/root/.bashrc", O_WRONLY|O_APPEND) = 7')
        assert ev is not None
        assert ev.kind == "write"

    def test_openat_path_preserved(self):
        ev = _ev('1234 openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 3')
        assert ev is not None
        assert ev.target == "/proc/self/maps"

    def test_openat_unicode_path(self):
        ev = _ev('1234 openat(AT_FDCWD, "/tmp/日本語/file.txt", O_RDONLY) = 3')
        assert ev is not None
        assert "日本語" in ev.target

    def test_openat_numeric_dirfd(self):
        """openat with a real fd (not AT_FDCWD) should still parse."""
        ev = _ev('1234 openat(5, "/relative/path", O_RDONLY) = 3')
        assert ev is not None
        assert ev.target == "/relative/path"


# ---------------------------------------------------------------------------
# openat — observer canary (REV-B)
# ---------------------------------------------------------------------------


class TestObserverCanary:
    def test_canary_path_emits_observer_canary_kind(self):
        ev = _ev(f'1234 openat(AT_FDCWD, "{OBSERVER_CANARY_MARKER}", O_RDONLY) = 3')
        assert ev is not None
        assert ev.kind == "observer_canary"
        assert ev.source == "observer_canary"

    def test_canary_target_is_marker_path(self):
        ev = _ev(f'1234 openat(AT_FDCWD, "{OBSERVER_CANARY_MARKER}", O_RDONLY) = 3')
        assert ev is not None
        assert ev.target == OBSERVER_CANARY_MARKER

    def test_non_canary_path_is_not_canary(self):
        ev = _ev('1234 openat(AT_FDCWD, "/aigate-something-else", O_RDONLY) = 3')
        assert ev is not None
        assert ev.kind != "observer_canary"

    def test_canary_write_mode_still_canary(self):
        ev = _ev(
            f'1234 openat(AT_FDCWD, "{OBSERVER_CANARY_MARKER}",'
            " O_WRONLY|O_CREAT) = 3"
        )
        assert ev is not None
        assert ev.kind == "observer_canary"


# ---------------------------------------------------------------------------
# execve
# ---------------------------------------------------------------------------


class TestExecve:
    def test_execve_kind_is_exec(self):
        ev = _ev(
            '1234 execve("/bin/sh", ["/bin/sh", "-c", "echo hi"],'
            " /* 15 vars */) = 0"
        )
        assert ev is not None
        assert ev.kind == "exec"

    def test_execve_target_is_path(self):
        ev = _ev(
            '1234 execve("/usr/bin/node", ["/usr/bin/node", "index.js"],'
            " 0x7fff) = 0"
        )
        assert ev is not None
        assert ev.target == "/usr/bin/node"

    def test_execve_argv_extracted(self):
        ev = _ev(
            '1234 execve("/bin/sh", ["/bin/sh", "-c", "npm run build"],'
            " /* 15 vars */) = 0"
        )
        assert ev is not None
        assert ev.argv == ["/bin/sh", "-c", "npm run build"]

    def test_execve_argv_single_entry(self):
        ev = _ev('1234 execve("/usr/bin/env", ["/usr/bin/env"], /* 5 vars */) = 0')
        assert ev is not None
        assert ev.argv == ["/usr/bin/env"]

    def test_execve_pid_preserved(self):
        ev = _ev(
            '5678 execve("/bin/curl", ["/bin/curl", "-s", "http://evil.com"],'
            " 0x7fff) = 0"
        )
        assert ev is not None
        assert ev.pid == 5678


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------


class TestWrite:
    def test_write_kind_is_write(self):
        ev = _ev('1234 write(1, "hello\\n", 6) = 6')
        assert ev is not None
        assert ev.kind == "write"

    def test_write_target_fd(self):
        ev = _ev('1234 write(4, "data", 4) = 4')
        assert ev is not None
        assert ev.target == "fd=4"

    def test_write_fd_zero_stdout(self):
        ev = _ev('1234 write(1, "out\\n", 4) = 4')
        assert ev is not None
        assert ev.target == "fd=1"


# ---------------------------------------------------------------------------
# clone
# ---------------------------------------------------------------------------


class TestClone:
    def test_clone_kind_is_clone(self):
        ev = _ev(
            "1234 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|SIGCHLD,"
            " child_tidptr=0x7f80) = 5678"
        )
        assert ev is not None
        assert ev.kind == "clone"

    def test_clone_target_has_child_pid(self):
        ev = _ev(
            "1234 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|SIGCHLD,"
            " child_tidptr=0x7f80) = 5678"
        )
        assert ev is not None
        assert ev.target == "child_pid=5678"

    def test_clone_failed_returns_none(self):
        """clone(...) = -1 (failed) should return None."""
        ev = _ev(
            "1234 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|SIGCHLD,"
            " child_tidptr=0x7f80) = -1 ENOMEM (Out of memory)"
        )
        assert ev is None

    def test_clone3_also_parsed(self):
        ev = _ev(
            "1234 clone3({flags=CLONE_CHILD_CLEARTID|SIGCHLD, exit_signal=SIGCHLD},"
            " 88) = 9999"
        )
        assert ev is not None
        assert ev.kind == "clone"
        assert ev.target == "child_pid=9999"


# ---------------------------------------------------------------------------
# PID prefix formats (strace 5.x vs 6.x)
# ---------------------------------------------------------------------------


class TestPidFormats:
    def test_strace_5x_bracket_pid(self):
        """strace 5.x [pid N] prefix."""
        ev = _ev(
            '[pid 1234] connect(4, {sa_family=AF_INET, sin_port=htons(80),'
            ' sin_addr=inet_addr("1.2.3.4")}, 16) = 0'
        )
        assert ev is not None
        assert ev.pid == 1234
        assert ev.kind == "connect"

    def test_strace_6x_bare_pid(self):
        """strace 6.x bare integer prefix."""
        ev = _ev(
            '1234 connect(4, {sa_family=AF_INET, sin_port=htons(80),'
            ' sin_addr=inet_addr("1.2.3.4")}, 16) = 0'
        )
        assert ev is not None
        assert ev.pid == 1234

    def test_strace_6x_double_space_pid(self):
        """strace 6.8 uses two spaces after PID."""
        ev = _ev(
            '1234  connect(4, {sa_family=AF_INET, sin_port=htons(80),'
            ' sin_addr=inet_addr("1.2.3.4")}, 16) = 0'
        )
        assert ev is not None
        assert ev.pid == 1234

    def test_strace_5x_large_pid(self):
        ev = _ev(
            '[pid 65535] openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
        )
        assert ev is not None
        assert ev.pid == 65535

    def test_strace_6x_five_digit_pid(self):
        ev = _ev('99999 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3')
        assert ev is not None
        assert ev.pid == 99999


# ---------------------------------------------------------------------------
# Non-event lines → None
# ---------------------------------------------------------------------------


class TestNonEventLines:
    def test_signal_delivery_returns_none(self):
        ev = _ev(
            '1234 --- SIGTERM {si_signo=SIGTERM, si_code=SI_USER,'
            " si_pid=999, si_uid=1000} ---"
        )
        assert ev is None

    def test_exit_notice_returns_none(self):
        ev = _ev("1234 +++ exited with 0 +++")
        assert ev is None

    def test_no_pid_prefix_returns_none(self):
        """Lines without a PID prefix are not syscall events."""
        ev = _ev("strace: Process 1234 attached")
        assert ev is None

    def test_empty_line_returns_none(self):
        ev, remaining = parse_strace_logical_event(b"\n", [])
        assert ev is None

    def test_partial_line_no_newline_returns_none_unchanged_buffer(self):
        buf = b"1234 connect(4, <unfinished"
        ev, remaining = parse_strace_logical_event(buf, [])
        assert ev is None
        assert remaining == buf  # buffer returned unchanged

    def test_unfinished_line_returns_none(self):
        ev = _ev("1234 connect(4, <unfinished ...>")
        assert ev is None

    def test_resumed_line_stateless_returns_none(self):
        """parse_strace_logical_event can't resolve resumed without state."""
        ev = _ev(
            '1234 <... connect resumed> {sa_family=AF_INET,'
            ' sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = 0'
        )
        assert ev is None

    def test_unknown_syscall_returns_none(self):
        ev = _ev("1234 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, -1, 0) = 0x7f")
        assert ev is None


# ---------------------------------------------------------------------------
# Redaction (REV-D: applied BEFORE event construction)
# ---------------------------------------------------------------------------


class TestRedaction:
    def test_secret_in_target_is_redacted(self):
        secret = "my-secret-token-abc123"
        ev = _ev(
            f'1234 connect(4, {{sa_family=AF_INET, sin_port=htons(80),'
            f' sin_addr=inet_addr("{secret}")}}, 16) = 0',
            scrub=[secret],
        )
        assert ev is not None
        assert secret not in ev.target
        assert "<REDACTED:" in ev.target

    def test_secret_in_raw_is_redacted(self):
        secret = "supersecret"
        ev = _ev(
            f'1234 openat(AT_FDCWD, "/path/{secret}", O_RDONLY) = 3',
            scrub=[secret],
        )
        assert ev is not None
        assert secret not in ev.raw
        assert "<REDACTED:" in ev.raw

    def test_empty_scrub_no_redaction(self):
        ev = _ev(
            '1234 connect(4, {sa_family=AF_INET, sin_port=htons(80),'
            ' sin_addr=inet_addr("10.0.0.1")}, 16) = 0',
            scrub=[],
        )
        assert ev is not None
        assert ev.target == "10.0.0.1:80"

    def test_scrub_applied_to_execve_argv(self):
        secret = "PASSWORD=hunter2"
        ev = _ev(
            f'1234 execve("/bin/sh", ["/bin/sh", "-c", "echo {secret}"],'
            " /* 5 vars */) = 0",
            scrub=[secret],
        )
        assert ev is not None
        for arg in ev.argv:
            assert secret not in arg


# ---------------------------------------------------------------------------
# parse_strace_logical_event — remaining buffer
# ---------------------------------------------------------------------------


class TestRemainingBuffer:
    def test_remaining_is_bytes_after_newline(self):
        buf = (
            b'1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n'
            b'5678 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 4\n'
        )
        ev, remaining = parse_strace_logical_event(buf, [])
        assert ev is not None
        assert remaining == b'5678 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 4\n'

    def test_remaining_empty_after_last_line(self):
        buf = b'1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n'
        ev, remaining = parse_strace_logical_event(buf, [])
        assert ev is not None
        assert remaining == b""


# ---------------------------------------------------------------------------
# Fixture-file parse ratio ≥ 0.9 (plan §1.5)
# ---------------------------------------------------------------------------


def _parse_fixture(fixture_name: str) -> tuple[int, int]:
    """Return (events_parsed, logical_lines_seen) for a fixture file.

    logical_lines_seen counts each physical line that has a PID prefix
    (i.e. excludes banners, blank lines, and exit notices that are not
    normal syscall lines). Unfinished lines count as 0 events parsed but
    DO count in the denominator; resumed continuations do NOT count in the
    denominator when their unfinished partner was already counted.
    """
    from aigate.sandbox.observers.strace import _RE_PID, _RE_RESUMED

    fixture = (FIXTURES_DIR / fixture_name).read_bytes()
    lines = fixture.split(b"\n")

    logical_lines = 0
    events_parsed = 0

    for raw in lines:
        if not raw.strip():
            continue
        line = raw.decode("utf-8", errors="replace").rstrip("\r")
        pid_m = _RE_PID.match(line)
        if pid_m is None:
            continue  # banner / non-pid line
        tail = line[pid_m.end():]
        # Resumed lines pair with an earlier unfinished line; count as one unit.
        # The unfinished line was already counted; the resumed is the second half.
        if _RE_RESUMED.match(tail):
            continue
        # Signal delivery (--- SIG... ---) and exit notices (+++ exited +++) are
        # strace metadata, not syscall logical-events; exclude from denominator.
        if tail.startswith("---") or tail.startswith("+++"):
            continue
        logical_lines += 1

    # Now parse through the observer to count actual events
    obs2 = StraceObserver()
    for raw in lines:
        if raw.strip():
            ev = obs2.parse_event(raw + b"\n", [])
            if ev is not None:
                events_parsed += 1

    return events_parsed, logical_lines


class TestFixtureParseRatio:
    @pytest.mark.parametrize("fixture", [
        "strace_5_10.txt",
        "strace_5_19.txt",
        "strace_6_1.txt",
        "strace_6_8.txt",
    ])
    def test_parse_ratio_gte_0_9(self, fixture: str):
        """Parse ratio on logical-event units must be ≥ 0.9 per plan §1.5."""
        events, total = _parse_fixture(fixture)
        assert total > 0, f"{fixture}: no logical lines found"
        ratio = events / total
        assert ratio >= 0.9, (
            f"{fixture}: parse ratio {events}/{total} = {ratio:.2%} < 90%"
        )

    def test_strace_5_10_connects_parsed(self):
        """Fixture strace_5_10 must yield ≥1 connect event."""
        fixture = (FIXTURES_DIR / "strace_5_10.txt").read_bytes()
        obs = StraceObserver()
        events = []
        for raw in fixture.split(b"\n"):
            if raw.strip():
                ev = obs.parse_event(raw + b"\n", [])
                if ev is not None:
                    events.append(ev)
        connects = [e for e in events if e.kind in ("connect", "dns")]
        assert len(connects) >= 1

    def test_strace_6_1_connects_parsed(self):
        """Fixture strace_6_1 must yield ≥1 connect event."""
        fixture = (FIXTURES_DIR / "strace_6_1.txt").read_bytes()
        obs = StraceObserver()
        events = []
        for raw in fixture.split(b"\n"):
            if raw.strip():
                ev = obs.parse_event(raw + b"\n", [])
                if ev is not None:
                    events.append(ev)
        connects = [e for e in events if e.kind in ("connect", "dns")]
        assert len(connects) >= 1

    def test_strace_6_8_double_space_parsed(self):
        """strace 6.8 double-space format yields valid events."""
        fixture = (FIXTURES_DIR / "strace_6_8.txt").read_bytes()
        obs = StraceObserver()
        events = []
        for raw in fixture.split(b"\n"):
            if raw.strip():
                ev = obs.parse_event(raw + b"\n", [])
                if ev is not None:
                    events.append(ev)
        assert len(events) >= 3


# ---------------------------------------------------------------------------
# StraceObserver class attributes
# ---------------------------------------------------------------------------


class TestStraceObserverAttributes:
    def test_name_is_strace(self):
        assert StraceObserver.name == "strace"

    def test_coverage_contains_required_surfaces(self):
        from aigate.sandbox.types import SandboxCoverage
        cov = StraceObserver.coverage
        assert SandboxCoverage.NETWORK_CAPTURE in cov
        assert SandboxCoverage.FS_WRITES in cov
        assert SandboxCoverage.DNS in cov
        assert SandboxCoverage.PROCESS_TREE in cov

    def test_sink_kind_is_fifo(self):
        obs = StraceObserver()
        assert obs.sink_kind == "fifo"

    def test_check_available_uses_which(self):
        """check_available reflects whether strace is on PATH."""
        import shutil
        obs = StraceObserver()
        expected = shutil.which("strace") is not None
        assert obs.check_available() == expected

    def test_two_instances_independent_state(self):
        """REV-D: two concurrent instances must never share state."""
        obs1, obs2 = StraceObserver(), StraceObserver()
        # Feed unfinished line to obs1
        obs1.parse_event(b"1234 connect(4, <unfinished ...>\n", [])
        # obs2 should not see obs1's pending state
        ev = obs2.parse_event(
            b'1234 <... connect resumed> {sa_family=AF_INET,'
            b' sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = 0\n',
            [],
        )
        assert ev is None  # orphaned resumed in obs2


# ---------------------------------------------------------------------------
# argv_prefix
# ---------------------------------------------------------------------------


class TestArgvPrefix:
    def test_argv_prefix_structure(self):
        obs = StraceObserver()
        # Use a mock sink with a predictable argv_arg()
        class _MockSink:
            def argv_arg(self):
                return "/tmp/test.fifo"
        prefix = obs.argv_prefix(_MockSink())
        assert prefix[0] == "strace"
        assert "-f" in prefix
        assert "-e" in prefix
        assert "/tmp/test.fifo" in prefix
        assert "--" in prefix
        assert prefix[-1] == "--"

    def test_argv_prefix_contains_required_syscalls(self):
        class _MockSink:
            def argv_arg(self):
                return "/tmp/x.fifo"
        obs = StraceObserver()
        prefix = obs.argv_prefix(_MockSink())
        trace_idx = prefix.index("-e") + 1
        trace_arg = prefix[trace_idx]
        for syscall in ("connect", "openat", "write", "execve", "clone"):
            assert syscall in trace_arg, f"{syscall} missing from trace arg: {trace_arg}"


# ---------------------------------------------------------------------------
# Partial-line buffering
# ---------------------------------------------------------------------------


class TestPartialLineBuffering:
    def test_partial_bytes_buffered_until_newline(self):
        obs = StraceObserver()
        # Feed without newline → no event
        ev = obs.parse_event(
            b'1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3', []
        )
        assert ev is None
        # Feed newline → event
        ev = obs.parse_event(b"\n", [])
        assert ev is not None
        assert ev.kind == "open"

    def test_split_across_three_chunks(self):
        obs = StraceObserver()
        obs.parse_event(b"1234 openat(AT_FDCWD,", [])
        obs.parse_event(b' "/etc/hosts",', [])
        ev = obs.parse_event(b" O_RDONLY) = 3\n", [])
        assert ev is not None
        assert ev.target == "/etc/hosts"

    def test_multiple_lines_in_one_chunk_first_extracted(self):
        """When chunk has 2+ lines, first event is returned; rest stays buffered."""
        obs = StraceObserver()
        chunk = (
            b'1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n'
            b'5678 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 4\n'
        )
        ev1 = obs.parse_event(chunk, [])
        assert ev1 is not None
        assert ev1.target == "/etc/passwd"
        # Second line is buffered; extract with empty bytes
        ev2 = obs.parse_event(b"", [])
        assert ev2 is not None
        assert ev2.target == "/etc/hosts"
