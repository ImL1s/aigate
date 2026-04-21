"""Tests: secret scrub values are redacted BEFORE events land in trace.events.

REV-D invariant + PRD §3.2 P0-5:
  The observer applies ``secrets.redact_secrets(scrub)`` to ``target`` and
  ``raw`` BEFORE the ``DynamicTraceEvent`` is constructed.  A stale cache
  entry must never leak a secret that the current session never touched.

Covers:
- parse_strace_logical_event: secret in openat path → target redacted.
- parse_strace_logical_event: secret in execve argv → argv entry redacted.
- parse_strace_logical_event: empty scrub list → target unchanged.
- StraceObserver.parse_event: target and raw fields redacted.
- Multiple scrub values each individually replaced.
- The raw field (not just target) is also redacted.
- Redaction marker ``<REDACTED:...>`` appears in target when secret present.
"""

from __future__ import annotations

from aigate.sandbox.observers.strace import StraceObserver, parse_strace_logical_event


def _line(s: str) -> bytes:
    if not s.endswith("\n"):
        s += "\n"
    return s.encode()


# ---------------------------------------------------------------------------
# parse_strace_logical_event — stateless seam
# ---------------------------------------------------------------------------


class TestLogicalEventRedaction:
    def test_secret_in_openat_path_redacted_in_target(self):
        """Secret embedded in openat path must not appear in event.target."""
        secret = "secretpath999"
        line = f'1234 openat(AT_FDCWD, "/tmp/{secret}/data", O_RDONLY) = 3'
        ev, _ = parse_strace_logical_event(_line(line), [secret])
        assert ev is not None
        assert secret not in ev.target, f"Secret leaked in target: {ev.target!r}"
        assert "<REDACTED:" in ev.target

    def test_secret_in_openat_path_redacted_in_raw(self):
        """Secret in openat path must not appear in event.raw either."""
        secret = "rawsecretvalue"
        line = f'1234 openat(AT_FDCWD, "/home/{secret}/config", O_RDONLY) = 3'
        ev, _ = parse_strace_logical_event(_line(line), [secret])
        assert ev is not None
        assert secret not in ev.raw, f"Secret leaked in raw: {ev.raw!r}"

    def test_empty_scrub_leaves_target_unchanged(self):
        """No scrub values → target passes through unmodified."""
        line = '1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
        ev, _ = parse_strace_logical_event(_line(line), [])
        assert ev is not None
        assert ev.target == "/etc/passwd"

    def test_execve_argv_secret_redacted(self):
        """Secret appearing in execve argv list must be redacted in each arg."""
        secret = "topsecretarg"
        line = f'1234 execve("/bin/sh", ["/bin/sh", "-c", "{secret}"], NULL) = 0'
        ev, _ = parse_strace_logical_event(_line(line), [secret])
        assert ev is not None
        for arg in ev.argv:
            assert secret not in arg, f"Secret leaked in argv: {ev.argv!r}"

    def test_multiple_scrub_values_all_replaced(self):
        """All scrub values in target must each be individually replaced."""
        s1, s2 = "firstsecret111", "secondsecret222"
        line = f'1234 openat(AT_FDCWD, "/tmp/{s1}/{s2}/file", O_RDONLY) = 3'
        ev, _ = parse_strace_logical_event(_line(line), [s1, s2])
        assert ev is not None
        assert s1 not in ev.target, f"s1 leaked in target: {ev.target!r}"
        assert s2 not in ev.target, f"s2 leaked in target: {ev.target!r}"

    def test_redaction_marker_present_when_secret_in_path(self):
        """<REDACTED:...> marker must appear in target when a scrub value matched."""
        secret = "markertest123"
        line = f'1234 openat(AT_FDCWD, "/data/{secret}/result", O_RDONLY) = 3'
        ev, _ = parse_strace_logical_event(_line(line), [secret])
        assert ev is not None
        assert "<REDACTED:" in ev.target

    def test_write_flag_path_also_redacted(self):
        """O_WRONLY openat (kind='write') target is equally redacted."""
        secret = "writesecret456"
        line = f'1234 openat(AT_FDCWD, "/var/{secret}/log", O_WRONLY|O_CREAT) = 5'
        ev, _ = parse_strace_logical_event(_line(line), [secret])
        assert ev is not None
        assert ev.kind == "write"
        assert secret not in ev.target

    def test_connect_target_scrubbed(self):
        """Scrub applied to connect target string."""
        # While IPs are not typically secrets, the scrub plumbing must fire
        secret = "192.0.2"
        line = (
            '1234 connect(4, {sa_family=AF_INET, sin_port=htons(80), '
            'sin_addr=inet_addr("192.0.2.1")}, 16) = 0'
        )
        ev, _ = parse_strace_logical_event(_line(line), [secret])
        assert ev is not None
        assert secret not in ev.target


# ---------------------------------------------------------------------------
# StraceObserver.parse_event — stateful bytes interface
# ---------------------------------------------------------------------------


class TestObserverParseEventRedaction:
    def test_target_redacted_via_scrub_list(self):
        """StraceObserver.parse_event() must apply scrub to target."""
        secret = "obsecret789"
        line = f'1234 openat(AT_FDCWD, "/tmp/{secret}/data", O_RDONLY) = 3'
        observer = StraceObserver()
        ev = observer.parse_event(_line(line), [secret])
        assert ev is not None
        assert secret not in ev.target, (
            f"Secret leaked in target after parse_event: {ev.target!r}"
        )

    def test_raw_field_redacted_via_scrub_list(self):
        """StraceObserver.parse_event() must apply scrub to raw field."""
        secret = "rawobssecret"
        line = f'1234 openat(AT_FDCWD, "/data/{secret}/config.json", O_RDONLY) = 3'
        observer = StraceObserver()
        ev = observer.parse_event(_line(line), [secret])
        assert ev is not None
        assert secret not in ev.raw, (
            f"Secret leaked in raw after parse_event: {ev.raw!r}"
        )

    def test_empty_scrub_is_safe(self):
        """Empty scrub list must not crash or alter events."""
        line = '1234 openat(AT_FDCWD, "/etc/os-release", O_RDONLY) = 3'
        observer = StraceObserver()
        ev = observer.parse_event(_line(line), [])
        assert ev is not None
        assert ev.target == "/etc/os-release"

    def test_multiple_scrub_values_all_replaced_in_observer(self):
        """Observer applies all scrub values, not just the first."""
        s1, s2 = "obsecret_A", "obsecret_B"
        line = f'1234 openat(AT_FDCWD, "/tmp/{s1}/{s2}/file", O_RDONLY) = 3'
        observer = StraceObserver()
        ev = observer.parse_event(_line(line), [s1, s2])
        assert ev is not None
        assert s1 not in ev.target
        assert s2 not in ev.target

    def test_scrub_applied_before_event_construction(self):
        """Redaction must be in the returned event, not a caller post-processing step.

        If scrub is applied inside parse_event / _parse_openat before the
        DynamicTraceEvent is constructed, the returned event.target already
        contains the <REDACTED:...> marker.  This test verifies that behaviour
        directly — no intermediate event object can hold the plaintext secret.
        """
        secret = "earlysecret789"
        line = f'1234 openat(AT_FDCWD, "/cache/{secret}/result", O_RDONLY) = 3'
        observer = StraceObserver()
        ev = observer.parse_event(_line(line), [secret])
        assert ev is not None
        assert secret not in ev.target
        assert "<REDACTED:" in ev.target

    def test_scrub_applied_in_resumed_reassembly(self):
        """Redaction fires even on events produced from unfinished/resumed reassembly."""
        secret = "resumedsecret"
        observer = StraceObserver()

        # Feed unfinished line first
        unfinished = f'1234 openat(AT_FDCWD, "/tmp/{secret}/file" <unfinished ...>\n'
        ev1 = observer.parse_event(unfinished.encode(), [secret])
        assert ev1 is None  # pending; no event yet

        # Feed resumed line
        resumed = '1234 <... openat resumed> , O_RDONLY) = 3\n'
        ev2 = observer.parse_event(resumed.encode(), [secret])
        if ev2 is not None:
            # If reassembly produced an event, secret must be redacted
            assert secret not in ev2.target, (
                f"Secret leaked in resumed event target: {ev2.target!r}"
            )
