# Birdcage Output Shape Decision

**Research date:** 2026-04-21  
**Researcher:** worker-1  
**Repo HEAD SHA:** d0c625188385bbdb77bddd1a16408e7c20d22a9f (phylum-dev/birdcage main)

---

## 1. Linux channel

### What Birdcage emits on Linux

Birdcage on Linux uses Linux namespaces (`CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET`) to sandbox a child process via `libc::clone()`.

**Emission inventory** (grep for `println!` / `eprintln!` / `log::` / `fs::write` across all of `src/linux/`):

| Location | Macro | Condition | Content |
|---|---|---|---|
| `src/linux/mod.rs:164` | `eprintln!` | sandbox init failure only | `"sandboxing failure: {err}"` |

That is the **only** emission point in the entire Linux implementation. Under normal operation, Birdcage emits nothing.

**Internal IPC (not a user-facing channel):**  
`src/linux/mod.rs:232` writes 4 bytes (signal number, little-endian) to `exit_signal_tx` (an `OwnedFd` pipe) when the sandboxee is killed by a signal. This is internal signalling between the sandbox init process and the parent — not visible as stdout/stderr.

**Child output access:**  
The Linux `Child` struct (`src/process/linux.rs`) wraps piped `OwnedFd` handles for the sandboxee's stdout and stderr. The caller reads these after `child.wait()` or by consuming `child.stdout` / `child.stderr` directly.

### Candidates for our output channel (≤3)

| # | Channel | Description | Tradeoffs |
|---|---|---|---|
| **A** | **stdout JSON-lines** | Our inspection script, running inside the sandbox, writes JSON-lines to stdout. Birdcage pipes this to the parent via `ChildStdout`. | ✅ Zero Birdcage changes. ✅ Structured, parseable. ✅ Works on both platforms identically. ⚠️ Script must not write non-JSON to stdout. |
| B | stderr structured | Inspection script writes JSON-lines to stderr instead. | ✅ Separates diagnostic noise from structured data. ⚠️ Unconventional; `eprintln!("sandboxing failure: …")` from Birdcage would mix in on init failure. |
| C | Side-channel log file | Script writes a JSON log file to a tmpdir with `Exception::WriteAndRead` granted. | ✅ Clean separation. ⚠️ Requires an extra `Exception` grant. ⚠️ Race condition if process is killed mid-write. ⚠️ Cleanup burden. |

**Chosen (Linux): Option A — stdout JSON-lines.**

---

## 2. macOS channel

### What Birdcage emits on macOS

Birdcage on macOS uses `sandbox_init()` (Apple Seatbelt / SBPL — Sandbox Profile Language). The profile is generated in-process and applied via an FFI call to a private Apple framework.

**Emission inventory** (full scan of `src/macos.rs`, 239 lines):

| Location | Macro | Condition | Content |
|---|---|---|---|
| *(none)* | — | — | — |

There are **zero** `println!`, `eprintln!`, `log::`, `tracing::`, or `fs::write` calls in `src/macos.rs`.

The macOS `Child` is a **direct re-export of `std::process::Child`** (`src/process/macos.rs:1-4`). After `sandbox_init()` applies the SBPL profile, the process simply spawns the sandboxee with `sandboxee.spawn()`.

### Does macOS emit events?

**No.** SBPL violations are enforced silently at the XNU kernel level. When a sandboxed process attempts a denied operation:
- The syscall returns `EPERM` / `EACCES` to the process.
- No event is delivered to user space by Seatbelt.
- Apple's **EndpointSecurity** framework _could_ observe denials, but it requires a system extension entitlement, a signed binary, and root/SIP approval — not available in a library context.
- **DTrace** could capture violation events, but requires SIP disabled or an unrestricted DTrace entitlement.
- **fanotify** does not exist on macOS.

### Candidates for macOS (≤3)

| # | Channel | Feasibility | Notes |
|---|---|---|---|
| **A** | **stdout JSON-lines (DEGRADED)** | ✅ Feasible | Same design as Linux. We see what the script reports, not what the sandbox blocked. Violations are silent. |
| B | DTrace wrapping | ⚠️ Requires SIP disabled or `com.apple.security.cs.allow-unsigned-executable-memory` entitlement + restricted proc tracing. Not viable for an unprivileged library. | |
| C | EndpointSecurity framework | ❌ Requires system extension + notarization + user approval. Not viable without macOS System Extension distribution. | |

**Chosen (macOS): Option A — stdout JSON-lines, with DEGRADED posture.**

macOS DEGRADED means: the sandbox prevents filesystem/network access (SBPL rules are enforced), but we cannot observe _which_ accesses were attempted or denied. Our inspection script reports what it successfully read; it cannot report what was blocked.

### DEGRADED sign-off

**macOS posture is DEGRADED**: sandbox enforcement is real (SBPL denies restricted access), but violation visibility is zero. The `BirdcageBackend` on macOS will report what the inspection script outputs — it will not report sandbox denial events. This is an accepted limitation of the Seatbelt architecture.

---

## 3. Chosen options

| Platform | Channel | Rationale |
|---|---|---|
| **Linux** | `stdout` JSON-lines from inspection script | Birdcage pipes child stdout to parent via `ChildStdout` (`src/process/linux.rs`). No Birdcage changes required. Standard, structured, cross-platform consistent. |
| **macOS** | `stdout` JSON-lines from inspection script (DEGRADED) | macOS `Child` is `std::process::Child` — stdout is already piped. SBPL enforces policy silently; we accept zero violation visibility. |

**Wire format (both platforms):** One JSON object per line on stdout. Each line is a complete, self-contained event. Example:

```jsonl
{"event":"file_read","path":"/etc/passwd","status":"denied"}
{"event":"network_connect","host":"pypi.org","status":"allowed"}
{"event":"exit","code":0}
```

The parser (`BirdcageEventParser`) reads lines from `child.stdout`, deserialises each, and accumulates into a `SandboxReport`. Lines that fail JSON parse are treated as `PARSER_PARTIAL_DRIFT` events (logged, not fatal).

---

## 4. User sign-off checkbox

- [ ] **User signed off on macOS DEGRADED posture** — SBPL enforces sandbox policy but emits no violation events to user space. The `BirdcageBackend` on macOS cannot report which filesystem/network accesses were denied. Confirm this is acceptable before shipping Phase 1b on macOS.

---

## 5. Version bounds

| Constant | Value | Source |
|---|---|---|
| `BIRDCAGE_MIN_VERSION` | `0.5.0` | Conservative floor: tags exist from v0.2.1; v0.5.0 is chosen as the earliest version where both Linux namespace + macOS Seatbelt paths are confirmed stable. No formal release notes published (GitHub releases page is empty — only git tags exist). |
| `BIRDCAGE_TESTED_MAX_VERSION` | `0.8.1` | `Cargo.toml:version = "0.8.1"` in HEAD (SHA `d0c6251`); latest git tag is `v0.8.1`. |

**Rust minimum:** `1.70.0` (from `Cargo.toml:rust-version = "1.70.0"`).

**Note on releases:** The GitHub releases page for `phylum-dev/birdcage` shows "There aren't any releases here" — the project uses git tags only. Version bounds above are derived from `Cargo.toml` and `gh api repos/phylum-dev/birdcage/tags`.

---

## 6. Evidence links

| Claim | Source |
|---|---|
| Linux: only `eprintln!` on init failure | `src/linux/mod.rs:164` — SHA `d0c6251` |
| Linux: child stdout/stderr via pipes | `src/linux/mod.rs:62-65` (pipe creation), `src/process/linux.rs` (Child struct) |
| Linux: exit signal pipe (internal IPC) | `src/linux/mod.rs:232` |
| Linux: namespace flags | `src/linux/mod.rs:135-137` |
| macOS: zero emission points | `src/macos.rs` (full file, 239 lines) — SHA `d0c6251` |
| macOS: `sandbox_init` FFI | `src/macos.rs:80,237-238` |
| macOS: Child = std::process::Child | `src/process/macos.rs:1-4` |
| macOS: silent SBPL denial (no events) | Apple Seatbelt design; confirmed by absence of any event callback in `src/macos.rs` |
| Version 0.8.1 in Cargo.toml | `Cargo.toml:3` (version), `Cargo.toml:5` (rust-version) |
| Tags list (v0.2.1 → v0.8.1) | `gh api repos/phylum-dev/birdcage/tags` |
| Repo HEAD SHA | `d0c625188385bbdb77bddd1a16408e7c20d22a9f` (main, 2026-04-21) |
| GitHub repo | https://github.com/phylum-dev/birdcage |
| Linux mod.rs (full) | https://github.com/phylum-dev/birdcage/blob/main/src/linux/mod.rs |
| macOS mod (full) | https://github.com/phylum-dev/birdcage/blob/main/src/macos.rs |
| process/mod.rs | https://github.com/phylum-dev/birdcage/blob/main/src/process/mod.rs |
