# Sandbox Phase 1b Runbook

Operational guide for aigate's Birdcage-backed npm sandbox
(`--sandbox` / `--sandbox-mode=light`).

---

## Why no network egress

The sandbox enforces **tier-aware** network isolation, not a single universal
block:

| Platform | Mechanism | Strength |
|---|---|---|
| **macOS** | `sandbox-exec` SBPL `(deny network*)` | **Kernel-enforced** — XNU blocks every TCP/UDP/DNS socket before the package code can call `connect(2)` |
| **Linux** | `npm --offline` + `NPM_CONFIG_REGISTRY=http://127.0.0.1:1` + connect-observer (strace/bpftrace) | **Cooperative + observed** — npm client won't connect; rogue scripts are observed but not kernel-blocked (Landlock ≤6.6 has no network primitive) |

In both cases the npm tarball is downloaded **before** the sandbox starts:
`BirdcageBackend.run()` downloads the tarball from the registry, writes it
to a tempfile on the host, and passes the local path to `npm install <path>`.
The sandboxed process never needs to reach the registry.

`NPM_CONFIG_REGISTRY=http://127.0.0.1:1` is set in the subprocess environment
as a belt-and-suspenders measure: even if npm ignores `--offline`, any
registry connection attempt lands on a loopback port that is not listening and
fails immediately.

---

## Installing a Linux connect-observer

`aigate doctor --sandbox` shows the detected observer:

```
connect-observer: strace      ← OK
connect-observer: NONE        ← DEGRADED
```

Install one of the following:

```bash
# Debian / Ubuntu
sudo apt-get install strace

# macOS (bpftrace; strace is Linux-only)
brew install bpftrace

# Fedora / RHEL
sudo dnf install strace
```

`bpftrace` requires kernel ≥4.9 with BPF JIT enabled. `strace` works on any
Linux kernel that permits `ptrace(2)` (standard distros).

**Birdcage native observer** (future): once `birdcage --version` exposes a
feature flag for the built-in connect probe, `detect_linux_connect_observer()`
will prefer it over strace/bpftrace without requiring a separate install.

---

## Troubleshooting

### `aigate doctor --sandbox` shows `connect-observer: NONE`

The sandbox will still run on Linux but network observation is disabled —
connect events will not appear in `DynamicTrace.events`. The trace floor check
(`has_observation_failure()`) may trip if the package is quiet.

**Fix:** install `strace` (see above) and re-run `aigate doctor --sandbox` to
confirm detection.

### `SandboxUnavailable: No sandbox backend available`

Birdcage binary is not on `PATH`.

```bash
cargo install birdcage
```

If you do not have Rust/Cargo:

```bash
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
cargo install birdcage
```

Then verify:

```bash
birdcage --version
aigate doctor --sandbox
```

### `BIRDCAGE_MIN_VERSION` mismatch

aigate requires Birdcage ≥ 0.5.0. If your installed version is older:

```bash
cargo install birdcage --force
birdcage --version
```

The `BIRDCAGE_TESTED_MAX_VERSION` constant in `birdcage_backend.py` records
the highest version tested. Versions above this are accepted with a log
warning — newer birdcage should be backward-compatible but may emit new
event kinds that produce `PARSER_PARTIAL_DRIFT` until the parser is updated.

### Parser drift warnings (`PARSER_PARTIAL_DRIFT` in skipped_unexpected)

Birdcage emits JSON-lines on stdout. If a Birdcage version changes its event
schema, `parse_birdcage_stream()` may fail to parse some lines. The parse
ratio floor is 50% (`DynamicTrace.PARSE_RATIO_FLOOR = 0.5`):

- **< 50% parsed:** `PARSER_PARTIAL_DRIFT` added to `skipped_unexpected` →
  `has_observation_failure()` returns `True` → verdict escalates to
  `NEEDS_HUMAN_REVIEW`.
- **0 / N parsed:** same escalation + error message `"parser matched 0/N lines"`.

**Fix:** upgrade aigate to a version that supports the new Birdcage schema, or
pin birdcage to `BIRDCAGE_TESTED_MAX_VERSION`.

### Sandbox timeout

`BirdcageBackend.run()` kills the subprocess and sets `trace.timeout = True`
after `SandboxRunRequest.timeout_s` seconds (default: `sandbox.timeout_s` from
`.aigate.yml`, default 60 s). A timeout is treated as an observation failure.

**Fix:** increase the timeout:

```bash
aigate check <pkg> -e npm --sandbox --sandbox-timeout 120
```

Or in `.aigate.yml`:

```yaml
sandbox:
  timeout_s: 120
```
