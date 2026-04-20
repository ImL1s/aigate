# Sandbox Mode (Phase 1 Scaffold)

aigate sandbox mode runs `pip install` / `npm install` / `cargo build` inside
an isolated, **observe-not-deny** environment that emits a structured
`DynamicTrace` for downstream AI consensus and policy evaluation.

This document tracks the public contract for Phase 1. Implementation details,
backend wiring, and strict-mode Docker escalation are covered in the PRD
(`.omc/plans/aigate-sandbox-mode-prd.md` §3).

> Status: **Phase 1b — npm light mode shipped.** The `--sandbox` flag routes
> npm packages through the Birdcage backend (macOS `sandbox-exec` + Linux
> Landlock); other ecosystems and strict mode ship in later phases.

## Design principles

1. **Observe, don't deny.** Credential paths, shell RC files, and autostart
   dirs are **decoy bind-mounts** (Linux) or **scratch-`$HOME` redirects**
   (macOS), not `EACCES` denials. A malicious package thinks its write
   succeeded; the observer records the event.
2. **Cross-platform first.** Birdcage (Landlock on Linux, `sandbox-exec` on
   macOS) is tier-1. Docker + Tracee is tier-2 (`--sandbox=strict`).
   No Docker dependency on the default macOS path.
3. **Transparent coverage.** The set of side-effect classes that are NOT
   dynamically observable is publicly enumerated (see matrix below). Static
   scanning (prefilter §3.9 + Phase 3 evasion) picks up what dynamic
   observation cannot.
4. **Observability floor.** Every run must produce ≥3 distinct event kinds
   OR ≥10 total events for a ≥2s install run. Falling below the floor trips
   `has_observation_failure()` → `NEEDS_HUMAN_REVIEW`.

## Coverage matrix (PRD v3.1 §3.2)

Reproduced from the PRD as the authoritative Phase 1 contract. Test fixtures
under `tests/sandbox/` lock every **COVERED** row; every **PARTIAL** or
**NOT COVERED** row has a corresponding `SandboxCoverage` value in
`DynamicTrace.skipped_expected` so AI prompts and policy code can reason
about the gap instead of silently defaulting SAFE.

| Side-effect class | v3.1 coverage | Detection surface | Status |
|---|---|---|---|
| File read of credential path (`~/.ssh/id_rsa`, `~/.aws/credentials`) | **COVERED** | canary bind-mount + `canary_touched(HIGH)` | v1 in scope |
| File write to autostart (`~/.bashrc`, `~/Library/LaunchAgents/*.plist`, `/etc/cron.d/*`) | **COVERED** (via decoy bind-mount on Linux / `$HOME` scratch on macOS) | `persist_write(HIGH)` | v1 in scope |
| Environment variable **read** of secret (`AWS_SECRET_ACCESS_KEY`) | **COVERED** | strace getenv / DTrace; redacted via SECRET_ENV_PATTERNS; `credential_env_read(HIGH)` | v1 in scope |
| Environment variable **mutation** (`os.environ['SSH_AUTH_SOCK'] = '/tmp/evil'`) | **NOT COVERED DYNAMICALLY** | process-internal; dies with sandbox teardown. Partial mitigation: static scan for `os.environ[...]=` writes to known-sensitive names. | `OUT_OF_SCOPE_v1`; `latent_env_mutation(LOW)` static-only signal in Phase 3 evasion detector |
| macOS Keychain write (`security add-generic-password`, direct XPC to `securityd`) | **PARTIAL** | exec-event capture of `/usr/bin/security`; direct XPC IPC NOT observable without Endpoint Security | `xpc_keychain_write(MEDIUM)` on exec-path only; direct-XPC marked `OUT_OF_SCOPE_v1` |
| Linux Keychain / Secret Service (`secret-tool`, D-Bus to `org.freedesktop.secrets`) | **PARTIAL** | exec-event capture of `/usr/bin/secret-tool`; raw D-Bus NOT observable in light mode (strict mode via Tracee dbus signatures Phase 4) | Phase 4 scope |
| `launchctl load` / `systemctl --user start` / `crontab -e` post-sandbox registration | **PARTIAL** | exec-event captures the command invocation; the post-sandbox effect (persistence firing on next login / cron tick) is never observed inside the sandbox lifetime. The plist/service/crontab FILE write IS covered by decoy §3.9 latent-persistence scan. | COVERED (write) + PARTIAL (registration) |
| Shell-spawn state mutation against host (`sudo chmod 777 /`, `rm -rf ~/Documents`) | **PARTIAL** | In sandbox, `sudo` is blocked / fails; decoy bind-mounts absorb writes to documented canary paths; un-canaried host paths outside the decoy plane on macOS-light (see **macOS absolute-path-write gap** below) are not covered | Same surface as the macOS gap — strict-mode (Docker) closes, Birdcage-light partial |
| Outbound exfil of canary token literal | **COVERED** | mitmproxy + dnsmasq capture; `canary_exfil(HIGH)` | v1 in scope |
| Outbound exfil of **derived** canary (e.g. `sha256(id_rsa)`) | **NOT COVERED** | derivation hides the plaintext; cannot detect transform-then-exfil without content inspection of every outbound byte | `OUT_OF_SCOPE_v1`; documented limitation |
| In-memory-only secret processing (read → use → never write/exfil) | **COVERED (read event)** | read alone fires `canary_touched(HIGH)` regardless of what happens next | v1 in scope |

**Classification key:**

- **COVERED:** v1 test-fixture-locked; `DynamicTrace` events + signatures fire.
- **PARTIAL:** v1 catches a subset (typically exec-path); some sub-cases
  require Phase 4 strict-mode Tracee signatures or are explicit
  `OUT_OF_SCOPE_v1`.
- **NOT COVERED / `OUT_OF_SCOPE_v1`:** explicitly acknowledged gap. The
  AI prompt template (`DynamicTrace.to_prompt_section()`) includes a
  "Known unobservable classes" note so the model does not default SAFE
  when one of these would otherwise be the plausible attack class.

`DynamicTrace.skipped_expected` takes values from the `SandboxCoverage` enum,
including `ENV_MUTATION`, `DIRECT_XPC`, `DBUS_RAW`, `DERIVED_EXFIL`, and
`CANARY_ABSOLUTE_PATH_WRITES` (macOS only — see below).

## macOS absolute-path-write gap (Birdcage light mode)

Linux Birdcage uses `mount --bind` to overlay canary decoys onto sensitive
paths. macOS `sandbox-exec` does NOT provide bind-mounts (SBPL is a
path-based syscall allowlist/denylist, not a VFS overlay). Phase 1 adopts
a combined mitigation for macOS Birdcage light mode:

1. **Scratch-`$HOME` redirection (primary):** the install subprocess is
   launched with `HOME=/tmp/aigate-decoy-<run>/home` plus a mirrored
   canary tree (`.ssh/id_rsa`, `.aws/credentials`, `.npmrc`, `.pypirc`,
   `.gitconfig`, `.netrc`, …). Any code path that honours `$HOME`
   (`os.path.expanduser`, `os.homedir()`, `dirs::home_dir()`) sees the
   canary tree; writes succeed against decoys.
2. **`sandbox-exec` path-rule redirect (secondary):** hardcoded absolute
   paths that bypass `$HOME` (`/Users/<username>/.ssh/id_rsa`,
   `/etc/shadow`) are allowed via an SBPL rule coupled with a
   process-launch-time symlink into the per-run scratch root. Writes route
   under the same scratch root; elsewhere `(deny file-write*)` preserves
   observe-not-deny semantics.
3. **Residual gap — `CANARY_ABSOLUTE_PATH_WRITES`:** hardcoded absolute
   **writes** that land OUTSIDE the `$HOME`-rewrite plane AND OUTSIDE the
   SBPL-allowlisted scratch (e.g. a package that writes
   `/etc/cron.d/evil` directly by absolute path) hit the SBPL deny rule
   and fail silently with `EACCES`. This is the v2-era
   EACCES-laundering case and it is the ONLY observable side-effect class
   where macOS Birdcage light mode has reduced coverage vs. Linux.

   `BIRDCAGE_EXPECTED_SKIPS` on macOS includes `CANARY_ABSOLUTE_PATH_WRITES`
   so `has_observation_failure()` does not over-trigger on benign packages
   that never touch that plane. Strict-mode Docker (`--sandbox=strict`)
   does NOT have this gap — strict-only integration fixtures assert the
   Docker path catches what macOS-light cannot.

**User-visible commitment:** macOS light mode has reduced observe-not-deny
coverage for **hardcoded-absolute-path writes outside `$HOME`** vs Linux.
All other canary classes (credential reads, shell-RC writes via `$HOME`,
persistence autostart in `~/Library/LaunchAgents`) are covered symmetrically.

**Closing the gap:** run `aigate check <pkg> --sandbox=strict` on macOS to
invoke the Docker+Tracee backend, which supplies `FS_WRITES` coverage for
arbitrary absolute paths via the Linux VM boundary.

Rejected alternatives:

- **Endpoint Security Framework:** requires notarised entitlement
  incompatible with `pip install aigate` distribution. Tracked as ADR
  follow-up #12 should aigate ever ship a signed `.pkg`.
- **Ship-only-Docker on macOS:** loses the "no-Docker macOS dev" principle
  that is the entire reason Birdcage exists as tier-1 (violates driver-1
  cross-platform reach).

## Phase 1 test locks

- `tests/sandbox/test_sandbox_canary_exfil_detected.py` — scoped to the
  covered plane on macOS; exercises full Linux surface.
- `tests/sandbox/test_macos_absolute_path_write_known_gap.py` — locks the
  gap as `skipped_expected=[CANARY_ABSOLUTE_PATH_WRITES]` (documented, not
  silent).
- `tests/sandbox/test_sandbox_log_redacts_known_secrets.py` — env-var and
  canary-path redaction in `.omc/logs/sandbox-*.jsonl`.
- `tests/sandbox/test_sandbox_log_redacts_echo_stdout.py` — exec-stdout
  canary/secret redaction.
- `tests/sandbox/test_sandbox_log_redacts_curl_argv.py` — argv-embedded
  secret redaction.
- `tests/sandbox/test_prompt_injection_resistance.py` — `to_prompt_section()`
  escapes jailbreak tokens inside observed bytes.

## macOS coverage matrix

Per-surface breakdown for `--sandbox` (Birdcage light mode) on macOS.
`sandbox-exec` / SBPL enforces at the kernel level; Linux Landlock ≤6.6 has
no network primitive, so network isolation is cooperative + observed only.

| Surface | macOS (SBPL) | Notes |
|---|---|---|
| `syscall_trace` | skipped | Birdcage is Landlock/SBPL only — no ptrace tracing in light mode |
| `network_capture` | **kernel-enforced** (`(deny network*)`) | All TCP/UDP/DNS blocked by XNU at the socket layer |
| `fs_writes` | **kernel-enforced** (SBPL `file-write*` allowlist) | Only `$SCRATCH_HOME` and `/tmp` writable |
| `process_tree` | skipped | No PID-namespace isolation; PID tracking is best-effort via resource_probe |
| `dns` | **kernel-enforced** (subsumed by `deny network*`) | Same socket-layer block as network_capture |
| `import_probe` | skipped (Phase 2) | Post-install probe commands not yet wired |
| `build_time_hooks` | **observed** (exec events) | `postinstall`/`preinstall` exec chain captured |
| `env_reads` | skipped | No uprobes without SIP-disabled root; DTrace restricted |
| `canary_absolute_path_writes` | skipped (known gap) | See §macOS absolute-path-write gap above |

## Linux-light enforcement tiers

Linux Landlock (kernel ≥5.13) provides filesystem isolation but **no network
primitive before kernel 6.7**. Network enforcement in light mode is therefore
split across three cooperating tiers — not kernel-enforced:

1. **Cooperative (npm client):** npm is invoked with `--offline`,
   `NPM_CONFIG_OFFLINE=true`, and `NPM_CONFIG_REGISTRY=http://127.0.0.1:1`.
   A well-behaved npm will not attempt registry connections. This is the first
   and cheapest line of defence.

2. **Observed (connect-observer: strace / bpftrace):** A connect-observer
   shadows the subprocess tree for `connect(2)` / `sendto(2)` syscalls.
   Any rogue postinstall script that bypasses npm's offline mode is recorded
   as a `connect` event in `DynamicTrace.events`. The observer is detected by
   `detect_linux_connect_observer()` at runtime; `aigate doctor --sandbox`
   surfaces the result.

3. **Kernel (Phase 4 — strict mode):** `--sandbox=strict` wires Docker +
   `seccomp` + `iptables` drop-all for kernel-enforced network denial. Until
   then, Linux network enforcement is cooperative + observed only.

**Implication:** on Linux light mode a determined postinstall script can
attempt a network connection without being kernel-blocked. The attempt IS
observed (tier 2) and recorded in the trace; the AI prompt marks the
`NETWORK_CAPTURE` surface as cooperative-only so the model does not treat
absence-of-event as proof of no-attempt.

## See also

- PRD: `.omc/plans/aigate-sandbox-mode-prd.md` (§3.2 authoritative coverage
  matrix, §3.9 latent-persistence static scan, Phase 4 strict-mode roadmap).
- `docs/attack-detection.md` — how dynamic signals feed the consensus prompt.
- `docs/architecture.md` — where `DynamicTrace` slots into
  `AnalysisReport`.
