# Sandbox Phase 3 Runbook — Evasion Detectors

This runbook documents the 7 evasion detectors deployed in Phase 3, their detection strategies, false-positive mitigation, and the T14 multi-evasion gate that enforces autonomous MALICIOUS blocking only when ≥2 orthogonal HIGH tactics are present with dynamic confirmation.

## Detector Catalog

| Detector | Category | Severity | Static Regex | Dynamic Trigger |
|---|---|---|---|---|
| `EnvMutationDetector` | `env_mutation` | HIGH | `os.environ[KEY] = ...` where KEY ∈ sensitive denylist (SSH_AUTH_SOCK, LD_PRELOAD, PYTHONPATH, NODE_PATH, etc.) | None (strace env_write events not yet emitted) |
| `TimeBombDetector` | `time_bomb` | HIGH | `time.time() > future_epoch` or `datetime.now() > datetime(year > 2026)` | Strace `sleep` syscall > 30 seconds |
| `BuildHooksDetector` | `build_hooks` | MEDIUM (HIGH on dynamic) | npm lifecycle hooks (preinstall, postinstall, install, prepare, prepublish) in package.json; Python setup.py subprocess calls; Rust build.rs presence | Exec event matching hook path + connect syscall within same trace window |
| `DerivedExfilDetector` | `derived_exfil` | HIGH | Base64/hex/zlib encoding call within 50 LOC of network sink (requests.post, fetch, https.request) | /tmp write events followed by connect syscall |
| `DirectXPCDetector` | `direct_xpc` | MEDIUM (escalated by T14 on Darwin) | macOS XPC tokens (xpc_connection_create, NSXPCConnection, mach_port_*) and Linux D-Bus tokens (dbus.SessionBus(), org.freedesktop.*, Gio.DBus) | Linux D-Bus: connect to /run/dbus or /run/user/*/bus |
| `AntiDebugDetector` | `anti_debug` | HIGH (MEDIUM static-only) | ptrace syscall patterns (PTRACE_TRACEME, PTRACE_ATTACH, ctypes.ptrace, IsDebuggerPresent, /proc/self/status TracerPid) | Strace exec event containing "ptrace" |
| `ParserPartialDriftDetector` | `parser_partial_drift` | MEDIUM | Static-only: none (parser drift is runtime observation) | SandboxCoverage.PARSER_PARTIAL_DRIFT in trace.skipped_unexpected |

**Coverage mapping (from `src/aigate/sandbox/types.py`):**
- `env_mutation` → `SandboxCoverage.ENV_MUTATION`
- `time_bomb` → implicit (no explicit enum constant)
- `build_hooks` → implicit
- `derived_exfil` → `SandboxCoverage.DERIVED_EXFIL`
- `direct_xpc` → `SandboxCoverage.DIRECT_XPC`
- `anti_debug` → implicit
- `parser_partial_drift` → `SandboxCoverage.PARSER_PARTIAL_DRIFT`

## False-positive Playbook

When a benign package trips a detector, follow this investigation flow:

1. **Inspect the trace** (if dynamic fire)
   - Run `aigate check <package> --sandbox --verbose` to see the full `DynamicTrace` JSON.
   - Confirm the event `kind`, `target`, and `timestamp` fields match the detector's expectation.
   - Example: if `build_hooks` fires on a benign postinstall, verify the exec and connect are both legitimate (e.g., postinstall downloading an optional prebuilt binary from an official CDN).

2. **Inspect risk_signals** (static + aggregated)
   - Check the `prefilter` output: `aigate check <package> --skip-sandbox --verbose`.
   - If the detector fired statically, confirm the matched source snippet with `grep -n "<pattern>" <package-path>`.
   - Is the match a true positive (malicious attempt) or benign code (legitimate polyfill, test, documentation)?

3. **Check fixture for similar negative case**
   - Browse `tests/fixtures/evasion/<detector>/neg_*.txt` files.
   - If a negative fixture already exists that matches the benign code pattern, the detector's regex should have been tuned to exclude it. If not, this is a regression.
   - If no matching negative fixture, consider adding one: `neg_<real-pkg>.txt` with `# Source: <path>@<sha>` header from the false-positive package.

4. **File issue with repro**
   - Create a GitHub issue: `"FP: <detector> flags <package> at <version>"`.
   - Attach: the package name/version, the matched source snippet (or event JSON if dynamic), your expected verdict, and rationale.
   - Link the relevant negative fixture (or propose a new one).

5. **Exclude via config (if confirmed FP)**
   - **Do not modify detector code.** Instead, update `.aigate.yml`:
     ```yaml
     sandbox:
       evasion_skipped_packages:
         - "package-name@>=1.0.0"  # Known FP: reason
     ```
   - Commit the config change with a note pointing to the GitHub issue.
   - Re-run tests: `pytest tests/test_evasion_aggregator.py -v` should still pass.

## DIRECT_XPC on macOS — Why It Stays in skipped_unexpected

### Observability Gap

On macOS, the system call tracing layer (via `sandbox-exec` + strace/dtruss) **does not observe XPC interprocess communication** at the kernel level. XPC is an opaque Mach-based RPC mechanism with no standard strace events. This is a documented Phase 2 limitation, not a bug.

### Static-Pairing Upgrade (D5 Option D)

Phase 3 addresses this gap with a **belt-and-braces** approach:

1. **`DirectXPCDetector` emits static signal** when source code contains XPC tokens (xpc_connection_create, NSXPCConnection, mach_port_*). Severity: MEDIUM (reflects that we're missing runtime observation).

2. **On Darwin, T14 escalation rule (Step 2)** — evaluated FIRST in the multi-evasion gate:
   ```
   if platform.system() == "Darwin"
      and set(categories_dict.keys()) == {"direct_xpc"}
      and current_verdict == SAFE:
       verdict = NEEDS_HUMAN_REVIEW
   ```
   This **standalone rule** escalates a lone static XPC hit from SAFE → NEEDS_HUMAN_REVIEW, ensuring users review any package that tries to bypass the sandbox via XPC.

3. **DIRECT_XPC remains in `skipped_unexpected`** — no change to `src/aigate/sandbox/types.py` or `SBPL_EXPECTED_SKIPS`. When a package emits actual XPC traffic at runtime (which the sensor cannot observe), the signal lands in `skipped_unexpected`, and `has_observation_failure()` still returns True, triggering the existing Phase 2 fail-closed path independently of T14.

### Phase 4 Roadmap

Phase 4 will promote `DIRECT_XPC` from static-pairing to **full dynamic observation** via macOS endpoint security framework (`EndpointSecurityClient` to hook XPC service registrations). This removes the static detector dependency and closes the observability gap permanently. Until then, static pairing + T14 belt-and-braces rule is the best we can do without a macOS system extension.

## Aggregator Rules

### Threshold and Collapse Logic

`THRESHOLD_INITIAL = 5` (defined in `src/aigate/sandbox/evasion/aggregator.py:17`). Tagged for telemetry-driven revisit after Phase 3 merge (F-10 in the plan).

**Collapse rule (REV-6 scenario 4):**
- Signals are grouped by category.
- **If a category has ANY HIGH or CRITICAL signal, NO collapse occurs for that category** — all signals in the cluster are preserved individually.
- For categories with only LOW/MEDIUM signals: if ≥ THRESHOLD_INITIAL signals exist in that category, they collapse into a single synthetic signal:
  ```
  RiskSignal(
    category=<same>,
    severity=<max-in-cluster>,
    description="multi_evasion_pattern: N signals aggregated"
  )
  ```
- All HIGH/CRITICAL signals are ALWAYS preserved individually.

**Rationale:** Collapse prevents signal fatigue on large packages (e.g., a utility library that legitimately reads environment variables in 6 places). But HIGH/CRITICAL signals must remain visible — a collapsed cluster must never hide a P0 issue.

### Preservation of Mixed Severity

If a category cluster contains **both MEDIUM and HIGH signals**, the HIGH signals prevent the entire cluster from collapsing. Both HIGH and MEDIUM signals appear in the output.

**Test:** `test_aggregator_preserves_mixed_severity_cluster` in `tests/test_evasion_aggregator.py` enforces this invariant.

## Tactic Coverage Matrix

| Tactic | Static Layer | Dynamic Layer | Notes |
|---|---|---|---|
| env_mutation | Yes (`os.environ[KEY] =` regex) | N/A (strace env_write events deferred) | HIGH severity; denylist covers sensitive vars (SSH_AUTH_SOCK, LD_PRELOAD, PYTHONPATH, NODE_PATH, PATH, HTTP/HTTPS_PROXY, token vars) |
| time_bomb | Yes (`time.time() > epoch` and `datetime.now() > year>2026` regex) | Yes (sleep > 30s events) | HIGH severity; both time source patterns; dynamic triggers on long sleeps (heuristic for timing gates) |
| build_hooks | Yes (npm lifecycle keys in package.json, setup.py subprocess, build.rs) | Yes (exec+connect correlation) | MEDIUM static, HIGH dynamic; correlates hook exec with network activity |
| derived_exfil | Yes (encode+send within 50 LOC) | Yes (entropy spike on /tmp write + connect) | HIGH severity; static pairs encoding with network sink; dynamic uses Shannon entropy > 7.2 |
| direct_xpc | Yes (XPC + D-Bus tokens) | Yes (D-Bus only: connect to /run/dbus, /run/user/*/bus) | MEDIUM severity; macOS static gap filled by T14 belt-and-braces; Linux D-Bus observable via strace |
| anti_debug | Yes (ptrace + debugger-detection patterns) | Yes (ptrace syscall events) | HIGH severity; both static source patterns and dynamic syscall observation |
| parser_partial_drift | N/A (static deferred) | Yes (SandboxCoverage.PARSER_PARTIAL_DRIFT in skipped_unexpected) | MEDIUM severity; phase 2 observer detects raw_lines > 0 but events == 0 (strace injection evasion) |

Minimum coverage: 1 header row + 1 separator row + 7 detector rows = **9 pipe-prefixed lines** (CI `grep -c '^|'` ≥ 9 enforced).

## Category Constant Contract

**Invariant:** Every `Detector` subclass in `src/aigate/sandbox/evasion/` MUST define a `CATEGORY` class constant (a snake_case string). This constant is the **single source of truth** for category names across the entire Phase 3 evasion system.

### Contract Rules

1. **`CATEGORY` is a class constant** (not an instance variable, not a computed property):
   ```python
   class EnvMutationDetector(Detector):
       CATEGORY = "env_mutation"  # ← Required
   ```

2. **`detect_static()` emissions use this constant:**
   ```python
   def detect_static(self, source_files):
       signals.append(RiskSignal(category=self.CATEGORY, ...))
   ```

3. **`detect_dynamic()` return values equal this constant exactly:**
   ```python
   def detect_dynamic(self, trace):
       if condition:
           return [self.CATEGORY]  # ← Must be exactly self.CATEGORY
       return []
   ```

4. **No string literals in dynamic returns.** All emitted strings must derive from a registered detector's `CATEGORY` constant. Literal strings like `return ["some_detector"]` that don't correspond to any `CATEGORY` are a bug.

### Enforcement

- **Contract test:** `test_all_detectors_dynamic_emissions_match_registered_categories` (in `tests/test_evasion_category_contract.py`)
  - Iterates all `Detector` subclasses via `inspect.getmembers(aigate.sandbox.evasion)`.
  - For each subclass, runs `detect_dynamic()` against a crafted positive fixture.
  - Asserts every emitted string `s` satisfies `s == cls.CATEGORY`.
  - **Required:** Every detector must pass this test; violations block CI.

- **CI grep-check:** `grep -rE 'return \["[a-z_]+"\]' src/aigate/sandbox/evasion/`
  - Finds all literal string returns in detector code.
  - Every matched literal string must correspond to a registered `CATEGORY` constant.
  - This is a fast pre-check; the contract test is the authoritative enforcement.

### For Future Detector Authors

When adding a new detector:

1. Define `CATEGORY = "your_detector_name"` (snake_case, unique across all detectors).
2. Every `RiskSignal` you emit from `detect_static()` MUST set `category=self.CATEGORY`.
3. Every string you return from `detect_dynamic()` MUST equal `self.CATEGORY` (or return `[]` if no dynamic signal).
4. Add your detector class to the `all_detectors()` list in `src/aigate/sandbox/evasion/registry.py`.
5. Create `tests/fixtures/evasion/<detector_name>/` with ≥3 positive + ≥3 negative + ≥2 mutation fixtures.
6. Your detector will be automatically picked up by `test_all_detectors_dynamic_emissions_match_registered_categories`.

## T14 Evaluation Order

The multi-evasion gate in `src/aigate/policy.py` evaluates the following **five-step sequence** (REV-BS3). Each step is executed in order; early steps may short-circuit and return, preventing later steps from running.

```
Step 1: Build categories_dict via MAX monotone join
  categories_dict = categories_from_signals(risk_signals, dynamic_signals)
  → dict[str, Severity] with keys = unique evasion categories detected
  → values = max severity across static + dynamic for each category

Step 2: Standalone-Darwin-XPC belt-and-braces rule — FIRST, before any count gate
  if platform.system() == "Darwin"
     and set(categories_dict.keys()) == {"direct_xpc"}
     and current_verdict == SAFE:
      verdict = NEEDS_HUMAN_REVIEW
      return verdict
  # Note: This rule runs FIRST to ensure macOS XPC static hits are
  # escalated even when no other evasion categories are present.

Step 3: MALICIOUS gate (REV-NI2 option (a) — deliberate tightening)
  high_cats = {c for c, s in categories_dict.items() if s >= HIGH}
  dynamic_confirmed = any(c in dynamic_signals for c in high_cats)
  if len(high_cats) >= 2 and dynamic_confirmed:
      return MALICIOUS
  # Note: 1 HIGH + N MEDIUM + dynamic confirmation does NOT escalate
  # to MALICIOUS — falls through to Step 4. Requires two orthogonal
  # HIGH tactics for autonomous blocking.

Step 4: NEEDS_REVIEW monotone-lift gate (REV-NI1)
  medium_plus_cats = {c for c, s in categories_dict.items() if s >= MEDIUM}
  if len(medium_plus_cats) >= 2:
      verdict = max(current_verdict, NEEDS_HUMAN_REVIEW)
      # Ordering: MALICIOUS > NEEDS_HUMAN_REVIEW > SAFE
      # NEVER downgrades MALICIOUS (monotone-lift, not floor)
      return verdict

Step 5: Otherwise return the consensus verdict unchanged
  return verdict
```

**Critical note on Step 2 ordering:** The standalone Darwin-XPC rule is evaluated FIRST, before Steps 3 and 4. This is intentional — a macOS package that only touches XPC (with no other evasion tactics) still deserves escalation. Test `test_darwin_standalone_static_direct_xpc_escalates_safe_to_needs_review` proves this step is not dead code by providing a trace with zero other categories.

## T14 Gate Semantics

### Monotone-Lift vs. Floor (REV-NI1)

Step 4 uses explicit `max(current_verdict, NEEDS_HUMAN_REVIEW)` in the total ordering `MALICIOUS > NEEDS_HUMAN_REVIEW > SAFE`.

**Monotone-lift (correct):**
```python
verdict = max(current_verdict, NEEDS_HUMAN_REVIEW)  # ← Use max()
# Ordering: MALICIOUS > NEEDS_HUMAN_REVIEW > SAFE
# If input verdict is MALICIOUS, output is MALICIOUS
# If input verdict is SAFE, output is NEEDS_HUMAN_REVIEW
```

**This is NOT a floor.** A "floor" operation would be `verdict = max(NEEDS_HUMAN_REVIEW, ...)`, which could incorrectly downgrade MALICIOUS → NEEDS_HUMAN_REVIEW. The monotone-lift formulation is **safe to compose** with any other policy layer that may also raise the verdict.

**Test:** `test_medium_floor_does_not_downgrade_malicious_verdict` verifies that input MALICIOUS + 2 MEDIUM categories → output MALICIOUS.

### Deliberate Tightening: 1 HIGH + N MEDIUM (REV-NI2 option a)

**Rule:** 1 HIGH + N MEDIUM with dynamic confirmation → NEEDS_REVIEW, NOT MALICIOUS.

**Rationale:**
- A single HIGH tactic is severe but not unambiguously malicious — it could be a false positive or a weak heuristic.
- A single regex pattern represents one hypothesis class; hypothesis-space errors (e.g., matching legitimate library code) are well-documented in the ML literature.
- Autonomous blocking (MALICIOUS verdict) is **load-bearing**: the minute aigate blocks a legitimate package, users disable the tool in production.
- **Two orthogonal HIGH tactics** eliminates single-regex-hypothesis error — it's unlikely both regexes are wrong for the same package.
- Mixed HIGH+MEDIUM clusters preserve **human-review-in-the-loop** rather than rolling the dice with auto-block.

**Step 3 consequence:** The MALICIOUS gate requires ≥2 HIGH categories with dynamic confirmation. A package with 1 HIGH + 3 MEDIUM + dynamic confirmation on the HIGH falls through to Step 4 and returns NEEDS_HUMAN_REVIEW.

**Test:** `test_one_high_plus_multiple_medium_with_dynamic_confirm_stays_at_needs_review` enforces this behavior.

**Follow-up (F-11):** Post-merge telemetry will instrument the 1-HIGH branch; if ≥80% of human-reviewed packages in this category resolve to "actually malicious," the team will revisit option (b) in a future phase. For now, false-negative avoidance (letting a few malicious packages slip) is preferable to false-positive avalanche (auto-blocking legitimate packages).

### Legacy Scoring Carve-Out (prefilter.py)

The legacy `_calculate_risk_level` in `src/aigate/prefilter.py` pre-dates Phase 3 and auto-escalates any HIGH-severity signal to `RiskLevel.HIGH` (or CRITICAL at `high_count ≥ 2`). That path would bypass T14 by the time `decision_from_prefilter` sets `base_outcome = MALICIOUS` at `policy.py:113-123`.

To honor REV-NI2 end-to-end, Phase 3 carves evasion categories out of the legacy HIGH count. `_is_evasion_signal(s)` returns True for any `RiskSignal` whose `.category` is in `_EVASION_CATEGORIES` (the 7 Phase 3 detectors). Those signals:

- Are **excluded from `high_count`** so they never auto-trigger CRITICAL.
- Are **counted toward the MEDIUM bucket** so they still drive `needs_ai_review = True`.
- Flow through as structured `RiskSignal` (not stringified) so `decision_from_prefilter` sees them via `isinstance(s, RiskSignal)` and forwards to T14.

**Contract:** Evasion verdicts are authoritative only through the T14 gate. Legacy `dangerous_pattern(HIGH)` / blocklist / behavior-chain HIGH signals keep their 1-HIGH-auto-HIGH behavior unchanged. Regression tests: `test_prefilter_preserves_evasion_risksignal_structured_form` + `test_single_high_evasion_does_not_auto_escalate_to_malicious` in `tests/integration/sandbox/evasion/test_prefilter_runs_evasion_static.py`.

### Link to PRD

See `.omc/plans/aigate-sandbox-mode-prd.md` §3.2 "Evasion-aware by default" (Principle 4) and §3.4 "Tiered gating" for the policy-layer context. The PRD's decision drivers (§2.2) justify autonomous blocking only under high-confidence scenarios; Phase 3 implements this conservatively by requiring two orthogonal HIGH signals.

---

**Document version:** Phase 3 iter-3 (REV-BS1/2/3, REV-NI1/2, REV-MINOR)  
**Last updated:** 2026-04-21  
**Related files:**
- Implementation: `src/aigate/sandbox/evasion/*.py`, `src/aigate/policy.py`
- Tests: `tests/test_evasion_*.py`, `tests/test_policy_multi_evasion_gate.py`
- Plan: `.omc/plans/aigate-phase3-evasion-detectors.md`
