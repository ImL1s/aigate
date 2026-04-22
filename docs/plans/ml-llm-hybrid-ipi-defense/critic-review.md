# Critic Review — ML + LLM Hybrid with Integrated IPI Defense (iter-3)

**Mode:** `/ralplan --consensus --deliberate` (Critic gate)
**Reviewer:** oh-my-claudecode:critic (Opus 4.7, 1M ctx)
**Date:** 2026-04-22
**Plan:** `.omc/plans/ml-llm-hybrid-ipi-defense.md` (589 lines / 10,975 words, iter-3 final)
**Architect handoff:** `APPROVE-FOR-CRITIC` (iter-3, see architect-review.md L448)
**Verdict:** **APPROVE** (with follow-ups for executors)

---

## Pre-commitment predictions (made before reading iter-3 in detail)

1. 3-lane parallel calendar with 3 PRs touching `consensus.py` → hidden serialization risk.
2. PR-AUC ≥ 0.95 gate measured on `temporal_test_stable` has potential label-leakage if feature extraction pulls any post-cutoff signal.
3. `min_version_age_days: 7` hard gate likely strong, but `version_age_days` reference timestamp (scan-time vs publish-time) will be load-bearing and probably ambiguous somewhere.
4. `PackageInfo.prior_provenance` is a new field not present in current models.py; the +250 LOC / +0.5 day for PR-4 may be underbudgeted.
5. Class-D-Tail residual is genuinely unresolved but is correctly outside aigate's scope — the right response is acknowledge + retroactive, not block.

**Post-review calibration:** (1) is partially mitigated by the rebase gate but still contains a real lane-serialization risk (finding below). (2) is not visible as label leakage but has an open sub-question about feature temporality. (3) hit — the reference timestamp is underspecified. (4) confirmed; +0.5 day is tight but not wildly off. (5) correctly handled.

---

## 1. Principle–Option consistency

Mapping each of the 5 RALPLAN-DR Principles to the concrete PR / config / test that enforces it:

| Principle | Enforced by | Evidence | Verdict |
|---|---|---|---|
| P1 Local-first + offline-capable | `[ml]` / `[ipi]` optional extras; `skops.io` shipped in wheel; `remote_list_url: null` default; `telemetry.endpoint: null` default; `tests/e2e/test_airgapped_mode.py` asserts zero outbound | Plan L126 (airgap test with explicit `remote_kill_switch_url: null` assertion); L346 (`remote_list_url: null`); L400 (`endpoint: null`) | PASS |
| P2 Everything toggleable, nothing mandatory | `ml.enabled`, `ipi_defense.enabled`, per-layer `.enabled` keys; IPI + ML both optional extras; `dual_llm.enabled: false` default | Plan L320-408 full config schema; L424-427 rollback table; `AIGATE_DISABLE_ML=1` env kill-switches (L428) | PASS |
| P3 Composition, not special-case flags | `ml.mode` enum + `short_circuit.enabled_in_mode` + `short_circuit.hard_gates` + `short_circuit.confidence_threshold_{ci,interactive}` compose | Plan L321-336 | PASS-WITH-RESIDUAL. The `ml.mode` enum (Architect iter-1 §3 Principle 3 LOW flag) still exists. Architect iter-2 §6 downgraded this to LOW-flag because `enabled_in_mode` sub-key acts as independent kill. Accepting the downgrade. |
| P4 Evidence gates promotion | PR-AUC/Brier/ROC-AUC/F1 on `_stable`; ≥50K events + ≥4 weeks shadow; retroactive precision ≥0.9; kill-switch absolute floors | Plan L233-244 (PR-4 acceptance); L275 (`scripts/promote_ml.py` reads `_stable` only); L58-60 (hard gates + kill-switch floors) | PASS |
| P5 Trust nothing the package author wrote | `scan_metadata_fields: true` scans `PackageInfo.description` + `author`; IPI catalog; spotlighting sandwich + nonce + datamarking | Plan L163 (prefilter also scans PackageInfo fields); L107 (`tests/unit/test_ipi_metadata_scan.py`); L20 Principle 5 hardening note | PASS |

**Extension check — does P5 extend to aigate's own dependencies?** Architect iter-2 §6 raised this as a "new principle note" — the skops Beta + CVE-2025-54412 situation is itself a P5 tension on aigate's supply chain. The plan responds with (a) `skops>=0.12.0` pin, (b) `skops_trusted_types: []` empty-whitelist structural defense, (c) CI POC test that fires if the whitelist is ever broadened without review. This is the correct shape. Not a violation.

**No principle is performative.** Each has at least one PR, one config key, AND one test enforcing it. PASS.

---

## 2. Fair alternatives

Alternatives audit:

| Alternative | Rejection rationale | Quality of rejection |
|---|---|---|
| Option A (all-in-one PR) | Review surface + rollback granularity | STRONG. PR-by-PR rollback table (L417-426) concretely demonstrates the value lost. |
| Option C (ML short-circuit day-1) | Violates P4 + D1 | STRONG. Ties rejection to stated Principles. |
| Option D (IPI only, no ML) | Fails D2 (CI latency) | ADEQUATE. Could be stronger — the quantitative claim "3-5s per check" is stated but not citation-backed. |
| Option E (IPI-only 80/20) | Partially adopted | STRONGEST. Plan explicitly absorbs E's conclusions into Dual-LLM default-OFF (L41-46). This is the antithesis taken seriously, which is rare. |
| Bundled joblib (primary) | 5 CVE citations (NullifAI, JFrog×3, NVIDIA NeMo, PickleScan) | STRONG. Evidence-gated rejection. |
| Bundled joblib WITH SHA256 (as primary) | SHA256 necessary-not-sufficient; class vs instance argument | STRONG. "pickle.load on bytes is latent RCE" is the correct framing. |
| Dual-LLM ON by default | Reversec 2025 + CaMeL + cost economics + PR-3 coverage | STRONG. Four-pronged rejection with literature citations. |
| xgboost/lightgbm over sklearn HistGBM | Wheel size, marginal accuracy | WEAK-BUT-ACCEPTABLE. No published benchmark cited for the "marginal accuracy" claim. Not a blocker; this is a secondary choice. |
| Meta Prompt-Guard v1 | Superseded by v2 | STRONG. |
| CaMeL-style capability tracking | Too heavyweight; ADR follow-up | ADEQUATE. A purist would want a LOC/engineering estimate to substantiate "too heavyweight," but the 2025 CaMeL paper does not ship a sklearn-compatible implementation, so this is fair. |

**No strawmen detected.** Option E is the strongest case against the plan and the plan acknowledges it seriously. Option C and D are genuinely weaker positions, and their rejection is crisp. PASS.

---

## 3. Risk mitigation clarity

Auditing every Risk R1-R10 and Pre-mortem Scenarios 1-5:

| Item | Root cause specific? | Early warning observable? | Mitigation in-plan? | Verdict |
|---|---|---|---|---|
| R1 Labeled-list redistributability | YES (OSSF Apache-2.0 + Datadog Apache-2.0) | NO-WARNING-NEEDED | NOTICE attribution file | PASS |
| R2 sklearn 1.7+ forward-compat | YES | CI matrix on 3.11/3.12/3.13 | PASS | PASS |
| R3 Prompt-Guard-2 bypass | YES (Trendyol May 2025, multilingual) | `as_signal_only: true` posture | PASS | PASS |
| R4 Dual-LLM schema drift | YES (Claude 4.8 adds field) | Schema-violation rate alarm >5%/1000 | `route_needs_human_review` + rate-escalation | PASS |
| R5 Shadow-log PII | YES (hashes, no raw strings) | PII-grep test | PASS | PASS |
| R6 Short-circuit bypass | YES (3+2 classes enumerated) | Retroactive OSV+Aikido join | Hard gates + retroactive net | PASS-WITH-RESIDUAL (Class-D-Tail documented) |
| R7 npm data skew | YES (Q3-Q4 2025 bulk ingest) | Reported `_adversarial` metric | Two-set temporal split | PASS |
| R8 Pickled-model RCE | YES (5 CVEs cited) | SHA256 mismatch signal | skops.io primary + SHA256 + CVE test | PASS |
| R9 Dual-LLM cost regression | YES (math at L58-62 of architect review) | `aigate doctor --cost-projection` >1.2× alarm | Default-OFF | PASS |
| R10 AGPL exposure | YES | `agpl_notice_ack: false` opt-in | Documentation + opt-in | PASS |
| Scenario 1 Novel typosquat short-circuit | YES | Retroactive FN auto-trip kill-switch | Hard gates + unconditional floor | PASS |
| Scenario 2 Schema drift | YES | `aigate doctor` RED banner | `route_needs_human_review` + rate-escalation | PASS |
| Scenario 3 CI/CD poisoning | YES | SHA256 mismatch | Pinned SHA256 + two-person review | PASS |
| Scenario 4 Pickled-model RCE | YES | None possible pre-exec | skops primary + SHA256 + CVE test + PEP 740 follow-up | PASS-WITH-RESIDUAL (wheel-itself class) |
| Scenario 5 Day-8 dormant takeover | YES (Sygnia data) | Retroactive OSV+Aikido day-8+ | Hard gates + retroactive net | PASS-WITH-RESIDUAL (Class-D-Tail) |

**Every risk has a specific root cause, an observable early warning (or a justified "no warning possible" — Scenario 4 which is pre-execution RCE), and a mitigation built into the plan (not a TODO).** PASS.

---

## 4. Testable acceptance criteria

Per-PR audit:

| PR | Measurable? | Failable? | Test path specified? | Verdict |
|---|---|---|---|---|
| PR-1 | Yes: `100% of IPIPattern`, `FP ≤ 2/200`, `p95 < 50ms`, `100/100 zero-width`, `0 ruff`, `705 unit tests` | Each has a concrete test file | `tests/unit/test_ipi_catalog.py`, `test_prefilter_ipi.py`, `test_ipi_metadata_scan.py` | PASS |
| PR-2 | Yes: nonce 10K uniqueness, datamark <2× length | Concrete assertions | `tests/unit/test_ipi_spotlighting.py` (implied from plan iter-1) | PASS |
| PR-3 | Yes: NEEDS_HUMAN_REVIEW on stacked-malware fixtures, SAFE preserved on new-legit, 2× LLM calls, FP ≤ 3% | Each is testable | `tests/unit/test_consensus_ml_vote.py` + fixtures | PASS |
| PR-4 | Yes: PR-AUC≥0.95 on `_stable`, Brier≤0.05, p95<50ms, p99<150ms, ≤1MB skops file, byte-flip rejection, empty-whitelist rejection, 100% gate-failure blocks short-circuit, CI=0.90/interactive=0.97, bit-for-bit shadow invariant on 100 seeded | Each has a concrete unit/integration test | `tests/unit/test_metadata_ml_backend.py`, `test_model_artifact_security.py`, `test_short_circuit_hard_gates.py`, `test_short_circuit_context_threshold.py`, `test_version_cooldown_gate.py`, `test_model_size_budget.py`, `test_temporal_split_stable_vs_adversarial.py`, `tests/security/test_skops_cve_2025_54412.py` | PASS |
| PR-5 | Yes: schema success ≥98%/100 pkg, cost doubles documented, `NEEDS_HUMAN_REVIEW` routing, rate-escalation at >5%/1000, `>1.2×` cost banner, default OFF | Each is testable | `tests/integration/test_dual_llm.py` | PASS |
| PR-6 | Yes: 1.5× + floor 5, 2.0× + floor 10, unconditional floor ≥1000 dl/wk, 10/10 retroactive join, 0 net calls on fresh install | Each is testable | `tests/unit/test_kill_switch.py`, `test_retroactive.py`, `test_telemetry_privacy.py`, `test_kill_switch_absolute_floor.py`, `test_aikido_feed_parser.py` | PASS |
| PR-7 | Iter-1 acceptance inherited; `--cost-projection` +1 subcommand | Testable | Promotion-gate CI | PASS-THIN. The plan says "as iter-1" without re-listing; Critic confirms by reference that iter-1 acceptance already included numeric gates. |

**No aspirational adjectives ("good coverage", "acceptable latency") survive in the iter-3 acceptance table.** Every numeric threshold is pinned. Every test file path is specified. PASS.

---

## 5. Concrete verification steps

For each PR, "what command would I run to verify done?":

- PR-1: `.venv/bin/python -m pytest tests/unit/test_ipi_catalog.py tests/unit/test_prefilter_ipi.py tests/unit/test_ipi_metadata_scan.py -v && ruff check src/aigate/ipi.py`. VERIFIABLE.
- PR-2: `.venv/bin/python -m pytest tests/unit/test_ipi_spotlighting.py -v`. VERIFIABLE.
- PR-3: `.venv/bin/python -m pytest tests/unit/test_consensus_ml_vote.py tests/integration/test_ipi_stack_end_to_end.py -v`. VERIFIABLE.
- PR-4: `.venv/bin/python -m pytest tests/unit/test_metadata_ml_*.py tests/unit/test_short_circuit_*.py tests/unit/test_version_cooldown_gate.py tests/unit/test_model_size_budget.py tests/security/test_skops_cve_2025_54412.py tests/integration/test_ml_llm_cooperative_vote.py -v && python tools/verify_model.py`. VERIFIABLE.
- PR-5: `.venv/bin/python -m pytest tests/integration/test_dual_llm.py -v && aigate doctor --cost-projection`. VERIFIABLE.
- PR-6: `.venv/bin/python -m pytest tests/unit/test_kill_switch*.py tests/unit/test_retroactive.py tests/unit/test_aikido_feed_parser.py -v && aigate doctor --ipi-stats`. VERIFIABLE.
- PR-7: `scripts/promote_ml.py --dry-run && aigate doctor --cost-projection && aigate doctor --ipi-stats`. VERIFIABLE.

PASS.

---

## 6. Deliberate mode extras — rigorous scrutiny

### Pre-mortem quality (5 scenarios)

- **Scenario 1 (novel typosquat short-circuit):** REAL. Exactly the class that 2025 real-world typosquats look like. Mitigations include the iter-3 new gates. PASS.
- **Scenario 2 (schema drift):** REAL. Claude 4.x has historically added fields between minor versions (plan even cites hypothetical 4.8). Auto-escalation is measured. PASS.
- **Scenario 3 (CI/CD poisoning):** REAL. Same class as PyTorch nightly torchtriton (2022). SHA256-pin + two-person-review is the correct posture. PASS.
- **Scenario 4 (pickled-model RCE):** REAL. Five 2025 CVEs cited. The honest-residual framing (inside-wheel SHA256 doesn't protect whole-wheel) is correct and iter-3's clarification (L83-87) of the iter-2 self-contradiction is well-done. PASS.
- **Scenario 5 (day-8 dormant takeover):** REAL with a caveat. Sygnia data (Sep 2025: 16-min compromise-to-publish, 2h live) shows this is NOT the dominant pattern — which the plan honestly states (L96 "Delay-8-days is a tail-risk"). The scenario exists to stress-test `min_version_age_days: 7` against a non-dominant but non-zero attack class. Intellectually honest. PASS.

**All 5 scenarios are real plausible failures with specific root cause + observable early-warning (or justified absence) + built-in mitigation.** None are manufactured.

### Expanded test plan coverage

| Lane | Present? | Specific targets? |
|---|---|---|
| Unit | YES (12 named files) | Each feature, each hard-gate, each config path |
| Integration | YES (5 named files) | 4 toggle combos; full IPI stack; Dual-LLM real backend; shadow invariant; Aikido join |
| E2E | YES (4 named files) | Real PyPI; malicious fixture; airgapped; short-circuit threshold honored |
| Observability | YES (5 named files) | Shadow schema v1; drift detector; OSV+Aikido join; IPI rate alarm; temporal split stable vs adversarial |
| Security | YES (1 named file: `test_skops_cve_2025_54412.py`) | POC exploit against empty whitelist |

**No lane is TBD or missing.** The security lane (new in iter-3) is a valuable addition because the skops CVE test is a cross-cutting concern that doesn't fit cleanly into unit/integration. PASS.

---

## 7. Architect's two scrutiny focuses

### (i) Stage-1 evidence gates — quantitatively strong enough given Class-D-Tail?

**Current gates** (plan L233-244, L463): PR-AUC ≥ 0.95 on `_stable`, Brier ≤ 0.05, ROC-AUC ≥ 0.97, per-family F1 ≥ 0.85, agreement ≥ 95%, retroactive precision ≥ 0.9, ≥50K events, ≥4 weeks shadow.

**Class-D-Tail** = dormant >7 days AND (no prior attestation OR attacker controls publisher identity).

**Critic analysis:**

The gates are statistically strong for the MODEL quality but have a specific blind-spot for Class-D-Tail: **shadow-mode data cannot distinguish "ML said SAFE correctly" from "ML said SAFE and attacker was biding time"** — because by definition in shadow mode, no user was harmed and no retroactive advisory has been published yet at the time of promotion decision. The Architect iter-3 §2b makes this exact point (review L475): adding a naive "zero confirmed Class-D-Tail FN in shadow data" gate is non-meaningful because Class-D-Tail FNs are unobservable during shadow.

**The Architect's proposed tightening** (review L475-476, L520): Stage-1 promotion should require the retroactive OSV+Aikido pipeline to have caught AND auto-revoked at least one real malicious package during shadow weeks — **proof-of-wiring for the day-8+ net, not a false-negative metric.** Critic concurs: this is operational correctness (the retroactive pipe is the only catch-net for Class-D-Tail; verify it actually fires before enabling short-circuit). It is NOT captured in the current Stage-1 criteria.

**Open question #3 in the tracker** (`ml-llm-hybrid-ipi-defense iteration 3` section, line 130 of open-questions.md) — "Stage-1 promotion criteria addition for Class-D-Tail" — is the right place to resolve this. Planner iter-3 leans toward "match the 8-week window." Critic recommends: adopt Architect's simpler formulation — **"retroactive pipeline has caught ≥1 real malicious package during shadow weeks (proof the day-8+ net is wired, not just unit-tested)"** as a Stage-1 checklist item. This is one line in `scripts/promote_ml.py`.

**Verdict on (i):** Gates are quantitatively strong for ML model quality. Add the operational wiring proof as a Stage-1 checklist item. NOT BLOCKING for merge (it's a Stage-1 gate, triggered only at promotion, not at PR-7 merge); recommend adding as a Critic follow-up.

### (ii) 7-PR / 3-lane / ~8.5-9.5 day calendar realism with PR-4 +250 LOC / +0.5 day expansion

**Lane breakdown (plan L311-314):**

- Lane A: PR-1 → PR-2 → PR-3 = 2 + 1 + 1.5 = 4.5 days
- Lane B: PR-4 (after PR-1) = 5.5 days (iter-3 expanded from 5)
- Lane C: PR-5 (after PR-3) = 3 days (can shadow-dev in parallel earlier)
- Lane D: PR-6 → PR-7 (after PR-4/PR-5) = 2.5 + 1.5 = 4 days

**Critical path analysis:**

- Start: day 0.
- PR-1 done: day 2 (Lane A) — unlocks Lane B start (PR-4) at day 2.
- PR-2 done: day 3 (Lane A).
- PR-3 done: day 4.5 (Lane A) — unlocks Lane C start (PR-5) at day 4.5 (if not shadow-dev'd earlier).
- PR-4 done: day 2 + 5.5 = day 7.5 (Lane B).
- PR-5 done: day 4.5 + 3 = day 7.5 (Lane C) — identical critical path to PR-4.
- PR-6 done: day 7.5 + 2.5 = day 10 (Lane D).
- PR-7 done: day 10 + 1.5 = day 11.5.

**Plan claims "8.5-9.5 days with 3 lanes."** Critic's math yields 10-11.5 days serial on the critical path with the given lane structure. The plan's figure likely reflects (a) shadow-dev parallelism on PR-5 that starts earlier than PR-3 landing, and/or (b) PR-7 as a diagnostic-UX PR that doesn't strictly block release. If PR-5 shadow-dev starts at day 2 (after PR-1) with 3 days of parallel work before it can merge, and PR-6 starts at day 7.5 in Lane D running 2.5 days → day 10, with PR-7 landing in parallel with final stabilization → day ~9.5-10.5.

**Finding:** The 8.5-9.5 day figure is *tight* given PR-4's 5.5-day size and PR-6's PR-4 dependency. A realistic range is 9.5-11 calendar days, which is still within the same order-of-magnitude and not materially different. MAJOR-LEVEL discrepancy on the stated calendar but MINOR-severity operationally — the 4-week shadow clock is the real critical path (plan acknowledges this at L296).

**Hidden serialization on `consensus.py`:** PR-3 (`_detect_reader_disagreement`), PR-4 (`BACKEND_MAP` + hard-gate resolver + context-threshold resolver), PR-5 (Dual-LLM stage). Current file is only 246 lines (`/Users/setsuna/Documents/aigate/src/aigate/consensus.py`). Three PRs adding ~50-300 LOC each to a 246-line file WILL conflict unless the rebase gate (plan L298) is enforced strictly. The gate is correctly specified but:
- It does NOT require re-running the full integration suite on the SECOND PR after the FIRST merges — it requires "full integration test suite (`tests/integration/test_ml_llm_cooperative_vote.py` + `test_ipi_stack_end_to_end.py` + `test_dual_llm.py`)." This is 3 files, not the full integration suite. Minor, but the wording "full integration test suite" is slightly misleading.
- Lane C (PR-5) rebasing after "whichever of Lane A/B merges later" is correct; Lane B (PR-4) rebasing only after Lane A assumes PR-3 always merges before PR-4. If PR-4 finishes first (5.5 days serial vs 4.5 days for PR-3 — close race), the gate rule may need to reverse. The plan text says "Lane B rebases-and-retests after Lane A (PR-3) merges; Lane C rebases-and-retests after whichever of Lane A/B merges later." This is ONE-WAY — PR-3 is privileged to merge first. If PR-4 finishes first in practice, is PR-3 required to rebase on PR-4? The text is asymmetric.

**Verdict on (ii):** Calendar is defensible at ~10-11 days; plan's 8.5-9.5 is optimistic by ~1-2 days but within noise. Rebase-gate asymmetry is a MINOR coordination ambiguity that executors should resolve when lanes merge (first-to-finish wins, second rebases — regardless of which lane). NOT BLOCKING.

---

## 8. Consistency pass (full plan read end-to-end)

Systematic check for contradictions:

| Check | Result |
|---|---|
| `PackageInfo.prior_provenance` field added (L225, L335) vs current `models.py:60` PackageInfo | NEW FIELD — plan correctly budgets the +0.5 day for registry-client resolution (L247). Verified PackageInfo currently has no `prior_provenance`, `version_published_at`, or `maintainers_history`. Three new fields required in PR-4. Budgeted. |
| `MODEL_SHA256` at `src/aigate/ml/__init__.py` inside wheel (L217, L84) | Self-contradiction flagged by iter-2 now RESOLVED in iter-3 (L83-87 scoping + PEP 740 for whole-wheel). Consistent. |
| skops version pin `>=0.12.0,<0.20` (L216) vs upper bound `<0.20` | skops v0.14 current at 2026-04-22 per architect iter-2 §4 table; `<0.20` allows 6 minor version bumps. Reasonable. |
| `min_version_age_days: 7` scope "short-circuit only" (L334) vs ML-still-votes | L58 mitigation (b) EXPLICITLY states "ML still votes in LLM consensus" when gate fails. L223 consensus.py hard-gate resolver comment: "any failure → short-circuit blocked, ML still votes". L111 test assertion. Consistent. |
| `require_provenance_continuity: true` is no-op when no prior attestation (L335 config comment) vs gate "must pass" | L58 says "ALL must pass"; L335 clarifies no-op-on-absence. These reconcile: the gate returns TRUE trivially when there's nothing to check. Plan's `docs/short-circuit-hard-gates.md` fallback doc (L522) supports this. Consistent. |
| `agpl_notice_ack: false` default (L413) vs iter-2 table L561 "`agpl_notice_ack: true`" | Iter-2 table L561 describes iter-2 state; iter-3 table L579 describes the flip to `false`. No inconsistency; iter-3 correctly supersedes. |
| Totals: ~5,820 LOC, ~17.5 eng-days serial (L296) | Breakdown: PR-1 550 + PR-2 200 + PR-3 320 + PR-4 2,850 + PR-5 450 + PR-6 900 + PR-7 550 = 5,820 LOC. ADDS UP. |
| Eng-days: 2+1+1.5+5.5+3+2.5+1.5 = 17 days (plan says 17.5) | Off-by-0.5. MINOR arithmetic slip in plan L296. Not consequential. |
| `temporal_test_stable` ≤ 2025-07-01 cutoff (L26) vs PR-4 acceptance "pre-2025-07" (L233) vs open-question #7 "≤2025-07-01" | Consistent. |
| `ipi_signals` in ConsensusResult (L559 iter-2 table claim, L94 in test spec) vs current `models.py:127` ConsensusResult (has `risk_signals: list[str]`, NOT `ipi_signals`) | **NEW FIELD** on `ConsensusResult`. Plan doesn't explicitly list `ConsensusResult.ipi_signals` as an added field in any PR's files section, but PR-3 (L188-201) edits `consensus.py` to append to `ipi_signals`. Implicit: PR-3 adds the field. Plan should explicitly list this. MINOR ambiguity; call out as executor follow-up. |
| kill-switch unconditional floor threshold `1000 downloads/week` (L274, L329, L352) | Consistent across mentions. |

**Two minor findings from consistency pass:**

1. MINOR — arithmetic: plan totals L296 state 17.5 eng-days; sum of per-PR sizes is 17. Off-by-0.5 day. Not consequential.
2. MINOR — implicit field: `ConsensusResult.ipi_signals` appears in tests/mitigations but is not explicitly listed as a new field in any PR's "files" section. Current `ConsensusResult` uses `risk_signals: list[str]`. Executor should confirm PR-3 adds the field explicitly.

No fields referenced but missing from schema. No metrics with different numbers. No PR-dependency contradictions. No orphan pre-mortem mitigations. PASS-WITH-MINOR-FOLLOWUPS.

---

## 9. Critic verdict — **APPROVE (with executor follow-ups)**

The iter-3 plan passes all ralplan deliberate-mode gates:

- Principle–option consistency: all 5 principles enforced by at least one PR + one config + one test.
- Alternatives fairly considered: Option E (IPI-only) taken seriously; joblib-primary rejected with 5 CVE citations; CaMeL correctly scoped as follow-up.
- Risk mitigation: all 10 Risks + all 5 Pre-mortem Scenarios have specific root cause + observable early warning + in-plan mitigation.
- Acceptance criteria: every PR has numeric thresholds, concrete failable tests, specified test file paths.
- Verification steps: every PR has a runnable command.
- Pre-mortem: 5 real plausible scenarios, none manufactured.
- Expanded test plan: unit/integration/e2e/observability/security lanes all present with specific targets.

Both iter-2 blockers are structurally resolved:
- **Blocker 1 (skops CVE):** pin `>=0.12.0`, empty-whitelist structural defense, CI POC test on every PR, `MODEL_SHA256`-scope clarified.
- **Blocker 2 (maintainer takeover):** `min_version_age_days: 7` + `require_provenance_continuity` match 2025-2026 ecosystem norm; Class-D shrinks to documented Class-D-Tail with retroactive net as catch.

The plan's residuals are **honestly acknowledged, not hidden:**
- Class-D-Tail (dormant >7 days + provenance-fully-compromised) → mitigated via retroactive, full resolution requires ecosystem sigstore adoption.
- Whole-wheel mirror compromise → mitigated via PEP 740 attestations + `--require-hashes` recommendation.
- AGPL interpretation → defensible but not formal-counsel-signed.

**The remaining issues are MINOR and do not justify iter-4.** At 3/5 iterations used, iter-4 would cost more than the minor gaps deserve. All can be resolved during PR execution.

---

## Critic follow-ups for executors (resolve during PR execution, not in another iteration)

**PRIORITY-1 (must address in the affected PR):**

1. **[PR-7] Add Stage-1 operational-wiring gate:** Promotion checklist must include "retroactive OSV+Aikido pipeline has caught AND auto-revoked ≥1 real malicious package during shadow weeks" — not just unit-tested. One line in `scripts/promote_ml.py` + corresponding checklist item. (Per Architect iter-3 §2b + §7 item #1.)

2. **[PR-3] Explicitly add `ConsensusResult.ipi_signals: list[str]` field:** Currently `ConsensusResult` at `src/aigate/models.py:127` uses `risk_signals: list[str]`. PR-3's `_detect_reader_disagreement` implementation appends to `ipi_signals` but no PR's files section explicitly adds this field. Add it to PR-3's `src/aigate/models.py` edits, not implicitly.

3. **[PR-4] Clarify `version_age_days` reference timestamp:** Plan says "the SPECIFIC version being scanned must be ≥7 days old" (L334). Unambiguously resolve: is this `now() - version.upload_time`, or `pkg.resolved_at - version.upload_time`, or `scan_start_time - version.upload_time`? For CI-scanning-yesterday's-published-version, the three diverge by seconds-to-hours. Pick one (recommend `scan_start_time - version.upload_time`) and encode in test.

4. **[PR-4 rebase gate] Make rebase-gate rule symmetric:** Plan L298 states "Lane B rebases-and-retests after Lane A (PR-3) merges." This is asymmetric (Lane A privileged). Make symmetric: "whichever lane merges first, subsequent-to-merge lanes rebase on main and re-run integration suite." The integration suite list (3 files) is correct; the wording "full integration test suite" should be clarified as "these three files."

**PRIORITY-2 (nice-to-have, not blocking):**

5. **[PR-4] Document `aigate doctor` stat for prior_provenance adoption:** Per Architect iter-3 §6 Consensus Addendum item: add `aigate doctor` line reporting "% of checks with prior_provenance data available" so operators can calibrate expectations as PEP 740 adoption grows. Not a v0.6 blocker; can land in v0.7.

6. **[Plan]** Off-by-0.5 arithmetic slip at L296 (17 vs 17.5 eng-days). Inconsequential.

7. **[PR-3]** Disagreement-rule calibration: Architect iter-2 §4 table noted the (conf ≥ 0.7, gap < 0.3) values are best-guess, not literature-calibrated. PR-3's acceptance criteria should include a cross-validation sweep over (0.6..0.8)×(0.2..0.4) to confirm the (0.7, 0.3) point is near-optimal on the 200-pkg top-PyPI+npm fixture set. Non-blocking but worth 1 hour.

8. **[PR-4]** `maintainers_history` resolution for Feature #49 (`maintainer_set_changed_within_30d`): plan says "source: registry API history" (architect iter-1 §4a) but `PackageInfo` (`models.py:60`) currently has no `maintainers_history` field. Same class as `prior_provenance` — new field, new resolver work. The +250 LOC / +0.5 day budget includes `prior_provenance` explicitly; verify `maintainers_history` is also in scope (it should be — Feature #49 was added in iter-2, not iter-3).

---

## Verdict Justification

Review operated in **THOROUGH mode** throughout. No CRITICAL findings surfaced and fewer than 3 MAJOR findings emerged. No pattern suggesting systemic issues — iter-1 and iter-2 feedback was absorbed non-cosmetically, and iter-3 resolved both blockers with real code/config/tests, not rhetoric. Architect's handoff focus areas (Stage-1 gate strength and calendar realism) both resolved: gates are sound with one operational-wiring follow-up; calendar is optimistic by ~1-2 days but the 4-week shadow clock dominates the critical path anyway.

**Realist Check applied** to the one borderline-MAJOR finding (calendar optimism): realistic worst case is ship-slips-by-1-2-days, easily absorbed given the 4-week shadow clock dominates. Mitigating factor: work is parallelizable and the lane structure is sound. Downgraded from MAJOR to MINOR under Realist Check. Mitigated by: 4-week shadow-mode clock is the critical path, not PR-merge calendar.

Escalation to ADVERSARIAL mode was not warranted.

The plan is architecturally solid, evidence-driven, honestly-scoped, and ready for execution. The iter-3 additions (skops pin + CVE test, version-cooldown gate, provenance-continuity gate, rebase gate, agpl opt-in flip, model-size assertion, threat-model quantification) all match real 2025-2026 ecosystem norms with proper citations. Literature-calibrated design choices dominate over hand-waving.

---

## Open Questions (unscored — low-confidence or speculative follow-ups)

- **Joblib fallback existence** (open-questions.md `ml-llm-hybrid-ipi-defense iteration 2`, item 114): whether to ship `allow_joblib_fallback` at all. Critic leans "keep, heavily gated" matching plan's posture — removing the fallback makes skops-serialization failures into hard ship-blockers during the training pipeline. Not Critic's decision.
- **skops protocol pinning** (open-questions.md item 113): single vs range. Critic leans single per model version (matches plan), but this is an implementation detail resolvable at training time.
- **Stage-1 Class-D-Tail window** (open-questions.md item 130): 4 weeks vs 8 weeks. Critic leans "match the 8-week full shadow window" per planner's lean, but Architect's simpler "≥1 retroactive catch during shadow weeks" formulation is equivalent in effect and simpler to codify.
- **`PackageInfo.prior_provenance` schema stability** (open-questions.md item 129): unified dict vs split per-ecosystem. Critic leans unified (matches plan) for forward-ecosystem extensibility.

None of the above block approval.

---

*Ralplan summary row:*
- **Principle/Option Consistency: PASS** — all 5 principles enforced by concrete PR+config+test; downgraded `ml.mode` enum flag from MEDIUM to LOW is accepted.
- **Alternatives Depth: PASS** — Option E antithesis taken seriously and partially adopted; 5 CVE citations back the joblib-primary rejection.
- **Risk/Verification Rigor: PASS** — all R1-R10 + Scenarios 1-5 have root cause + warning + mitigation + test.
- **Deliberate Additions: PASS** — 5 real pre-mortem scenarios, all 5 test lanes present (unit/integration/e2e/observability/security), no TBD lanes.

---

## Final handoff

**ADR-ready one-paragraph summary:**

> Ship aigate v0.6 with a 7-PR ML+LLM cooperative hybrid + layered IPI defense, executed across 3 parallel lanes over ~10-11 calendar days of merge work followed by a 4-week shadow-mode evidence clock before Stage-1 promotion. The plan structurally closes the 2025 pickle-RCE class by shipping the ML artifact as `skops.io` (empty `trusted_types: []` whitelist + pinned `skops>=0.12.0` for CVE-2025-54412 + CI POC test + pre-deserialization SHA256 + `MODEL_SHA256` constant scoped to post-install tampering defense, with PEP 740 sigstore attestation as the wheel-level integrity follow-up). Short-circuit safety is gated by six hard checks (package age ≥14d, releases ≥5, maintainer stability 30d, repo/homepage resolves, version age ≥7d matching pnpm/Yarn/Bun/npm 2025-2026 ecosystem norm, and provenance-continuity matching pnpm 10.21 trustPolicy) plus context-aware confidence thresholds (CI 0.90, interactive 0.97) and absolute-floor kill switches (1.5×+5/24h short-circuit, 2.0×+10/24h general, unconditional floor on >1000dl/week). Dual-LLM defaults OFF because PR-3's metadata-only reader carries ~80% of the intended protection at 50% of the LLM cost per 2025 Reversec/CaMeL literature; schema-violation auto-routes to `NEEDS_HUMAN_REVIEW` with >5%/1000 rate-escalation to full-corpus routing. Retroactive verification consumes OSV + Aikido Intel feeds (AGPL consume-only, opt-in `agpl_notice_ack: false`) to catch the Class-D-Tail (dormant >7-day) residual. Evidence gates promote ML only on `temporal_test_stable` (pre-2025-07 cut) metrics with `_adversarial` reported diagnostically. Ship IPI layers 1-3 ON by default; ML in `mode: shadow` (zero verdict impact); Dual-LLM + classifier OFF by default; `ml.mode: short_circuit_*` requires operator opt-in. Four Critic follow-ups for executors (Stage-1 operational-wiring gate, explicit `ConsensusResult.ipi_signals` field add in PR-3, `version_age_days` reference-timestamp disambiguation, symmetric rebase-gate wording) are non-blocking and addressable during PR execution.

**Verdict: APPROVE.** End workflow. Next artifact: ADR-0001 document + executor briefing.
