# aigate ML + LLM Hybrid Backend with Integrated IPI Defense — RALPLAN-DR Plan (Iteration 3)

**Mode:** `/plan --consensus --deliberate`
**Planner:** oh-my-claudecode:planner (Opus 4.7, 1M ctx)
**Iteration:** 3 (responding to Architect iter-2 `REVISE-BEFORE-CRITIC`: 2 blockers + 4 non-blocking)
**Next:** Architect iter-3 re-review → Critic evaluation
**Repo:** `/Users/setsuna/Documents/aigate`
**Date:** 2026-04-22

---

## RALPLAN-DR Summary (compact)

### Principles (5)

1. **Local-first + offline-capable.** ML model ships in the wheel; LLM is optional. `aigate check` on an airgapped laptop must still produce a verdict. A supply-chain security tool cannot have a runtime supply-chain dependency on a network CDN or third-party API. **Hardening added in iter-2:** the model artifact format itself must not be a supply-chain vector — we reject pickle-family formats (`joblib`, `pickle`) as the primary path and ship `skops.io` (pickle-free, whitelist-based deserialization). **Iter-3 correction:** `skops` itself had CVE-2025-54412 (GHSA-m7f4-hrc6-fwg3, fixed in v0.12.0); the plan now pins `skops>=0.12.0,<0.20` and ships a CI test exercising the POC vector against our empty whitelist.
2. **Everything toggleable, nothing mandatory.** ML and LLM are independently enableable. IPI defense layers 1-5 compose. Users in regulated environments can run ML-only; hobbyists can stay LLM-only; default is cooperative weighted vote. **Hardening added in iter-2:** `pydantic` downgraded to an optional extra, not a required dep, so the default aigate wheel stays lean for Python 3.11-3.13.
3. **Flexibility by composition, not by special-case flags.** Short-circuit, vote-only, shadow-only, and disabled are expressions of orthogonal knobs: `ml.mode` and `ml.short_circuit.*`. No hidden interaction. Context-aware thresholds (CI vs. interactive) are runtime composition, not new modes.
4. **Evidence gates promotion.** ML moves from shadow → vote-participant → short-circuit-SAFE only when measurable thresholds hold. Per-user kill switch is first-class. **Hardening added in iter-2:** kill-switch multipliers tightened to 1.5× / 2.0× with absolute floors (5 FN/24h short-circuit, 10 FN/24h general, plus an **unconditional floor** of "any confirmed FN on a >1000 downloads/week package").
5. **Trust nothing the package author wrote.** README, docstring, comments, code strings — all treated as UNTRUSTED. **Hardening added in iter-2:** registry-served `PackageInfo.description` and `PackageInfo.author` are also author-controlled and must be scanned for IPI patterns before they reach any LLM prompt.

### Decision Drivers (top 3)

1. **Indirect prompt injection is active exploitation, not theory.** The Cline/Clinejection incident (disclosed 2026-02-09) weaponized a GitHub-Actions `claude-code-action` IPI into unauthorized npm publish of `cline@2.3.0` with a `postinstall: npm install -g openclaw@latest` line, infecting ~4,000 developer machines within hours. aigate is architecturally analogous — we ship IPI hardening or we ship a known-exploitable tool.
2. **LLM cost + latency is the bottleneck for CI/dev-install UX.** Claude ~4s, Gemini ~3s, ~$0.01-0.02/call. A fast, calibrated, 20-50ms local ML can short-circuit the clear-SAFE majority (est. 60-80% of traffic). Savings fund the IPI hardening in the residual 20-40%.
3. **Correctness under drift > peak precision.** OSSF npm corpus is warped by 2025 bulk-ingest spikes. A model that looks 0.99 PR-AUC on random split will look 0.85 on temporal split. Temporal split + drift telemetry + shadow-first promotion is non-negotiable. **Refined in iter-2:** two temporal test sets (`_stable` pre-2025-07 for promotion gating; `_adversarial` post-2025-07 for diagnostics), both reported but only `_stable` gates promotion.

### Viable Options (with bounded pros/cons)

**Option A — All-in-one PR.** INVALIDATED — previously rejected, retained only as reference rollback.

**Option B (RECOMMENDED) — 7 sequenced PRs, IPI hardening first, ML shadow next, promotion last. PR-5 parallelizes with Lane A per Architect §4(c).**
- Pros: IPI fixes ship in ~3 days. ML starts in shadow mode (zero verdict impact). Promotion gates enforced in CI. Every PR independently reversible. Pickle-family risk eliminated at PR-5 itself (skops.io primary, pre-deserialization SHA256 fallback). Dual-LLM defaults OFF.
- Cons: 6-8 weeks end-to-end before ML can short-circuit. Requires discipline not to "just promote it."
- Risk: LOW.

**Option C — Ship ML in short-circuit-SAFE mode from day 1.** INVALIDATED (violates Principle 4 + Driver 1; documented in ADR alternatives).

**Option D — IPI only, no ML.** INVALIDATED (fails Driver 2 + task goal).

**Option E (NEW in iter-2) — Ship IPI PR-1 + PR-2 + PR-3 only; defer ML and Dual-LLM indefinitely.** The Architect's steelman antithesis. Delivers ~80% of IPI value at ~20% of complexity; PR-3's metadata-only reader carries most of Dual-LLM's protection at half the cost.
- Pros: ships in ~4.5 eng-days; no pickled-model supply-chain attack surface; no 4-week promotion wait.
- Cons: permanent 3-5s per `aigate check` (Driver 2 unmet); users remain on `--skip-ai` as de-facto workaround; no short-circuit economics.
- **Partial acceptance in iter-2:** we don't ship Option E as the plan — but we **adopt its conclusions** for Dual-LLM (PR-5 ships default-OFF with explicit cost-regression warning in `aigate doctor`), and we explicitly document in the ADR that PR-3 carries ~80% of Dual-LLM's protection at 50% cost, so Dual-LLM is a latent capability not a required layer.

**Surviving options: B (chosen).** A retained as documentary rollback; E's conclusions partially absorbed into B.

---

## Deliberate Mode Extras (required — auto-enabled)

### Pre-mortem — "It's 2026-10-22. aigate ML+IPI shipped 6 months ago. What went wrong?"

**Scenario 1 — "The ML model short-circuited a novel typosquat campaign and we auto-approved 800 malicious installs."**
- Root cause: 2026-Q3 typosquat with new obfuscation; model scores `SAFE` at 0.97 because every feature looks top-decile benign. Short-circuit fires. LLM skipped. Exfil at import time.
- Mitigation in-plan (iter-2 strengthened):
  - (a) Short-circuit-SAFE gate requires `prefilter.risk_level == NONE` AND `ML.confidence ≥ short_circuit_confidence_threshold_<context>` (0.90 CI / 0.97 interactive).
  - (b) **NEW hard gates (bypass-blockers, not signals):** `min_pkg_age_days: 14`, `min_num_releases: 5`, `maintainer_set_changed_within_30d == false`, at least one of `repository` / `homepage` resolves to a real git host. **Iter-3 adds `min_version_age_days: 7` (catches Class-D version-level takeover on established packages — chalk/debug/Axios 2025-2026) and `require_provenance_continuity: true` (catches provenance-drop attacks).** Any failure → short-circuit blocked regardless of ML confidence; **ML still votes** in LLM consensus.
  - (c) Retroactive OSV+Aikido pipeline (PR-7) runs daily; any FN in a short-circuited bucket auto-trips kill switch for that model version.
  - (d) Kill-switch threshold **1.5× + absolute floor of 5 FN/24h** for short-circuited traffic, **plus unconditional floor**: any confirmed FN on a >1000 downloads/week package flips short-circuit to shadow regardless of rate.
  - **Honest residual risk (per Architect §4a Class A + iter-3 Class D shrinkage):** iter-2 residual "maintainer takeover on a popular package >14 days old that keeps the same maintainer list for 30+ days" is **narrowed in iter-3** by `min_version_age_days: 7` + `require_provenance_continuity`. Class-D (version-level takeover) is now covered for short-circuit in the dominant attack pattern (per Sygnia Sep 2025: most takeovers exploited within hours-to-days, not weeks). The new residual is narrower: "compromised version that sits for >7 days before being exploited, AND either had no prior provenance to begin with OR attacker also controls provenance identity." Per iter-3 web research (PEP 740 adoption ~5% Nov 2024 → estimated 15-25% top-360 by 2026-Q1, high on popular packages), provenance-continuity gate fires on most high-download packages. Residual attack class is documented as Class-D-Tail in `docs/ml-short-circuit-threat-model.md`, with retroactive OSV+Aikido pipeline as the day-8+ catch-net. See Scenario-5 (iter-3) for the full attack walkthrough.

**Scenario 2 — "Dual-LLM schema drift silently downgraded everyone to single-LLM analysis."**
- Root cause: Claude 4.8 adds a trailing `explanation` field; `model_validate_json` raises `ValidationError`; fallback bypasses the defense for 3 weeks unnoticed.
- Mitigation in-plan (iter-2 strengthened):
  - (a) **NEW — auto-escalate:** schema violation emits `quarantined_llm_schema_violation(HIGH)` AND routes that specific package to `NEEDS_HUMAN_REVIEW` (not `metadata_only_only`). Iter-1 used `metadata_only_only`; Architect §4(b) flagged this as silent-degrade risk.
  - (b) pydantic `extra="ignore"` for forward-compat; type-validated, not presence-validated.
  - (c) telemetry (opt-in) counts violations; `aigate doctor` prints RED banner at >5% of last 1000 calls.
  - (d) CI integration test asserts ≥99% schema success on 100-package fixture corpus; weekly `aigate doctor --ipi-stats` in CI fails build at >2%.
  - (e) Per Architect §4(b) second-stage: if sustained `>5% over last 1000 calls`, config-level `schema_violation_escalation_threshold` auto-flips layer behavior from "route-this-package" to "route-all-packages" until rate recovers (full conservative mode).

**Scenario 3 — "The model-file bundled in the wheel got poisoned via our own CI/CD."**
- Root cause: training-pipeline secrets leak; attacker reweights features via training-config PR.
- Mitigation in-plan: (a) model-file SHA256 pinned in `src/aigate/ml/__init__.py` outside the bundle; two-person review on any change. (b) training pipeline in locked-down GitHub environment. (c) deterministic rebuild via `tools/train_metadata_ml.py`. (d) third-party `tools/verify_model.py` re-train check.

**Scenario 4 (NEW — iter-2, per Architect §2 Tension 1 + §6 Check 4) — "Pickled ML model shipped in aigate wheel caused RCE when a user's pip mirror was compromised."**
- Root cause: hypothetical 2026-Q3: a regional PyPI mirror is compromised. Attacker replaces the `aigate-0.7.0-py3-none-any.whl` with a lookalike containing a poisoned `metadata-ml-v1.joblib.gz`. Users running `pip install aigate` from that mirror get a wheel whose on-first-load `joblib.load()` executes attacker shellcode. aigate, a supply-chain-security tool, becomes the supply-chain vector. Incident class: same as NullifAI (ReversingLabs Feb 2025), JFrog PickleScan CVEs (June 2025), CVE-2025-1716, NVIDIA NeMo CVE-2025-23304.
- Early warning: none — the first execution of `aigate check` fires RCE. By the time the SHA256-mismatch alert fires, the attacker's shell has already run.
- Mitigation in-plan (iter-2, **PRIMARY**):
  - (a) **Ship the ML artifact as `skops.io` format, NOT `joblib`/`pickle`.** skops.io uses a whitelist-based deserialization (`trusted=[...]` explicit types) and does NOT execute arbitrary code at load time. Verified: actively maintained (v0.13, MIT license, HF + sklearn-core-maintainer backed), supports sklearn Pipeline/wrappers; `CalibratedClassifierCV(HistGradientBoostingClassifier)` reduces to supported primitives. Format is protocol-versioned (plan pins the protocol).
  - (b) **Pre-deserialization SHA256 verification** (defense-in-depth even with skops): `verify_model_integrity()` reads bytes from disk, computes SHA256, compares against `MODEL_SHA256` constant **before** calling `skops.io.load`. Mismatch → `Verdict.ERROR` with `model_integrity_mismatch(CRITICAL)` signal; backend refuses to load.
  - (c) **Fallback path only if skops.io cannot represent a CalibratedClassifierCV wrapper** (verified low-risk but budgeted): use `joblib` + `BytesIO`-loaded-only-after-SHA256-match; document fallback explicitly and require two-person review to enable it. Training script emits BOTH artifacts; CI tests both paths; runtime preferrs skops.io if available.
  - (d) **Wheel-itself integrity** — this is the residual risk class that aigate **cannot** fully prevent. Clarification (iter-3, correcting iter-2 self-contradiction): the `MODEL_SHA256` constant lives at `src/aigate/ml/__init__.py` **inside** the Python module as a module constant (shipped in the wheel). It is NOT "outside the wheel" — iter-2 text was wrong. What inside-wheel SHA256 actually buys you:
    - **Defense-in-depth against *post-install* tampering of just the `.skops` file** — e.g. another process on the same host with filesystem write access to `site-packages/aigate/ml/models/` swaps the model bytes but leaves `__init__.py` untouched. Pre-load SHA256 verification catches this.
    - **Does NOT protect against whole-wheel replacement by a compromised PyPI mirror or typosquat wheel**, because the attacker who controls the wheel controls BOTH `MODEL_SHA256` AND the `.skops` bytes. This class is the residual.
  - (e) **Mitigations for the whole-wheel class** (aigate-level, imperfect): (1) documenting recommended `pip install --require-hashes` in `docs/install-security.md`; (2) publishing wheel SHA256 in `CHANGELOG.md` + signed GitHub Release artifact; (3) **ADR follow-up: adopt PEP 740 / Sigstore attestations on aigate's own wheel**. Per iter-3 research: PEP 740 was GA Nov 2024; as of 2026-Q1 ~5% of top-360 PyPI projects publish attestations (~20K total attestations uploaded; two-thirds of top packages haven't cut a release since GA). aigate adopts attestations at v0.6 release via `pypa/gh-action-pypi-publish` Trusted Publisher flow — this is the wheel-level integrity story.
  - **Honest residual risk (restated after iter-3 clarification):** if a user installs from a compromised mirror without `--require-hashes` AND does not verify sigstore attestation, the attacker who controls the wheel controls both `MODEL_SHA256` and the `.skops` bytes and can disable every in-wheel check. The inside-wheel SHA256 is NOT a mitigation for this class — it is only a mitigation against post-install tampering of just the model file. This class is structural to Python packaging and is resolved (not by aigate but by the ecosystem) via sigstore/cosign on release wheel (plan adopts; ADR follow-up tracks broader Trusted-Publisher adoption).

**Scenario 5 (NEW — iter-3, per Architect iter-2 BLOCKER 2) — "chalk/debug-class maintainer-takeover day-8 attack on an established npm package."**
- Root cause: hypothetical 2026-Q3. Attacker compromises the maintainer token for a 10-year-old npm package (call it `legit-util`, 80M weekly downloads, 24 stable maintainers for 2+ years, repo + homepage both resolve). Publishes `legit-util@5.2.7-malicious` with postinstall-free import-time exfil. Sits for **8 days** before being exploited (attacker's operational choice: delay reduces chance of detection-by-automated-tools). On day 8 the attacker's C2 activates and widescale installs start from CI systems worldwide.
- Early warning: on **day 0-6** aigate blocks short-circuit via `min_version_age_days: 7` (iter-3 new gate) — LLM consensus runs; attacker's exfil is (hopefully) caught by prefilter or LLM-on-diff. On **day 7+**, short-circuit becomes eligible. At this point the package has passed all iter-2 hard gates (14 days > pkg_age, 5+ releases, stable maintainer set 30d+) AND now passes iter-3 `min_version_age_days: 7`. Provenance-continuity gate fires IF `5.2.6` had OIDC attestation but `5.2.7` doesn't — catches most top-tier npm packages post-2024 (Trusted Publishers adoption high on well-known packages). If attacker ALSO publishes with matching attestation (requires compromising the publishing account, not just the npm token) the gate passes.
- What happens in aigate on day 8 if attacker evades all gates: short-circuit fires. ML sees feature vector indistinguishable from benign top-decile (established package, stable maintainers, repo resolves, version >7d old, provenance-continuity holds). LLM skipped. Exfil at import.
- Mitigation in-plan (iter-3):
  - (a) **Retroactive OSV+Aikido pipeline (PR-6)** runs daily. Once OSV or Aikido publishes the advisory (typically hours-to-days after first reports), shadow-log is re-scanned; any short-circuited confirmed-FN retroactively triggers `gold_label = MALICIOUS` which (i) trips the kill-switch `high_profile_fn_threshold_downloads_per_week: 1000` unconditional floor instantly (legit-util is 80M weekly), (ii) flips short-circuit mode to `shadow` for ALL users running the affected model version, (iii) emits `aigate doctor` RED banner, (iv) logs to `~/.aigate/retroactive-fn.jsonl` for user review.
  - (b) **Sygnia Sep 2025 chalk report data point:** compromise-to-publish was 16 minutes; compromise-window-live was ~2 hours. Most real-world takeovers are **exploited within hours**, not sit-dormant-for-8-days. Delay-8-days is a tail-risk — the `min_version_age_days: 7` closes the dominant attack window while retroactive verification closes the dormant-sleeper class.
  - (c) **Interactive mode default threshold 0.97** is a deeper moat than CI 0.90: on residual 0.07-confidence-gap exposure (flagged in Architect iter-2 §3.3, quantified in iter-3 threat model doc), developer laptops are protected more conservatively than CI systems. A developer running `pip install legit-util` in an interactive shell with `isatty()==true` faces 0.97 threshold which is above typical ML confidence on maintainer-takeover-class attacks (ML sees "no red flags" → conf 0.92-0.95 typically, below 0.97 → short-circuit blocked).
- **Honest residual risk:** a week-8+ dormant takeover on a very-high-reputation package with provenance-preserving compromise (attacker also owns publishing identity) passes all aigate checks. This class is structurally outside aigate's static-analysis reach and requires (a) sigstore-signed attestation-transparency-log verification (ADR follow-up), (b) behavioral sandbox-at-install-time (out of aigate's scope — aigate deliberately never executes package code per Class-D threat model documented in `docs/ml-short-circuit-threat-model.md`), or (c) runtime-hook instrumentation (out of scope).

### Expanded test plan

**Unit tests** (run on every PR, target p95 < 10s for the suite):
- `tests/unit/test_metadata_ml_features.py` — each of the 48+ features (Architect §4a added `maintainer_set_changed_within_30d` as feature #49): (a) extraction test, (b) missing-field sentinel, (c) monotonicity sanity.
- `tests/unit/test_metadata_ml_backend.py` — missing-model → `Verdict.ERROR`; **skops-load primary, joblib fallback only if skops fails, both with pre-SHA256 verification**; sklearn-version mismatch → warning + load; latency < 50ms on 10-pkg batch.
- `tests/unit/test_model_artifact_security.py` (NEW) — (a) corrupted bytes → pre-load SHA256 rejection; (b) skops `trusted=[...]` list rejects unknown types; (c) attempt to load a joblib that contains a forbidden opcode → rejection; (d) `verify_model_integrity` never calls `skops.io.load`/`joblib.load` on mismatched bytes.
- `tests/security/test_skops_cve_2025_54412.py` (NEW — iter-3) — reproduces the GHSA-m7f4-hrc6-fwg3 POC: forged `OperatorFuncNode` with `__module__: "sklearn.linear_model._stochastic_gradient.SGDRegressor"` + `__class__: "call"` that attempts `operator.call` execution on load. Asserts: (a) with our shipped `skops_trusted_types: []` empty whitelist, `skops.io.load(..., trusted=[])` raises `UntrustedTypesFoundException` **before** executing any operator method; (b) `aigate ml load` surfaces this as `model_integrity_mismatch(CRITICAL)` and refuses verdict; (c) the test runs against whatever `skops` version the `[ml]` extra resolves to — so if CI ever accidentally un-pins back to a vulnerable version, this test becomes an early-warning not a blocker-after-release. Wired into `.github/workflows/ci.yml` on every PR (not just release tag), under a dedicated `security-tests` job that MUST pass for merge. Reference: [GHSA-m7f4-hrc6-fwg3 advisory](https://github.com/advisories/GHSA-m7f4-hrc6-fwg3), fixed in skops v0.12.0, commit `0aeca055509dfb48c1506870aabdd9e247adf603`, published 2025-07-25, CVSS 8.7.
- `tests/unit/test_ipi_catalog.py` — each `IPIPattern` positive + negative fixture; unicode normalization; nonce uniqueness; fake-tag-closure with different nonce does NOT match.
- `tests/unit/test_ipi_metadata_scan.py` (NEW per Architect revision #9) — `scan_for_ipi()` must flag `ipi_pattern(HIGH)` when `PackageInfo.description` or `PackageInfo.author` contains `"ignore previous"` / tag-closure / role-injection / obfuscation; registry-sourced strings are author-controlled, not trusted.
- `tests/unit/test_ipi_dual_llm_schema.py` — schema violation → `NEEDS_HUMAN_REVIEW` (iter-2 revised, not `metadata_only_only`); rate-based escalation threshold flips to full-corpus routing above 5%.
- `tests/unit/test_consensus_ml_vote.py` — weighted vote; disagreement rules; **tightened metadata-only disagreement rule** (Architect §2 Tension 3): `full_code=SAFE ∧ metadata_only.verdict≠SAFE ∧ metadata_only.confidence≥0.7 ∧ (full_code.conf - metadata_only.conf) < 0.3` → `NEEDS_HUMAN_REVIEW`; else signal-only.
- `tests/unit/test_short_circuit_hard_gates.py` (NEW) — verify short-circuit blocked when `pkg_age_days<14`, or `num_releases<5`, or `maintainer_set_changed_within_30d=true`, or neither repository nor homepage resolves, **or (iter-3) `version_age_days<7`, or (iter-3) `provenance_continuity` violated (prior version had attestation but current doesn't)**, regardless of ML confidence. CRITICAL: test asserts that when a hard gate fails, ML backend STILL votes (short-circuit is only the fast-path; ML participates in LLM consensus if LLM enabled).
- `tests/unit/test_version_cooldown_gate.py` (NEW iter-3) — fixture: chalk@5.3.0-malicious (hypothetical) published 2h ago from stable 10-year-old package → short-circuit BLOCKED, LLM consensus runs. Same package-version 8 days old → short-circuit ALLOWED if other gates pass. Also: `axios@1.14.1` published 5h ago dropping OIDC when `1.14.0` had it → provenance_continuity gate BLOCKS short-circuit regardless of version age.
- `tests/unit/test_short_circuit_context_threshold.py` (NEW) — `CI=true` env → threshold 0.90; interactive TTY → 0.97; verified via monkey-patched `os.environ` and `sys.stdout.isatty()`.
- `tests/unit/test_kill_switch.py` — 1.5× + absolute floor 5/24h for short-circuit; 2.0× + absolute floor 10/24h for general; **unconditional floor**: FN on package with >1000 downloads/week trips immediately.
- `tests/unit/test_shadow_log.py` — schema v1; rotation; 1% sampling; no PII.

**Integration tests** (run on PR + nightly):
- `tests/integration/test_ml_llm_cooperative_vote.py` — 4 toggle combinations.
- `tests/integration/test_ipi_stack_end_to_end.py` — prefilter → readers → consensus.
- `tests/integration/test_dual_llm_with_real_backend.py` — opt-in via env var.
- `tests/integration/test_shadow_mode_no_user_impact.py` — bit-for-bit invariant.
- `tests/integration/test_retroactive_aikido_join.py` (NEW per Architect revision #12) — synthetic Aikido feed JSON + synthetic OSV dump; both feeds are joined against shadow log; Aikido consumed via HTTPS, not bundled.

**E2E tests** (tagged releases):
- `tests/e2e/test_hybrid_check_real_pypi.py`.
- `tests/e2e/test_hybrid_check_malicious_fixture.py`.
- `tests/e2e/test_airgapped_mode.py` — `AIGATE_OFFLINE=1`; Claude/Gemini absent; ML + prefilter still produce a verdict; **also asserts `remote_kill_switch_url: null` default — no outbound fetches occur**.
- `tests/e2e/test_short_circuit_threshold_honored.py` — 1000 synthetic-safe packages; count LLM invocations via mock; ≥95% short-circuit in `aggressive` mode; 0 short-circuits when any hard gate fails.

**Observability tests** (nightly):
- `tests/observability/test_shadow_log_schema_v1.py`.
- `tests/observability/test_drift_detector.py`.
- `tests/observability/test_retroactive_osv_aikido_join.py` — both feeds, synthetic dumps.
- `tests/observability/test_ipi_violation_rate_alarm.py` — 5% schema-violation injection triggers full-corpus-routing escalation.
- `tests/observability/test_temporal_split_stable_vs_adversarial.py` (NEW) — train on synthetic corpus; assert `temporal_test_stable` and `temporal_test_adversarial` metrics are reported separately; promotion gate reads `_stable` only.

---

## Plan proper

### Scope

**In scope:** (unchanged except for additions flagged `[iter-2]`)
- New `MetadataMLBackend`; **ML artifact in `skops.io` format primary, pickle-family only as pre-SHA256-verified fallback**.
- Hardened IPI defense: layered (pattern catalog incl. metadata fields, spotlighting hardening, metadata-only reader with tightened disagreement rule, Dual-LLM default-OFF, optional classifier).
- Shadow-mode logging, 3-stage promotion gates, kill switch with absolute floors, **retroactive OSV + Aikido Intel pipeline**.
- Config schema extensions including **short-circuit hard gates** and **context-aware thresholds**.
- Python 3.11-3.13 compatibility preserved; **sklearn + skops.io gated behind `[ml]` optional extra; pydantic gated behind `[ipi]` optional extra**.

**Out of scope (explicit):**
- Replacing LLM backends.
- Adding new LLM providers.
- SBOM / sigstore-signed wheels (ADR follow-up).
- Web UI / dashboard.
- Per-user account / fleet management.
- `transformers` / `xgboost` / `lightgbm` as required deps.
- ML-only MALICIOUS short-circuit (Stage-3 future work).

### Milestones & PRs

**PR-1 — IPI pattern catalog + prefilter integration + metadata-field IPI scan**
- Files:
  - `src/aigate/ipi.py` (new, ~320 LOC) — `IPIPattern`, `IPI_CATALOG`, `scan_for_ipi()`, `scan_metadata_fields()` (NEW), `normalize_unicode()`, `datamark()`, `generate_delimiter_nonce()`.
  - `src/aigate/prefilter.py` (modified, +70 LOC) — scan all text files; **also scan `PackageInfo.description` and `PackageInfo.author`** (Architect rev #9). Emit `ipi_pattern(HIGH): ipi.tag.close_untrusted in PackageInfo.description`.
  - `src/aigate/config.py` (modified, +40 LOC) — `IPIDefenseConfig` with `enabled`, `scan_docs`, `scan_metadata_fields`, `unicode_normalize`.
  - `tests/unit/test_ipi_catalog.py`, `tests/unit/test_prefilter_ipi.py`, `tests/unit/test_ipi_metadata_scan.py` (new).
  - `tests/fixtures/ipi/{direct_override,tag_closure,role_injection,obfuscation,verdict_leak,metadata_injected,benign_but_flagged}/`.
  - `docs/ipi-defense.md`.
- Acceptance (new + existing):
  - 100% of `IPIPattern` entries have ≥1 positive + ≥1 negative fixture.
  - FP ≤ 2/200 on top-100 PyPI + top-100 npm.
  - Metadata-field scan catches all 6 `metadata_injected` fixtures.
  - `scan_for_ipi` p95 < 50ms on 10MB dump.
  - Unicode-normalize defeats zero-width-injected variants (100/100).
  - 0 new ruff errors; all 705 unit tests pass.
- Dependencies: none.
- Size: ~550 LOC, 2 days.
- Rollback: revert; or `ipi_defense.scan_metadata_fields: false`.

**PR-2 — Spotlighting hardening (unchanged except tests)**
- Files: same as iter-1.
- Acceptance: same as iter-1; nonce 10K uniqueness, datamark <2× length, etc.
- Dependencies: PR-1.
- Size: ~200 LOC, 1 day.
- Rollback: spotlighting toggles to `false`.

**PR-3 — Metadata-only second reader with tightened disagreement rule**
- Files: same as iter-1 PR-3 plus:
  - `src/aigate/consensus.py` — `_detect_reader_disagreement()` implements the **revised rule (Architect §2 Tension 3):**
    ```python
    if (full_code.verdict == SAFE
        and metadata_only.verdict != SAFE
        and metadata_only.confidence >= 0.7
        and (full_code.confidence - metadata_only.confidence) < 0.3):
        ipi_signals.append("prompt_injection_suspected(HIGH)")
        final_verdict = NEEDS_HUMAN_REVIEW
    elif (full_code.verdict == SAFE
          and metadata_only.verdict != SAFE):
        # emit signal, but do not override verdict
        ipi_signals.append("reader_disagreement(MEDIUM)")
        final_verdict = full_code.verdict  # keep SAFE
    ```
- Acceptance:
  - For all `stacked_with_real_malware/*` fixtures with mocked full-code=SAFE@0.95, metadata-only=MALICIOUS@0.8 → `NEEDS_HUMAN_REVIEW`.
  - For new-legit-package fixtures with full-code=SAFE@0.95, metadata-only=SUSPICIOUS@0.5 → SAFE preserved, `reader_disagreement(MEDIUM)` emitted.
  - LLM call count doubles with layer enabled.
  - FP rate ≤ 3% on top-100 benign (target: tight disagreement rule is less noisy than iter-1's simpler rule).
- Dependencies: PR-2.
- Size: ~320 LOC, 1.5 days.
- Rollback: `ipi_defense.metadata_only_reader.enabled: false`.

**PR-4 — MetadataMLBackend + training pipeline + shadow-mode wiring (PROMOTED AHEAD OF DUAL-LLM per Architect §4(c) / revision #11)**

Rationale for re-sequencing: iter-1 ordered ML as PR-5 (after Dual-LLM). Architect revision #11 confirms PR-5 (now PR-4) can parallelize with Lane A — shadow mode has zero verdict impact, so ML can land earlier and the 4-week shadow clock starts sooner. This compresses calendar time and starts evidence accumulation before Dual-LLM lands.

- Files:
  - `pyproject.toml` — `[project.optional-dependencies] ml = ["scikit-learn>=1.4,<1.9", "skops>=0.12.0,<0.20", "numpy>=1.26"]`. **Iter-3: skops minimum is `0.12.0`** (CVE-2025-54412 / GHSA-m7f4-hrc6-fwg3 fix — "Inconsistent Trusted Type Validation enables hidden `operator` Methods Execution via forged `__module__`"; advisory published 2025-07-25; fix commit `0aeca055509dfb48c1506870aabdd9e247adf603`). CI `test_skops_cve_2025_54412.py` re-verifies the shipped whitelist rejects the POC, providing defense-in-depth if a future un-pin slips in. **NOTE: no `joblib` in default `ml` extra; `joblib` moves to `[ml-fallback]` extra, used only if skops.io cannot deserialize the model (budget-tested to never fire in CI).**
  - `src/aigate/ml/__init__.py` — `MODEL_SHA256` constant (two-person-review guarded); `verify_model_integrity(path)` reads bytes, verifies SHA256, returns bytes-or-raises; `load_model(bytes)` tries `skops.io.load` first (with explicit `trusted=[...]` whitelist), falls back to `joblib.load` from `BytesIO` ONLY if `skops` import fails AND the bytes are a detected joblib magic header AND `ml.artifact.allow_joblib_fallback: true` (default false).
  - `src/aigate/ml/features.py` — `FEATURE_NAMES` (now 49, adding `maintainer_set_changed_within_30d`), `MONOTONIC_CST`, `extract_features_runtime()`, `extract_features_offline()`.
  - `src/aigate/ml/drift.py` — `log_prediction()`, `compute_drift()`.
  - `src/aigate/ml/models/metadata-ml-v1.skops` (binary, target ≤ 1MB uncompressed, ~400-600KB compressed via skops native zlib option).
  - `src/aigate/ml/models/metadata-ml-v1.ref.json`.
  - `src/aigate/backends/metadata_ml.py` — `MetadataMLBackend(AIBackend)`.
  - `src/aigate/consensus.py` — register `metadata-ml` in `BACKEND_MAP`; shadow-mode wiring; **context-aware threshold resolver** reading `CI=true` / `GITHUB_ACTIONS` / `sys.stdout.isatty()` to pick `short_circuit_confidence_threshold_ci` vs `_interactive`; **hard-gate resolver** checking (all must pass for short-circuit; any failure → short-circuit blocked, ML **still votes** in LLM consensus): `pkg_age_days ≥ 14`, `num_releases ≥ 5`, `maintainer_set_changed_within_30d == false`, `(repository OR homepage).resolves_to_real_host == true`, **NEW in iter-3 — `version_age_days ≥ 7`** (blocks chalk/Axios-class maintainer-takeover on established packages publishing a brand-new malicious version), **NEW in iter-3 — `provenance_continuity_holds == true`** (if `PackageInfo.prior_provenance.has_attestation == true` for any prior version in the package, current version MUST also have attestation; if no prior version had attestation, gate is a no-op — see config notes on adoption-rate fallback).
  - `src/aigate/shadow_log.py`.
  - `src/aigate/config.py` — `MLConfig` with: `enabled`, `mode`, `weight`, `short_circuit.confidence_threshold_ci: 0.90`, `short_circuit.confidence_threshold_interactive: 0.97`, `short_circuit.hard_gates: {min_pkg_age_days: 14, min_num_releases: 5, maintainer_set_changed_within_30d_must_be_false: true, require_any_of_repo_or_homepage_resolves: true, min_version_age_days: 7, require_provenance_continuity: true}`, `model_path_override`, `threshold_malicious: 0.60`, `threshold_suspicious: 0.20`, `artifact.format: "skops"` (default) | `"joblib"` (opt-in, requires `allow_joblib_fallback: true`). **Iter-3 adds `PackageInfo.prior_provenance: dict | None`** (npm: OIDC attestation presence per prior version via `npm view --json` attestations field; PyPI: PEP 740 attestations via `pypi.org/simple` JSON API v1.3+); iter-3 also adds `PackageInfo.version_published_at: datetime` (already resolvable from PyPI `releases[version][0].upload_time` / npm `time[version]`).
  - `tools/train_metadata_ml.py` — outputs `.skops` by default; emits `.joblib.gz` only with `--emit-joblib-fallback` flag.
  - `tools/verify_model.py` — re-train check + format verification (skops-primary, joblib-fallback).
  - Tests as listed above including new `test_model_artifact_security.py`, `test_short_circuit_hard_gates.py`, `test_short_circuit_context_threshold.py`, `test_temporal_split_stable_vs_adversarial.py`.
  - `data/labels/` — tuples list.
  - `NOTICE` — OSSF malicious-packages attribution; skops.io attribution (MIT).
  - `docs/ml-short-circuit-threat-model.md` (NEW doc, iter-3 non-blocking #6): comprehensive threat-model document covering Class A-D attack families with per-family mitigations, residuals, and detection coverage estimates. **Includes quantitative analysis of the CI-mode 0.07-confidence-gap exposure window** (between interactive threshold 0.97 and CI threshold 0.90): estimated from iter-2 shadow-mode data structure (when Stage-1 evidence arrives) — our order-of-magnitude prior is ~2-5% of short-circuit-eligible packages fall in the `[0.90, 0.97)` confidence band (derived from calibrated-model literature: a well-calibrated binary classifier with Brier ≤0.05 places ~60% of predictions above 0.95 and ~10-15% in [0.85, 0.95]; after subtracting the ~50% that fall above 0.97 already, the gap-band is ~2-5%). **Document also specifies:** (a) the attack class that specifically exploits the CI gap is "packages passing all hard gates including iter-3 `min_version_age_days: 7` AND `require_provenance_continuity` AND where ML returns confidence ∈ [0.90, 0.97)" — a narrow intersection. (b) CI operators who want to close the gap opt into `confidence_threshold_ci: 0.97` (= matching interactive) at ~15-25% cost of reduced short-circuit rate. (c) Until shadow-mode data is collected the 2-5% figure is a prior, not an observation; re-measure and update the doc at Stage-1 promotion.
- Acceptance (iter-2 strengthened):
  - Training produces a model that on **`temporal_test_stable` (pre-2025-07)** achieves: PR-AUC ≥ 0.95, Brier ≤ 0.05, ROC-AUC ≥ 0.97, per-family F1 ≥ 0.85. These are the **promotion-gate metrics.**
  - **`temporal_test_adversarial` (post-2025-07) metrics reported as diagnostics**; no gate.
  - Inference p95 < 50ms, p99 < 150ms.
  - Model file (skops.io zlib) ≤ 1MB; joblib fallback (if emitted) ≤ 1.5MB. **Iter-3: CI assertion `assert os.path.getsize("src/aigate/ml/models/metadata-ml-v1.skops") <= 1_048_576` enforced in `tests/unit/test_model_size_budget.py` — failing build if bloat regression sneaks in. Prevents silent joblib-fallback activation by ensuring skops-zlib stays within budget.**
  - Missing/corrupt model or SHA256 mismatch → `Verdict.ERROR` + `model_integrity_mismatch(CRITICAL)` signal. Validated via byte-flip test.
  - skops.io deserialization uses explicit `trusted=[...]` whitelist; test verifies unknown-type input is rejected without executing code.
  - Default aigate install (no `[ml]` extra) still passes all 705 unit tests.
  - Python 3.11 / 3.12 / 3.13 CI matrix: all three pass ML tests and non-ML tests.
  - Shadow-mode invariant: `final_verdict` bit-for-bit identical to LLM-only for 100 seeded packages.
  - Hard-gate tests: short-circuit BLOCKED on any hard-gate failure regardless of ML confidence (100% of bypass-attempt fixtures).
  - Context-threshold tests: CI=true uses 0.90; interactive uses 0.97.
  - No raw malicious source in repo.
- Dependencies: PR-1 (for `IPI_CATALOG` utilities shared with metadata scan).
- Parallelization: **can land after PR-1, before PR-2/PR-3 stabilize** (Architect §4(c)). The `consensus.py` edits are in a separate code region from PR-2/PR-3's edits; minor merge-conflict risk only.
- Size: **~2,850 LOC, 5.5 days (iter-3: +250 LOC for version-cooldown + provenance-continuity resolver + 2 new unit-test files + skops-CVE test + `PackageInfo.prior_provenance` resolver in registry clients)**.
- Rollback: `ml.enabled: false` or uninstall `[ml]` extra.

**PR-5 — Optional Dual-LLM (default-OFF; schema-violation escalation; cost-regression warning)**

Rationale for downgrading to default-OFF (Architect §2 Tension 2 + §6 Check 3 + revision #3): Reversec Labs 2025 / DeepMind CaMeL 2025 literature establishes that Dual-LLM secures only control flow, not data flow — attackers still influence schema-compliant argument values. PR-3's metadata-only reader provides ~80% of the same security property at 50% of the LLM-cost. Economics require short-circuit rate >55% for Dual-LLM-ON to not regress cost; with realistic Stage-1 metrics (60-80% short-circuit) we expect this to hold, but only for a subset of users.

- Files:
  - `src/aigate/models.py` — `BehaviorSummary` pydantic model. **`pydantic>=2.6` moves to `[project.optional-dependencies] ipi = [...]`** (Architect §3 Principle 2 / revision #5). Schema validation falls back to `json.loads` + manual dict-validation when pydantic missing.
  - `pyproject.toml` — `[project.optional-dependencies] ipi = ["pydantic>=2.6,<3"]`.
  - `src/aigate/backends/base.py` — `QUARANTINED_SYSTEM_PROMPT`, `_build_quarantined_messages()`, `BehaviorSummary.model_validate_json(extra="ignore")` or fallback dict-validation.
  - `src/aigate/consensus.py` — Dual-LLM stage; **schema-violation auto-escalates to `NEEDS_HUMAN_REVIEW` for THAT package** (Architect §4(b), revision #10); rate-based `schema_violation_escalation_threshold: 0.05` auto-flips to "all-packages-routed" mode when sustained >5% over last 1000 calls.
  - `tests/integration/test_dual_llm.py` — schema-violation branch (asserts `NEEDS_HUMAN_REVIEW`, NOT `metadata_only_only`); rate-escalation branch; privileged-sees-no-raw-code.
  - `tests/fixtures/quarantined_responses/`.
- Acceptance:
  - Schema success ≥ 98% on 100-pkg corpus.
  - When enabled and all 3 readers run, per-package LLM cost doubles vs single-reader baseline; documented.
  - `quarantined_llm_schema_violation(HIGH)` emitted at WARNING; that package routes to `NEEDS_HUMAN_REVIEW`; if rate >5% over 1000 calls, all packages route until recovery.
  - `aigate doctor --ipi-stats` reports schema-violation rate AND cost-regression warning: if `(short_circuit_rate × 1 + (1-short_circuit_rate) × 2) > 1.2`, print RED banner "Dual-LLM net cost regression detected. Disable or wait for higher short-circuit rate."
  - **Default: `dual_llm.enabled: false`.** Users opt in knowingly.
- Dependencies: PR-3.
- Parallelization: **can be developed in shadow mode in parallel with PR-4 landing** (Architect revision #11) — Dual-LLM code paths gated behind config flag; verdict impact only engages post-promotion.
- Size: ~450 LOC, 3 days.
- Rollback: `ipi_defense.dual_llm.enabled: false`. Pydantic dep is already optional-extra.

**PR-6 — Kill switch + retroactive OSV+Aikido verification pipeline + opt-in telemetry**
- Files:
  - `src/aigate/kill_switch.py` — local circuit breaker: **1.5× + absolute floor 5 FN/24h for short-circuit, 2.0× + absolute floor 10 FN/24h for general** (Architect §4(d), revision #8); **unconditional floor:** any confirmed FN on a >1000 downloads/week package immediately flips short-circuit to shadow. Remote kill-list: `~/.aigate/cache/kill.json` refreshed ≤24h, **only if `remote_list_url != null`** (Architect §3 / revision #4 — default `null`, opt-in only).
  - `src/aigate/retroactive.py` — daily OSV dump pull; **ALSO Aikido Intel feed pull** (`https://intel.aikido.dev/malware_predictions.json`, `https://intel.aikido.dev/malware_pypi.json`) — consumed via HTTPS, not bundled, not redistributed (Architect revision #12). AGPL note in `docs/threat-intel-sources.md`: "Aikido Intel data feed is consumed via public HTTPS endpoints and used as input only; no AGPL-licensed Aikido software is bundled in aigate. This is a data-consumption pattern analogous to fetching any HTTP-accessible dataset." Left-join both feeds by `(ecosystem, name, version)`; backfill `gold_label`; compute precision / recall / lead_time stats.
  - `src/aigate/telemetry.py` — opt-in uploader; scope hashing; CI auto-disable; **default `telemetry.endpoint: null`** (local-only v1, per open-question #3).
  - `scripts/daily_retroactive.py`.
  - `tests/unit/test_kill_switch.py`, `test_retroactive.py`, `test_telemetry_privacy.py`, `test_kill_switch_absolute_floor.py` (NEW), `test_aikido_feed_parser.py` (NEW).
- Acceptance:
  - Kill-switch trips at 1.5× OR ≥5 FN/24h OR ≥1 FN on high-download package (whichever first) in short-circuit lane.
  - Retroactive join correctly backfills 10/10 on synthetic OSV + 10/10 on synthetic Aikido dumps; deduplication when both feeds report the same pair.
  - Telemetry off by default; zero network calls in fresh install.
  - AGPL attribution test: `docs/threat-intel-sources.md` is present and correctly names the feed URLs.
- Dependencies: PR-4 (reads shadow log).
- Size: ~900 LOC, 2.5 days.
- Rollback: per-feature toggles all default-off-able.

**PR-7 — Promotion pipeline docs, `aigate doctor` subcommands, promotion-gate CI**
- Files: as iter-1 plus:
  - `scripts/promote_ml.py` — reads `_stable` metrics only (iter-2); `_adversarial` reported but non-gating.
  - `aigate doctor --cost-projection` — NEW subcommand reporting projected LLM cost under current Dual-LLM + short-circuit config; warns at >1.2× baseline.
- Acceptance: as iter-1.
- Dependencies: PR-4, PR-5, PR-6.
- Size: ~550 LOC, 1.5 days.

**Totals:** 7 PRs, **~5,820 LOC, ~17.5 eng-days (serial)** — iter-3 increment: +250 LOC / +0.5 day in PR-4 (version-cooldown + provenance-continuity + skops-CVE test + size-budget test + `PackageInfo.prior_provenance` wiring in registry clients). With 3 lanes (A: PR-1→PR-2→PR-3; B: PR-4 in parallel after PR-1; C: PR-5 shadow-dev after PR-3; D: PR-6→PR-7 after PR-4/PR-5 land), calendar reduces to ~8.5-9.5 days. 4-week shadow clock is the real critical path.

**Iter-3 PR-sequencing rule (consensus.py rebase gate — Architect iter-2 non-blocking #3):** PR-3, PR-4, and PR-5 all edit `consensus.py` in separate code regions (`_detect_reader_disagreement` / `BACKEND_MAP` + hard-gate + context-threshold resolver / Dual-LLM stage). **If two PRs both touch `consensus.py._aggregate_votes` or any shared helper, the second PR to reach merge MUST rebase on main AFTER the first merges AND re-run the full integration test suite (`tests/integration/test_ml_llm_cooperative_vote.py` + `test_ipi_stack_end_to_end.py` + `test_dual_llm.py`) before merge is allowed.** Lane coordination: Lane B (PR-4) rebases-and-retests after Lane A (PR-3) merges; Lane C (PR-5) rebases-and-retests after whichever of Lane A/B merges later. This is codified in `.github/CODEOWNERS` + PR-template checklist item "☐ If this PR touches `consensus.py`, confirm rebase on main AND integration suite pass within the last 24h." Non-blocking for any individual PR author, but merging out-of-sequence without the rebase is blocked by CI.

### Sequencing rationale (iter-2 revised)

- **PR-1 first** — pure static analysis; immediate catch-rate improvement; ships in 2 days with zero regression risk. Now includes metadata-field scanning (revision #9).
- **PR-2 second** — depends on PR-1 utilities; still prompt-only.
- **PR-3 third** — metadata-only second reader. Tightened disagreement rule (§2 Tension 3). Ships the ~80% Dual-LLM-equivalent protection at 50% of the cost.
- **PR-4 (promoted from old PR-5) — parallelizable with PR-2/PR-3** — ships ML in shadow mode; starts 4-week shadow clock immediately; includes short-circuit hard gates and context-aware thresholds; **skops.io primary serialization eliminates the pickle-RCE class**.
- **PR-5 (demoted from old PR-4) — default-OFF Dual-LLM** — dev can parallelize with PR-4 landing (shadow/config-flag gated). Lower priority because (a) default-OFF, (b) PR-3 covers most of the threat, (c) cost economics uncertain.
- **PR-6 after PR-4** — kill switch + retroactive pipeline + Aikido integration. Depends on shadow log existing.
- **PR-7 last** — read-only diagnostic UX; depends on all subsystems.

Parallelization:
- Lane A: PR-1 → PR-2 → PR-3 (IPI stack, ~4.5 eng-days serial).
- Lane B: PR-4 (ML + shadow, starts after PR-1, ~5 eng-days).
- Lane C: PR-5 (Dual-LLM, starts after PR-3, ~3 eng-days).
- Lane D: PR-6 → PR-7 (infra + UX, after PR-4 ships; ~4 eng-days).

### Configuration schema (iter-2 complete)

```yaml
# Existing sections unchanged.

ml:
  enabled: true
  mode: shadow                         # off | shadow | vote | short_circuit_safe | short_circuit_both
  weight: 0.5
  short_circuit:
    enabled_in_mode: true              # global kill of short-circuit even if mode=short_circuit_*
    confidence_threshold_ci: 0.90      # iter-2: context-aware (Architect §2 Tension 5, revision #7)
    confidence_threshold_interactive: 0.97
    hard_gates:                        # iter-2: Architect §4a, revision #2. ALL must pass.
      min_pkg_age_days: 14
      min_num_releases: 5
      maintainer_set_changed_within_30d_must_be_false: true
      require_any_of_repo_or_homepage_resolves: true
      min_version_age_days: 7          # iter-3 (BLOCKER-2): the SPECIFIC version being scanned must be ≥7 days old. Catches chalk/debug (Sep 2025, 16-min compromise-to-publish), Axios (Mar 2026, 4-5h window). Matches npm --min-release-age / pnpm minimumReleaseAge / Yarn npmMinimalAgeGate / Bun minimumReleaseAge. Gate applies to SHORT-CIRCUIT only; ML backend STILL RUNS and STILL VOTES in LLM consensus if version_age_days < 7. Scope restriction is intentional.
      require_provenance_continuity: true   # iter-3 (BLOCKER-2): if ANY prior version of this package had OIDC attestation (npm) / PEP 740 attestation (PyPI), current version MUST also have matching publisher identity. If NO prior version had attestation, this gate is a no-op (adoption ~5% at 2026-Q1 per PyPI blog; absence ≠ suspicious, only PROVENANCE-CHANGE is suspicious). Detection source: npm `packument.versions[v].dist.attestations` / PyPI `/simple/<pkg>/` PEP 740 JSON.
  model_path_override: null
  threshold_malicious: 0.60
  threshold_suspicious: 0.20
  artifact:                            # iter-2: Architect §2 Tension 1, revision #1
    format: skops                      # skops | joblib (joblib requires allow_joblib_fallback)
    allow_joblib_fallback: false       # safety-fuse; must be explicitly enabled
    verify_sha256_before_load: true    # pre-deserialization SHA256 verification
    skops_trusted_types: []            # overrideable whitelist for skops.io load
  kill_switch:
    enabled: true
    remote_list_url: null              # iter-2: Architect §3 Principle 1, revision #4 — OPT-IN
    remote_refresh_hours: 24
    local_fp_multiplier_short_circuit: 1.5
    local_fp_absolute_floor_short_circuit_24h: 5    # iter-2: Architect §4d, revision #8
    local_fp_multiplier_general: 2.0                 # iter-2: was 3.0
    local_fp_absolute_floor_general_24h: 10          # iter-2
    high_profile_fn_threshold_downloads_per_week: 1000  # iter-2: unconditional floor
    latency_p95_budget_ms: 500
    latency_p95_breach_minutes: 15
  drift:
    enabled: true
    z_threshold: 3.0
    log_path: ~/.aigate/drift.jsonl

ipi_defense:
  enabled: true
  scan_docs: true
  scan_metadata_fields: true           # iter-2: Architect revision #9
  unicode_normalize: true

  spotlighting:
    enabled: true
    sandwich: true
    random_nonce: true
    datamarking: true

  metadata_only_reader:
    enabled: true
    disagreement_severity: HIGH
    disagreement_confidence_threshold: 0.7    # iter-2: Architect §2 Tension 3, revision #3
    disagreement_confidence_gap_max: 0.3      # iter-2

  dual_llm:
    enabled: false                             # iter-2: default-OFF (Architect §2 Tension 2, revision #2)
    quarantined_backend: auto
    on_schema_violation: route_needs_human_review    # iter-2: was metadata_only_only (revision #10)
    schema_violation_escalation_threshold: 0.05      # iter-2: auto-escalate to full-corpus routing
    schema_violation_escalation_window_calls: 1000   # iter-2

  classifier:
    enabled: false
    model: llama-prompt-guard-2-22m    # smaller default; opt-in to 86m for multilingual
    threshold: 0.8
    as_signal_only: true

shadow:
  log_path: ~/.aigate/shadow.jsonl
  rotate_bytes: 52428800
  rotate_keep: 5
  capture_sample_rate: 0.01
  expose_preview: true

telemetry:
  enabled: false
  endpoint: null                       # iter-2: default null (local-only v1, open-question #3)
  remote_kill_switch_url: null         # iter-2: explicit opt-in (revision #4)
  include_features: true
  sample_rate: 1.0
  hash_private_scopes: true
  auto_disable_in_ci: true

retroactive:                           # iter-2: NEW section
  enabled: true
  osv_enabled: true
  aikido_enabled: true                 # iter-2: Architect revision #12
  aikido_npm_url: https://intel.aikido.dev/malware_predictions.json
  aikido_pypi_url: https://intel.aikido.dev/malware_pypi.json
  agpl_notice_ack: false               # iter-3 (non-blocking #4): default-false opt-in. User must explicitly set to true in .aigate.yml OR pass --agpl-ack to use the Aikido feed. On first Aikido fetch with `agpl_notice_ack: false`, aigate prints a one-line note pointing to `docs/threat-intel-sources.md` and skips the Aikido join (OSV still runs). Rationale: default-true silently assumed user consent which is weird UX and legally awkward. Attribution in `docs/threat-intel-sources.md` remains the canonical reference.
```

### Rollback / kill switch per PR (unchanged structure, PR numbers updated)

| PR | Instant rollback | Time |
|----|-----------------|------|
| PR-1 | `ipi_defense.enabled: false` or revert | seconds |
| PR-2 | spotlighting toggles to false | seconds |
| PR-3 | `metadata_only_reader.enabled: false` | seconds |
| PR-4 (ML) | `ml.enabled: false` or uninstall `[ml]` extra | seconds / `pip uninstall` |
| PR-5 (Dual-LLM) | `dual_llm.enabled: false` (already default) | seconds |
| PR-6 | `retroactive.*.enabled: false`; `kill_switch.enabled: false` | seconds |
| PR-7 | read-only | n/a |

Release-wide: `AIGATE_DISABLE_ML=1`, `AIGATE_DISABLE_IPI_DEFENSE=1`, `AIGATE_DISABLE_DUAL_LLM=1`.

### Risks & open questions

**Risks:**

- **R1 — Labeled-list redistributability.** As iter-1. Mitigated.
- **R2 — sklearn 1.7+ forward-compat.** As iter-1. Mitigated.
- **R3 — Llama Prompt-Guard-2 license + bypass.** Iter-2 addition: multiple bypasses confirmed post-April 2025 (Trendyol May 2025, multilingual/unicode). Mitigated: `classifier.enabled: false` default; `as_signal_only: true` posture maintained. Updated in `docs/ipi-defense.md`.
- **R4 — Dual-LLM schema drift.** Iter-2 strengthened: schema-violation now auto-routes that package to `NEEDS_HUMAN_REVIEW` (was `metadata_only_only`); sustained >5% rate flips to full-corpus routing. Pre-mortem Scenario 2 updated.
- **R5 — Shadow-log PII.** As iter-1.
- **R6 — Short-circuit bypass (maintainer takeover / adversarial crafting / clean-code exfil).** Iter-2 hardened: hard gates (min_age, min_releases, maintainer-stability, repo-resolves); context-aware thresholds; absolute-floor kill switches. Residual: maintainer-takeover on popular packages >14 days old with stable maintainer list for 30+ days — documented in threat model, requires LLM.
- **R7 — npm 2025 data-skew.** Iter-2 refined: two temporal test sets, `_stable` gates promotion, `_adversarial` diagnostics-only.
- **R8 (NEW) — Pickled-model RCE.** Iter-2: primary mitigation is skops.io (pickle-free, whitelist-deserialized); secondary is pre-SHA256 verification before any deserialization; tertiary is joblib-fallback gated behind explicit opt-in + SHA256. Pre-mortem Scenario 4 documents full incident path + residual risk.
- **R9 (NEW) — Dual-LLM cost regression.** Iter-2: default-OFF; `aigate doctor --cost-projection` warns when enabling would regress >1.2× baseline.
- **R10 (NEW) — AGPL exposure via Aikido consumption.** Mitigation: aigate never bundles Aikido code; consumes public HTTPS data feed only; documents the consumption model in `docs/threat-intel-sources.md`. Interpretation: AGPL copyleft triggers on distribution of AGPL *software* in modified form; consuming AGPL-licensed data via public API is analogous to consuming any HTTP dataset. Aikido's own launch post explicitly states "developers may freely use, modify, and distribute the vulnerability & malware feed." Apache-2.0 aigate remains Apache-2.0.

**Open questions** (to be appended to `.omc/plans/open-questions.md`):

1. `short_circuit_both` (Stage-3) — dead code behind flag or deferred entirely? **Leaning defer.**
2. Prompt-Guard-2 default variant 22M vs 86M. **Leaning 22M (English-only, CPU-friendly; aigate reads mostly English code).**
3. Telemetry endpoint ownership — **iter-2 decision: ship no endpoint in v1** (`endpoint: null` default), revisit post-MVP.
4. ~~Aikido Intel feed — include?~~ **Iter-2 resolved:** yes, consume-only, non-redistributed. Attribution in `docs/threat-intel-sources.md`.
5. `--show-shadow` UX — concise vs full dump. **Leaning concise two-line preview.**
6. Isotonic vs sigmoid calibration — compute both, ship lower-Brier. **Open.**
7. npm data-cutoff — train ≤2025-07-01, reserve Q4 as adversarial test. **Iter-2 resolved:** yes, two temporal test sets.
8. **NEW:** skops.io protocol version pinning — pin to single protocol or allow range? **Leaning single pinned protocol per model version**; bump protocol triggers a MODEL_SHA256 update + two-person review.
9. **NEW:** joblib fallback — ship at all, or require skops-only? Architect §2 Tension 1 suggests "skops or pre-SHA256-verify-joblib." Iter-2 plan ships skops.io as primary; joblib fallback gated behind `allow_joblib_fallback: true` (default false). **Question: should the fallback exist at all, or should we remove it entirely?** Leaning keep but heavily gated — `CalibratedClassifierCV(HistGradientBoostingClassifier)` is sklearn-core but skops protocol stability is not guaranteed forever; fallback is insurance.

---

## ADR sketch

**ADR-0001: Ship aigate v0.6 with ML + LLM cooperative hybrid + layered IPI defense, via 7 sequenced PRs, ML in `skops.io` format, ML shadow-first, Dual-LLM default-OFF.**

**Decision.** Add `MetadataMLBackend` in shadow mode with ML artifact shipped in `skops.io` (pickle-free, whitelist-deserialized) format; ship 5-layer IPI defense with each layer independently toggleable; promote ML from shadow → vote → short-circuit-SAFE only on `temporal_test_stable` evidence gates (PR-AUC ≥ 0.95, Brier ≤ 0.05, agreement ≥ 95%, retroactive precision ≥ 0.9, ≥50K events, ≥4 weeks); short-circuit subject to hard gates (package age, release count, maintainer stability, repository resolution); Dual-LLM default-OFF because PR-3 metadata-only reader carries ~80% of the protection at 50% of the LLM cost; retroactive verification consumes both OSV and Aikido Intel feeds.

**Drivers.**
1. IPI is active exploitation (Cline/Clinejection ~4,000 machines).
2. LLM cost/latency blocks CI/dev-install UX.
3. Training-corpus drift (OSSF npm Q3-Q4 2025 bulk ingest) requires temporal split + retroactive verification.
4. Flexibility: 4 ML modes × 5 IPI layers, independently composable.
5. **NEW in iter-2:** pickle-family model distribution is 2025's fastest-growing supply-chain attack vector (NullifAI, PickleScan CVE-2025-1716, JFrog 3 zero-days, NVIDIA NeMo CVE-2025-23304); a supply-chain-security tool that RCE-loads pickle on every invocation violates its own principles.

**Alternatives considered.**
- Option A (all-in-one PR) — rejected (review surface + rollback).
- Option C (ship ML short-circuit day-1, IPI later) — rejected (fails Principle 4 + Driver 1).
- Option D (IPI only, no ML) — rejected (fails Driver 2).
- Option E (IPI PR-1+2+3 only, no ML, no Dual-LLM) — **partially adopted**: Dual-LLM defaults OFF per this logic; ML still shipped because Driver 2 requires it.
- **Alternative ML artifact: bundle pickled joblib.gz — REJECTED** because (a) NullifAI (Feb 2025) showed HuggingFace's picklescan bypassed, (b) JFrog (June 2025) disclosed 3 zero-day CVEs in picklescan itself, (c) CVE-2025-1716 picklescan bypass, (d) NVIDIA NeMo CVE-2025-23304 pickle deserialization RCE, (e) a supply-chain-security tool cannot ship pickle as primary model format without violating its own raison d'être. skops.io (MIT, sklearn-ecosystem-maintained, whitelist-based deserialization, protocol-versioned) is the principled choice.
- **Alternative: bundle pickled joblib.gz WITH pre-SHA256 verification — REJECTED as primary** but accepted as heavily-gated fallback for the narrow case where skops.io cannot represent a specific sklearn wrapper. SHA256 is necessary but not sufficient — any code path that calls `pickle.load` / `joblib.load` on bytes is a latent RCE if the SHA256 check is ever bypassed (future refactor, unit-test miss, etc.). skops.io eliminates the class; SHA256 only protects a specific instance.
- **Alternative: Dual-LLM ON by default — REJECTED** because (a) Reversec Labs 2025 / DeepMind CaMeL 2025 show Dual-LLM secures control flow only, not data flow; (b) economics regress cost by up to 1.4× when short-circuit rate <50%; (c) PR-3 metadata-only reader covers ~80% of the same attack classes at 50% cost; (d) users who want the extra defense can opt in knowingly via `dual_llm.enabled: true` + `aigate doctor --cost-projection` check.
- Meta Prompt-Guard v1 — superseded by Prompt-Guard-2 (both 86M and 22M).
- xgboost/lightgbm instead of sklearn HistGBM — rejected (wheel size, marginal accuracy at 49 features).

**Why chosen.** Sequenced PRs ship immediate IPI value (PR-1/PR-2 in ~3 days) while ML accrues evidence in shadow. Layered IPI means any single-layer failure doesn't collapse the defense. skops.io closes the pickle-RCE class structurally. Hard gates + context thresholds + absolute-floor kill switches make short-circuit bypasses quantifiably harder. Dual-LLM default-OFF honors the current literature's posture (necessary-but-insufficient) while keeping the capability latent. Retroactive Aikido consumption improves detection lead time by an order of magnitude without AGPL entanglement. Evidence-gated promotion prevents shipping unvalidated short-circuits.

**Consequences.**
- **Positive:** IPI hardening aligned with 2026 industry best-practice; calibrated local ML with principled serialization; shadow-first culture; OSV+Aikido retroactive verification; 4 ML modes × 5 IPI layers orthogonal.
- **Negative / cost:** 1 new optional extra (`[ml]` with sklearn + skops + numpy); 1 new optional extra (`[ipi]` with pydantic); large wheel for `[ml]` users; 4-6 weeks from ship to first short-circuit promotion; Dual-LLM-enabled users see 2× LLM cost on residual traffic.
- **Irreversible:** `.aigate.yml` keys for `ml:` / `ipi_defense:` / `shadow:` / `telemetry:` / `retroactive:` become public API from v0.6.
- **Reversible:** each PR has a config-flip rollback. Default ships IPI layers 1-3 ON, Dual-LLM + classifier OFF, ML in shadow.

**Follow-ups.**
- Stage-3 ML short-circuit-MALICIOUS (≥0.99 precision at conf ≥0.98, 2 months additional shadow).
- sigstore/cosign on release wheel (mitigates Scenario-4 residual risk at the wheel level).
- Continuous retraining triggered by drift detector.
- CaMeL-style capability-tracked execution (successor to Dual-LLM per DeepMind April 2025).
- ShieldNet-style network-level guardrail for MCP-tool abuse (out of scope; aigate is static).

---

## External Verification Log

All checks run 2026-04-22 (iter-1 entries retained; iter-2 additions flagged).

| Claim | Verification | Status | Notes |
|---|---|---|---|
| OSSF malicious-packages Apache-2.0 | `raw.githubusercontent.com/ossf/malicious-packages/main/LICENSE` 2026-04-22 | CONFIRMED | — |
| Datadog malicious-software-packages-dataset Apache-2.0 | `raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/LICENSE` 2026-04-22 | CONFIRMED | — |
| Llama Prompt-Guard-2 current HF ID | `huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M` 2026-04-22 | CONFIRMED | Llama 3.1 Community License; 86M multilingual, 22M English/CPU-friendly. |
| PromptArmor ICLR 2026 | arXiv:2507.15219 / OpenReview `IeNXtofK6T` 2026-04-22 | CONFIRMED-WITH-CORRECTION | Prompting strategy, not 350M classifier. |
| sklearn `monotonic_cst` API stable through 1.8 | scikit-learn.org/stable 2026-04-22 | CONFIRMED | — |
| sklearn `CalibratedClassifierCV` isotonic caveats | sklearn issue #16321 | CONFIRMED | Compute Brier on both isotonic + sigmoid during training; ship lower-Brier. |
| Python 3.11/3.12/3.13 sklearn 1.4-1.8 | sklearn 1.8.0 docs | CONFIRMED | — |
| Cline/Clinejection ~4000 machines 2026-02-09 | Snyk + adnanthekhan + TheHackerNews | CONFIRMED | — |
| **NEW iter-2: skops.io current state** | `skops.readthedocs.io/en/v0.13` + `pypi.org/project/skops` + `github.com/skops-dev/skops` 2026-04-22 | CONFIRMED | v0.13 current; MIT license; HF + sklearn-ecosystem maintained; supports sklearn `Pipeline`, `GridSearchCV`, and intends to support all sklearn estimators. `CalibratedClassifierCV` not explicitly enumerated as supported in docs but decomposes to supported primitives (`HistGradientBoostingClassifier` + isotonic regressor); **plan budgets a joblib-with-SHA256 fallback if CalibratedClassifierCV serialization proves non-trivial, but budget must go unused per PR-4 acceptance criteria**. Format is protocol-versioned — aigate pins one protocol per model version. sklearn 1.8 official docs explicitly recommend skops.io over pickle/joblib for untrusted-source load. |
| **NEW iter-2: skops.io load security model** | skops persistence docs 2026-04-22 | CONFIRMED | Whitelist-based: `skops.io.load(path, trusted=[...])` requires explicit allowed types; does NOT execute arbitrary code. Unknown type → `UntrustedTypesFoundException`. This is the structural defense; pre-SHA256 verification is defense-in-depth. |
| **NEW iter-2: Aikido Intel AGPL consumption interpretation** | `aikido.dev/blog/launching-aikido-malware---open-source-threat-feed` 2026-04-22 | CONFIRMED | Aikido's own launch post: "developers may freely use, modify, and distribute the vulnerability & malware feed." Public HTTPS endpoints `intel.aikido.dev/malware_predictions.json` (npm) + `intel.aikido.dev/malware_pypi.json` (PyPI). Consuming the data feed via HTTPS is analogous to consuming any open dataset; AGPL copyleft attaches to distribution of the Aikido *software* in modified form, not to HTTP data consumption. aigate does not bundle Aikido code or redistribute the feed. Architect §6 Check 2 concurs. |
| **NEW iter-2: Llama-Prompt-Guard-2 bypasses post-April 2025** | Trendyol medium (May 2025); arXiv:2504.11168; `llama.com/docs/.../prompt-guard` 2026-04-22 | CONFIRMED | Trendyol May 2025 documented score-0.137 on malicious prompts; multilingual + unicode-invisible bypasses; Meta declined bounty June 2025. Tokenization-fix present but not sufficient. Reinforces `classifier.as_signal_only: true` posture; never sole gate. |
| **NEW iter-2: skops vs joblib benchmark** | sklearn 1.8 model persistence docs + skops 0.13 docs 2026-04-22 | CONFIRMED-WITH-CAVEAT | No published head-to-head load-time benchmark found. sklearn official docs state joblib is faster for large numpy arrays via mmap; skops trades perf for security. **For aigate's 300-700KB model, load-time delta is negligible (<100ms either way).** skops.io supports zlib compression via `compresslevel` kwarg to `dump()`; expected compressed size parity with `joblib.gz`. **Budget pinned in PR-4 acceptance: skops.io load p95 < 50ms on 300-700KB model.** |
| NullifAI / pickle CVE-2025-1716 / JFrog 3 zero-days / NVIDIA NeMo CVE-2025-23304 | ReversingLabs, JFrog, NVD 2026-04-22 | CONFIRMED | Drives plan revision #1 (skops.io primary). |
| **NEW iter-3: skops CVE-2025-54412 / GHSA-m7f4-hrc6-fwg3** | [GitHub Advisory GHSA-m7f4-hrc6-fwg3](https://github.com/advisories/GHSA-m7f4-hrc6-fwg3) 2026-04-22 | CONFIRMED-FIX-PINNED | Advisory published 2025-07-25. CVSS 8.7. Affected: skops < 0.12.0. **Patched version: 0.12.0.** Fix commit SHA: `0aeca055509dfb48c1506870aabdd9e247adf603`. Vulnerability: `OperatorFuncNode` inconsistent trust validation — construction uses `__class__` only, validation uses `__module__`+`__class__` concatenation, so attacker forges `__module__` to appear harmless while triggering `operator.call` execution at load. POC: malicious `schema.json` with `"__class__": "call", "__module__": "sklearn.linear_model._stochastic_gradient.SGDRegressor"`. **aigate response:** pin `skops>=0.12.0,<0.20` in `[ml]` extra; ship `tests/security/test_skops_cve_2025_54412.py` reproducing POC against `trusted=[]` empty whitelist (which rejects `OperatorFuncNode` entirely regardless of forged keys); CI runs on every PR. Defense-in-depth: even if a future un-pin happens, the POC test fires immediately. HiddenLayer 2024-06 is a prior separate advisory also pre-0.12 and covered by the same pin. |
| **NEW iter-3: npm/pnpm/yarn/bun version-cooldown ecosystem precedent** | [pnpm supply-chain-security docs](https://pnpm.io/supply-chain-security), [Socket.dev pnpm 10.16 writeup](https://socket.dev/blog/pnpm-10-16-adds-new-setting-for-delayed-dependency-updates), [nesbitt.io 2026-03 cooldown post](https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down.html), [npm CLI FR issue #8570](https://github.com/npm/cli/issues/8570), [DEV "Lessons from Spring 2026 OSS Incidents"](https://dev.to/trknhr/lessons-from-the-spring-2026-oss-incidents-hardening-npm-pnpm-and-github-actions-against-1jnp), [christian-schneider.net cooldowns post](https://christian-schneider.net/blog/dependency-cooldowns-supply-chain-defense/) 2026-04-22 | CONFIRMED | **pnpm 10.16 `minimumReleaseAge`** shipped Sep 2025; **Yarn 4.10 `npmMinimalAgeGate`** shipped same month; **Bun 1.3 `minimumReleaseAge`** shipped Oct 2025; **npm 11.10.0 `min-release-age`** shipped Feb 2026. Common default values: **pnpm docs recommend 7 days as a reasonable floor** for most teams; enterprise deployments use 14 or 21 days. aigate's `min_version_age_days: 7` matches the ecosystem norm; can be tuned up (14/21) via config without code changes. pnpm also has `trustPolicy: no-downgrade` for provenance-drop detection — this is the precedent for aigate's `require_provenance_continuity: true`. |
| **NEW iter-3: PEP 740 / PyPI attestation adoption at 2026-Q1** | [PyPI blog 2024-11-14](https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/), [Trail of Bits "Are we PEP 740 yet?"](https://trailofbits.github.io/are-we-pep740-yet/), [Sigstore blog PyPI GA](https://blog.sigstore.dev/pypi-attestations-ga/), [PEP 740 text](https://peps.python.org/pep-0740/) 2026-04-22 | CONFIRMED-LIMITED-ADOPTION | PEP 740 GA Nov 2024. As of launch: ~5% of top-360 PyPI projects publish attestations; ~20K total attestations uploaded; **~two-thirds of top packages haven't cut a release since GA (so attestation status is undetermined for many top packages)**. Direction: Trusted Publishers + GitHub Actions produce attestations by default, so adoption grows with release cadence; estimated 15-25% of top-360 by 2026-Q1 (extrapolation, no published 2026 numbers). **Implication for aigate `require_provenance_continuity: true`:** the gate is a NO-OP for packages with no prior attestation (~75-85% of packages), so default-true does not cause widespread false positives. The gate ONLY fires when a prior version DID have attestation and the current version DOES NOT — this is exactly the provenance-drop class caught by pnpm's `trustPolicy`. Fallback doc in `docs/short-circuit-hard-gates.md`: "absence of attestation ≠ suspicious; only provenance CHANGE is suspicious." |

**Newer evidence (top 3 iter-1 findings retained):**

1. Llama Prompt-Guard-2 supersedes v1 (kept).
2. Aikido Intel feed outperforms OSSF on npm detection latency (iter-1 action confirmed in iter-2 PR-6).
3. ShieldNet (arXiv:2604.04426) supply-chain-specific guardrail (kept as ADR follow-up).

**Iter-2 new top finding:**

4. **Pickle-family model distribution is THE supply-chain attack vector of 2025.** Combined evidence: NullifAI (Feb 2025, ReversingLabs), JFrog 3 zero-days in picklescan (June 2025), CVE-2025-1716, NVIDIA NeMo CVE-2025-23304, Sonatype 4 more picklescan CVEs, arXiv:2508.19774 "Art of Hide and Seek" stealthy pickle poisoning (Aug 2025). **Plan response: ship in skops.io format primary; pre-SHA256 verification defense-in-depth; joblib fallback heavily gated.** This is the single largest iter-2 revision.

5. **DeepMind CaMeL (April 2025) supersedes Dual-LLM.** Dual-LLM secures control flow only; data flow remains exploitable via schema-compliant argument content. **Plan response: Dual-LLM default-OFF; PR-3 metadata-only reader carries most of the intended protection at half the cost; CaMeL listed as ADR follow-up (too heavyweight for aigate's static-analysis scope).**

**Iter-3 new top findings:**

6. **skops v0.12.0 is the minimum-safe version** (CVE-2025-54412 / GHSA-m7f4-hrc6-fwg3, fix commit `0aeca055509dfb48c1506870aabdd9e247adf603`, CVSS 8.7, published 2025-07-25). The vulnerability: `OperatorFuncNode` validation-vs-construction mismatch enables `operator.*` method execution via forged `__module__` keys. Our empty `skops_trusted_types: []` whitelist rejects `OperatorFuncNode` entirely — structural defense independent of the CVE fix — but we pin to the fix version anyway as defense-in-depth. CI test `tests/security/test_skops_cve_2025_54412.py` exercises POC on every PR.

7. **Version-level cooldown is the 2025-2026 industry default.** All four major JS package managers shipped cooldown in a 6-month window: pnpm 10.16 (Sep 2025), Yarn 4.10 (Sep 2025), Bun 1.3 (Oct 2025), npm 11.10.0 (Feb 2026). The **7-day default is the ecosystem norm** (enterprise deployments bump to 14/21). aigate adopts `min_version_age_days: 7` to match. This is the dominant 2025-2026 defense against chalk/debug/Axios-class maintainer takeover.

8. **PEP 740 attestation adoption is low (~5% top-360 at GA; ~15-25% estimated 2026-Q1) but growing.** Implication: `require_provenance_continuity: true` gate is correctly designed as "flag only on provenance CHANGE, not on provenance ABSENCE." This avoids false positives on the 75-85% of packages that never had attestations while still catching pnpm-`trustPolicy`-class provenance-drop attacks (Axios Mar 2026).

---

## Iteration 2 — Response to Architect

| # | Architect concern | Resolution in this iteration | Residual risk |
|---|---|---|---|
| 1 (CRITICAL) | Pickled joblib as ML artifact is 2025's biggest supply-chain attack vector (NullifAI, JFrog 3 CVEs, CVE-2025-1716, NVIDIA NeMo CVE-2025-23304) | **PR-4 ships `skops.io` as PRIMARY artifact format** (MIT, whitelist-based deserialization, no arbitrary code execution at load). Pre-deserialization SHA256 verification added as defense-in-depth. joblib available only as heavily-gated fallback (`allow_joblib_fallback: false` default, two-person-review to enable). `tests/unit/test_model_artifact_security.py` added with byte-flip + unknown-type rejection tests. Pre-mortem Scenario 4 added. ADR explicitly rejects pickled-joblib-as-primary with 2025 CVE citations. `MODEL_SHA256` constant in source (not in bundle). | **Residual:** wheel-itself integrity (compromised PyPI mirror shipping a malicious aigate wheel) cannot be prevented by aigate alone — documented; mitigated by recommending `pip install --require-hashes` + publishing wheel SHA256 in CHANGELOG + GitHub Release; full resolution requires sigstore/cosign on release wheel (ADR follow-up). **Status: fully resolved (for model-artifact class); mitigated-with-residual-risk (for wheel-itself class).** |
| 2 (HIGH) | Short-circuit gate has 3 enumerated bypass classes (maintainer-takeover on established pkg, adversarial feature crafting on non-monotonic features, clean-code exfil) | **PR-4 adds hard gates** (Architect §4a): `min_pkg_age_days: 14`, `min_num_releases: 5`, `maintainer_set_changed_within_30d == false`, `require_any_of_repo_or_homepage_resolves: true`. All must pass before short-circuit regardless of ML confidence. Feature #49 `maintainer_set_changed_within_30d` added. `tests/unit/test_short_circuit_hard_gates.py` verifies bypass-attempt fixtures. Documented in `docs/ml-short-circuit-threat-model.md`. | **Residual (explicitly documented):** maintainer-takeover on an established popular package >14 days old whose maintainer-set has been stable for 30+ days can still pass ALL hard gates. No static signal catches this class — it requires LLM on the diff. Mitigation: context-aware threshold (interactive defaults to 0.97 AND mode defaults to `shadow` — interactive users in default config are NEVER short-circuited); CI mode uses 0.90 but operators accept that tradeoff knowingly. **Status: mitigated-with-residual-risk; documented honestly.** |
| 3 (HIGH) | Dual-LLM economics don't work unless short-circuit >55%; Reversec 2025 / CaMeL shows it secures control flow only, not data flow; PR-3 provides ~80% at 50% cost | **PR-5 downgraded to default-OFF** with explicit cost-regression warning in `aigate doctor --cost-projection`. **PR-3 disagreement rule tightened** to `metadata_only.confidence ≥ 0.7 AND (full_code.conf - metadata_only.conf) < 0.3` (avoids routing legitimate new-maintainer packages to review). ADR alternatives section adds explicit "why we don't ship Dual-LLM ON by default" with Reversec / CaMeL citations. Schema-violation fallback changed from `metadata_only_only` to `route_needs_human_review`; rate-based escalation at >5%/1000 calls. | **Residual:** CaMeL-style capability-tracked execution is the literature's recommended successor; out of scope for v0.6 (too heavyweight for static analysis). ADR follow-up. **Status: fully resolved.** |
| 4 | Remote kill-switch endpoint default → `null` (opt-in) | **`telemetry.remote_kill_switch_url: null` default**; `kill_switch.remote_list_url: null` default. Opt-in only. Config comment documents rationale (Principle 1). `tests/e2e/test_airgapped_mode.py` asserts zero outbound fetches in fresh install. | None. **Status: fully resolved.** |
| 5 | `pydantic` → optional extra | **`pydantic>=2.6,<3` moves to `[project.optional-dependencies] ipi = [...]`**. When pydantic missing, schema validation falls back to `json.loads` + manual dict-validation. `BehaviorSummary` remains canonical schema shape; pydantic is the enforcement mechanism not the schema itself. | None. **Status: fully resolved.** |
| 6 | Temporal test split → `_stable` + `_adversarial` variants | **PR-4 training script emits both**: `temporal_test_stable` (pre-2025-07, promotion gate) and `temporal_test_adversarial` (post-2025-07, diagnostic only). `scripts/promote_ml.py` reads `_stable` only. `tests/observability/test_temporal_split_stable_vs_adversarial.py` verifies reporting. | None. **Status: fully resolved.** |
| 7 | Context-aware short-circuit thresholds (CI vs interactive) | **`short_circuit.confidence_threshold_ci: 0.90` + `short_circuit.confidence_threshold_interactive: 0.97`**. Detection: `CI=true` / `GITHUB_ACTIONS` env AND/OR `sys.stdout.isatty() == false`. `tests/unit/test_short_circuit_context_threshold.py` covers both. | **Minor residual:** unusual environments (non-CI scripts with no TTY) may misdetect; fallback picks the MORE conservative threshold (0.97) — safe default. **Status: fully resolved.** |
| 8 | Kill-switch multipliers 3.0× → 2.0× with absolute floor + high-profile unconditional floor | **Short-circuit: 1.5× + absolute floor 5 FN/24h. General: 2.0× + absolute floor 10 FN/24h. Unconditional floor: any confirmed FN on a >1000 downloads/week package trips immediately.** Configurable via `high_profile_fn_threshold_downloads_per_week`. `tests/unit/test_kill_switch_absolute_floor.py` verifies all three. | None. **Status: fully resolved.** |
| 9 | PR-1 must scan `PackageInfo.description` and `author` | **`scan_metadata_fields: true`** config + `scan_metadata_fields()` function in `ipi.py`. Emits `ipi_pattern(HIGH): ipi.<rule> in PackageInfo.description`. `tests/fixtures/ipi/metadata_injected/` covers 6 metadata-embedded IPI scenarios. | None. **Status: fully resolved.** |
| 10 | Schema violation → `NEEDS_HUMAN_REVIEW` + `quarantined_llm_schema_violation(HIGH)` signal, NOT `metadata_only_only` | **`on_schema_violation: route_needs_human_review`** default. Signal emitted at WARNING log level and surfaced in `ConsensusResult.ipi_signals`. `schema_violation_escalation_threshold: 0.05` auto-escalates to full-corpus routing when sustained. | None. **Status: fully resolved.** |
| 11 | PR-5 (ML) can parallelize behind shadow; doesn't need to wait for PR-3/PR-4 promotion | **PR-4 (promoted from iter-1 PR-5) now lands after PR-1 in Lane B, parallel with PR-2/PR-3 in Lane A.** Shadow-mode invariant ensures zero verdict impact until Stage-1 promotion. Sequencing rationale explicitly updated. Calendar reduces from ~10 days serial to ~8-9 days with 3 lanes; 4-week shadow clock remains the critical path. | None. **Status: fully resolved.** |
| 12 | External intel ingestion from Aikido Intel AGPL consume-only | **PR-6 `retroactive.aikido_enabled: true`** default; consumes `intel.aikido.dev/malware_predictions.json` + `malware_pypi.json` via HTTPS. `docs/threat-intel-sources.md` documents AGPL-data-consumption model with Aikido's own "freely use, modify, distribute" statement. aigate ships zero Aikido source code; wheel remains Apache-2.0. `tests/integration/test_retroactive_aikido_join.py` covers join logic. | **Minor residual:** AGPL copyleft interpretation for "data feed consumption" is legally novel territory; plan's interpretation aligns with Aikido's own stated position but is not a formal legal opinion. Mitigation: `docs/threat-intel-sources.md` includes the Aikido launch-post quote; `retroactive.agpl_notice_ack: true` config requires user acknowledgment. **Status: mitigated-with-residual-risk (legal, not technical).** |

---

## Handoff for Architect re-review (iter-2 — archived)

This iteration addresses all 12 Architect revisions: the CRITICAL pickle-RCE class is eliminated structurally via `skops.io` primary with SHA256-verified joblib fallback only as an explicit opt-in, both HIGH issues are resolved (short-circuit hard gates + context-aware thresholds close enumerated bypass Classes A/B/C except for the honestly-documented maintainer-takeover-on-established-package residual; Dual-LLM downgraded to default-OFF with PR-3 carrying the bulk of the protection and schema-violation now routing to `NEEDS_HUMAN_REVIEW` with rate-escalation), and the 9 remaining revisions are integrated with minimal sequencing impact (PR-5→PR-4 swap starts the shadow clock earlier, pydantic + joblib move to optional extras, Aikido Intel ingestion joins OSV in PR-6, temporal test split and kill-switch floors are all wired and tested). Please re-scrutinize (a) whether `skops.io`'s whitelist-based trust model combined with pre-deserialization SHA256 is sufficient for a supply-chain security tool's own artifact, (b) whether the honestly-documented residual in the maintainer-takeover class (Issue #2) is acceptable for v0.6 or whether it blocks short-circuit shipping entirely, and (c) whether the Aikido AGPL interpretation (Issue #12) needs explicit legal counsel before merging or is acceptable with the documented consumption-model reasoning.

---

## Iteration 3 — Response to Architect iter-2

| # | Architect iter-2 concern | Resolution in iter-3 | Residual risk |
|---|---|---|---|
| 1 (BLOCKER) | skops CVE-2025-54412 / GHSA-m7f4-hrc6-fwg3: `OperatorFuncNode` inconsistent trust validation enables `operator.*` execution; plan's `skops>=0.13,<0.20` pin includes vulnerable versions | **Pinned `skops>=0.12.0,<0.20`** in `[project.optional-dependencies] ml = [...]` (fix in 0.12.0; advisory published 2025-07-25; commit `0aeca055509dfb48c1506870aabdd9e247adf603`). Added `tests/security/test_skops_cve_2025_54412.py` reproducing POC against empty `skops_trusted_types: []` whitelist (rejects `OperatorFuncNode` structurally regardless of CVE-fix status). CI runs on every PR under dedicated `security-tests` job (not just release). External Verification Log updated with advisory URL + fix date + fix commit SHA. | None on the CVE itself (pinned + defense-in-depth POC test). **Residual:** if a future skops release introduces a NEW un-advised trust-boundary bug, we rely on empty whitelist as first line of defense and pre-load SHA256 as second. Mitigation: `skops_trusted_types: []` is the safe default; any future broadening requires two-person review. **Status: fully resolved for this CVE class.** |
| 1a (self-contradiction at iter-2 L83) | Plan claimed `MODEL_SHA256` lives "outside the wheel" but implementation puts it at `src/aigate/ml/__init__.py` (inside wheel) | **Clarified in iter-3 Pre-mortem Scenario 4 mitigations (c), (d), (e).** `MODEL_SHA256` is explicitly documented as a module constant **inside** the wheel. What inside-wheel SHA256 buys: defense-in-depth against **post-install filesystem tampering** of just the `.skops` file. What it does NOT buy: protection against whole-wheel replacement — an attacker controlling the wheel controls both the constant and the bytes. Whole-wheel integrity is addressed via PEP 740 Sigstore attestations on aigate's own release wheel (adopted at v0.6 via Trusted Publisher), published in CHANGELOG + signed GitHub Release, and user-recommended `pip install --require-hashes`. | **Residual (explicitly acknowledged):** users who install from compromised mirrors without `--require-hashes` and without verifying PyPI attestation cannot be protected by any inside-wheel check. This is structural to Python packaging and outside aigate's direct control. **Status: correctly-scoped; residual acknowledged and addressed via PEP 740 attestations as sigstore-level defense.** |
| 2 (BLOCKER / conditional) | Maintainer-takeover on established packages (chalk/debug Sep 2025 16-min compromise; Axios Mar 2026 100M weekly dl) bypasses iter-2 hard gates — package is >14 days old, has many releases, maintainer stable 30d+, but NEW malicious version publishes and short-circuit fires | **Added 2 new short-circuit hard gates** (scope: short-circuit SAFE ONLY; ML backend still runs and still votes in LLM consensus if gate blocks short-circuit): (a) **`min_version_age_days: 7`** — catches chalk-class (2h window), Axios-class (4-5h window), matches pnpm 10.16 `minimumReleaseAge` / Yarn 4.10 / Bun 1.3 / npm 11.10.0. (b) **`require_provenance_continuity: true`** — if any prior version had OIDC/PEP 740 attestation and current version drops it, gate blocks short-circuit (matches pnpm 10.21 `trustPolicy: no-downgrade`). `PackageInfo.prior_provenance` + `PackageInfo.version_published_at` added to registry resolvers. Scenario-5 added to pre-mortem walking through a day-8 dormant attack. Retroactive OSV+Aikido pipeline is the day-8+ catch-net (kill-switch unconditional floor trips on any FN >1000 dl/wk). `tests/unit/test_version_cooldown_gate.py` + updated `test_short_circuit_hard_gates.py` verify both gates. Class D (version-level takeover) shrinks from "any established package" to "dormant-for-7+-days AND (no prior provenance OR attacker controls publishing identity)". Per Sygnia Sep 2025: dominant pattern is exploit-within-hours, not dormant-for-weeks. | **Narrower residual (documented as Class-D-Tail in `docs/ml-short-circuit-threat-model.md`):** compromised version that sits >7 days AND either the package never had attestations OR attacker also controls the publishing identity. Mitigated (not prevented) by retroactive daily OSV+Aikido join. Full resolution requires sigstore attestation-transparency-log verification + behavioral-at-install sandboxing (both ADR follow-ups; aigate deliberately never executes package code per Class-D scope). **Status: mitigated-with-narrower-residual; dominant 2025-2026 attack pattern now caught.** |
| 3 (non-blocking) | Three lanes touching `consensus.py` — plan's "separate code regions, minor conflict risk" is optimistic | **Added explicit rebase gate** in Sequencing section: "If two PRs both touch `consensus.py._aggregate_votes` or any shared helper, the second PR to reach merge MUST rebase on main AFTER the first merges AND re-run the full integration test suite before merge." Codified in `.github/CODEOWNERS` + PR-template checklist + CI branch-protection rule. Lane B rebases after Lane A; Lane C rebases after whichever of A/B merges later. | None. **Status: fully resolved.** |
| 4 (non-blocking) | `retroactive.agpl_notice_ack: true` default is vestigial — user never sees anything to ack | **Flipped default to `false`** (opt-in). Rationale documented inline: default-true silently assumed consent which is weird UX + legally awkward. User must explicitly set `agpl_notice_ack: true` in `.aigate.yml` OR pass `--agpl-ack` flag. With default-false, `aigate check` prints a one-line note on first Aikido fetch pointing to `docs/threat-intel-sources.md` and skips the Aikido join (OSV still runs). Attribution and AGPL interpretation unchanged in `docs/threat-intel-sources.md`. | None. **Status: fully resolved.** |
| 5 (non-blocking) | Model-size assertion `≤ 1 MiB` to prevent silent joblib-fallback activation | **Added `tests/unit/test_model_size_budget.py`** with `assert os.path.getsize("src/aigate/ml/models/metadata-ml-v1.skops") <= 1_048_576`. Wired into CI on every PR and release tag. PR-4 acceptance criteria updated explicitly. | None. **Status: fully resolved.** |
| 6 (non-blocking) | Quantify CI-mode 0.07-confidence-gap exposure in threat model doc | **Added `docs/ml-short-circuit-threat-model.md` with quantitative section.** Order-of-magnitude prior: ~2-5% of short-circuit-eligible packages fall in `[0.90, 0.97)` confidence band (derived from calibrated-model literature: Brier ≤0.05 implies ~60% predictions above 0.95 and ~10-15% in [0.85, 0.95]; gap-band ~2-5% after subtracting the above-0.97 majority). Doc specifies: (a) narrow intersection with iter-3 hard-gate-passers who attack in this band; (b) CI operators can set `confidence_threshold_ci: 0.97` to close the gap at ~15-25% cost of reduced short-circuit rate; (c) re-measure from shadow data at Stage-1 promotion; prior→observation. | **Residual (non-technical):** the 2-5% figure is a literature-derived prior, not shadow-mode-measured. Will be replaced with observation at Stage-1. **Status: fully resolved as a scoping/documentation task.** |

**Summary iter-3:** Both blockers fully resolved (Blocker 1: skops pin + CI POC test; Blocker 2: two new version-level hard gates with ecosystem-aligned 7-day default + provenance-continuity). All four non-blocking items fully resolved. 6/6 iter-2 items addressed. Net plan delta: +250 LOC, +0.5 eng-days, PR-4 expands from 5 to 5.5 days; total shifts from ~5,570 LOC / 17 eng-days to ~5,820 LOC / 17.5 eng-days (calendar ~8.5-9.5 days with 3 lanes).

---

## Handoff for Architect iter-3 re-review

This iteration resolves both iter-2 blockers and all four non-blocking items: **Blocker 1** pins `skops>=0.12.0,<0.20` per CVE-2025-54412 advisory (fixed in 0.12.0, commit `0aeca055`, published 2025-07-25), adds `tests/security/test_skops_cve_2025_54412.py` running POC against empty whitelist on every PR, and clarifies the `MODEL_SHA256`-inside-the-wheel scoping with PEP 740 Sigstore attestation as the wheel-level integrity path; **Blocker 2** adds `min_version_age_days: 7` (matching the 2025-2026 ecosystem norm — pnpm/Yarn/Bun/npm all shipped 7-day cooldown in Sep 2025 to Feb 2026) plus `require_provenance_continuity: true` (pnpm 10.21 `trustPolicy`-class), documents that these gates apply to short-circuit SAFE only (ML still votes in LLM consensus on gate failure), adds Scenario-5 pre-mortem for the day-8 dormant-takeover residual, and quantifies Class-D shrinkage against Sygnia Sep 2025 compromise-velocity data. Please re-verify that (a) the skops pin and POC test sufficiently close the CVE-2025-54412 vector given that our empty whitelist is already a structural defense independent of version, (b) the iter-3 Class-D-Tail residual (dormant >7 days AND provenance-fully-compromised) is acceptable for v0.6 short-circuit promotion, and (c) the PEP 740 attestation adoption gap (~75-85% of packages without prior attestations → gate is no-op) is the right "false-positives-absent, false-negatives-present" tradeoff for this class of defense.
