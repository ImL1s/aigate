# OSS Pluggable-Backend Architectures (findings)

研究目標：為 aigate 增加 ML classifier backend（快、本地）並在高信心時 short-circuit LLM backend，從 GuardDog、OSSF Package Analysis、LiteLLM Router、capa、Grype、Trivy 的實際程式碼中學習 pluggable-backend 架構。

## 三個最值得模仿的 pattern

**1. GuardDog 的「heterogeneous detector, homogeneous result envelope」**
- `guarddog/analyzer/analyzer.py` 內 `Analyzer.__init__` 同時持有三種 ruleset：`metadata_ruleset`（Python heuristic classes）、`semgrep_ruleset`（SAST rules）、`yara_ruleset`。三者 return type 完全不同（metadata detector 回 `tuple[bool, Optional[str]]`；semgrep 回 list of findings dict；yara 類似），但都被 normalize 進同一個 envelope：`{"issues": int, "errors": dict, "results": dict, "path": str}`。
- Aggregation 是單純 dict merge：`results = metadata_results["results"] | sourcecode_results["results"]`，`issues = a+b`。優點：新增 detector type 不需要改 aggregator，只要 emit 正確的 envelope。
- `metadata/detector.py` 的 ABC 只要求 `detect(package_info, path, name, version) -> tuple[bool, Optional[str]]`，class attribute `RULE_NAME` 當作 registration key。這對 aigate 的啟發：**ML backend 不必回 verdict+confidence+reasoning+risk_signals 四元組，回「這個 signal 有沒有中 + 解釋字串」即可，normalize 層做加權**。

**2. LiteLLM Router 的「alias + cooldown short-circuit」**
- 多個 deployment 共用一個 `model_name`（alias），router 根據策略選一個。`router_settings` 裡 `allowed_fails: 3` + `cooldown_time: 30` 實作 short-circuit：連續失敗後該 backend 被放進 cooldown cache 自動跳過。
- 關鍵：short-circuit 決策住在 router（caller 層），不住在 backend。Backend 永遠只負責「被叫到就盡力回答」；跳不跳過它由外層根據 cache/歷史決定。對 aigate 同理：**ML 高信心時跳過 LLM 的邏輯應該住在 `consensus.py`，不是 backend 內部**。
- Config 形狀（YAML）示範了 per-deployment 的 `rpm`/`tpm`/`weight`/`order`，每個 model 實例是「平等公民」，fallbacks 是另一段 list。

**3. capa 的「early exit on file-scope capabilities」**
- `capa.main.find_file_capabilities()` 在昂貴的 function/basic-block 分析之前，先跑 file-scope rules。若 file 被標記為 packed/encrypted，整個後續 pipeline 可提前短路（甚至直接 bail）。這是 aigate ML short-circuit 最直接的範本：**pre-filter → ML → LLM 三段 cascade，每段可以 finalize verdict 並阻止下一段執行**。

## YAML config schema 比較

**LiteLLM（router-centric，model list 扁平）**
```yaml
model_list:
  - model_name: gpt-3.5-turbo
    litellm_params: { model: azure/chatgpt-v-2, api_key: ..., rpm: 900 }
  - model_name: gpt-3.5-turbo
    litellm_params: { model: gpt-3.5-turbo, api_key: ... }
router_settings: { routing_strategy: simple-shuffle, allowed_fails: 3, cooldown_time: 30 }
```

**GuardDog（rule-centric，type-grouped）**
```yaml
# guarddog 實際是 CLI flags + rules/ 目錄自動發現 + per-rule YAML metadata
# 每個 rule 的啟用/停用用 --exclude-rules / --rules CLI 控制
rules:
  - id: shady-links
    type: semgrep
    severity: warning
```

**Trivy（scanner-category，capability flags）**
```yaml
scan:
  scanners: [vuln, secret, misconfig, license]
  severity: [HIGH, CRITICAL]
  skip-dirs: [node_modules]
```
Scanner 是 capability flag（開/關），而非 instance list。適合「每種 analyzer 只有一個 canonical 實作」的專案，不適合 aigate（aigate 可能同時跑多個 LLM backend）。

**aigate 當前（model-instance，接近 LiteLLM）**
```yaml
models:
  - name: claude-main
    backend: claude
    enabled: true
    weight: 1.0
```
這個形狀是對的，只需要擴充讓 ML backend 自然融入。

## Heterogeneous result normalization

三種常見做法：

1. **Dict-merge envelope（GuardDog）**：每個 detector emit `{rule_name: finding_or_none}`，aggregator 只做 `|` 合併。verdict 由 issue count + severity weight 推導。缺點：confidence 概念不存在，只有「中/不中」。
2. **Capability tuple（capa）**：每個 rule match 是 `(rule, address, features_used)`，最終 verdict 是 capability set。沒有 probabilistic aggregation，純布林。
3. **Weighted vote（aigate 現況 / 類 ensemble ML）**：每個 backend 回 `(verdict, confidence, reasoning, signals)`，加權投票 + disagreement 檢測。**這是 aigate 現在的做法，也是三者中最適合異質 (ML+LLM) 混合的**——ML 可以自然 emit `confidence=0.95`，LLM 也能；GuardDog 式的布林 envelope 會丟掉 ML 最有價值的資訊。

**混合方案（推薦 aigate 用）**：保留 `ModelResult` 作為統一結果型別，但讓 backend 可選擇性填 `reasoning`（LLM 填、ML 可留空或填 feature importance）。用 optional field + backend kind discriminator 區別處理。

## Short-circuit / cascading 實作

**LiteLLM cooldown（reactive）**：backend 出錯 → caller 記在 `failed_calls` cache → 下次 route 時跳過。決策在 router，資料在 cache。

**capa file-scope early exit（proactive）**：
```python
# capa/main.py 簡化
file_caps = find_file_capabilities(rules, extractor)
if any(c.is_disqualifying for c in file_caps):  # e.g. packed
    return early_verdict(file_caps)
# 否則才跑 expensive function-level
```
決策在 pipeline orchestrator，條件寫死在規則的 `scope: file` + 特殊 meta。

**GuardDog 不做 short-circuit**：所有 detector 平行跑到底，結果 merge。對他們合理（detector 都便宜）；對 aigate 不適用（LLM 昂貴）。

**推薦給 aigate（混 capa 的 early-exit + LiteLLM 的外層決策）**：在 `run_consensus` 分兩 phase：
```python
# phase 1: 跑所有 kind="fast" 的 backend（ML、heuristic）
fast_results = await asyncio.gather(*fast_tasks)
if _can_short_circuit(fast_results, config.short_circuit):
    return _aggregate_votes(fast_results, ...)
# phase 2: 跑 kind="slow" (LLM)
slow_results = await asyncio.gather(*slow_tasks)
return _aggregate_votes(fast_results + slow_results, ...)
```
Short-circuit 條件是 **config 層 threshold**，不是 per-backend property——因為同一個 ML model 在「高召回場景」和「高精準場景」該有不同門檻。

## 對 aigate 的具體建議

針對 `src/aigate/backends/base.py:116` 的 `AIBackend` ABC、`src/aigate/consensus.py:27` 的 `BACKEND_MAP`、`src/aigate/consensus.py:47` 的 `run_consensus`：

**Keep（不要動）**
- `BACKEND_MAP` dict：6 個 backend 規模下，entry-points 是過度設計。LiteLLM / Grype (`NewDefaultMatchers`) 都用 hardcoded registry，只有 plugin-first 專案（Trivy v2、Semgrep rules）才用 entry-points。
- `ModelResult` 作為 unified result type：比起 GuardDog 的 dict envelope，這給 ML backend 天然支援 `confidence` 欄位。
- Weighted vote 邏輯：比 GuardDog 的 issue-count 更適合異質混合。

**Refactor（小改）**
1. `AIBackend` 增加 `kind: Literal["fast", "slow"] = "slow"` class attribute。`ClassifierBackend` 設 `"fast"`，其他設 `"slow"`。不改現有 subclass signature。
2. `analyze()` signature 在 ABC 上保持不變，但加一個 optional `analyze_package()` override 路徑讓 ML backend 跳過 prompt 建構——ML 不需要 prompt string，需要的是 `PackageInfo + risk_signals + source_code` 原始結構。現在 `base.py` 的 `analyze_package()` 已經以這些結構當入口，只是內部一定會生 prompt，讓 subclass 可以 override 整個 `analyze_package()` 就好。
3. `run_consensus` 依 `backend.kind` 分兩階段跑，中間插 short-circuit check。

**Config 擴充**
```yaml
models:
  - name: ml-classifier
    backend: sklearn_classifier   # 新
    kind: fast                    # 新，非必填，override class default
    enabled: true
    weight: 0.8
    options:
      model_path: ~/.aigate/models/pypi_rf.pkl
      feature_set: v1
  - name: claude-main
    backend: claude
    weight: 1.0

short_circuit:                    # 新頂層 section
  enabled: true
  require_kind: fast              # 只有 fast backend 能觸發
  malicious_confidence: 0.95      # ML 說 MALICIOUS @ ≥0.95 → 跳過 LLM
  safe_confidence: 0.90           # ML 說 SAFE @ ≥0.90 → 跳過 LLM
  require_agreement: true         # 多個 fast backend 需同意（避免單點誤判）
```

**「short_circuit 放哪」的理由**：global section 而非 per-backend。per-backend（backend 自己說「我信心 0.95 請跳過別人」）違反 LiteLLM 學到的原則——backend 應該是 dumb 的。per-verdict（每個 verdict 不同門檻）是合理細分，但放 global 更清楚。

**ModelResult 不用改**，但 `model_name` 欄位要能表達 backend kind（目前只是字串）——可以在 aggregator 透過 `model_configs` 反查，不必改 dataclass。

**Proof-of-concept sketch（pseudocode，不 commit）**
```python
# consensus.py (new)
async def run_consensus(...):
    fast = [(mc, b) for mc, b in backends if b.kind == "fast"]
    slow = [(mc, b) for mc, b in backends if b.kind == "slow"]

    fast_results = await _run_phase(fast, package, ...)
    if config.short_circuit.enabled:
        decision = _try_short_circuit(fast_results, config.short_circuit)
        if decision is not None:
            return decision  # 含 summary="short-circuited by ml-classifier"

    slow_results = await _run_phase(slow, package, ...)
    return _aggregate_votes(fast_results + slow_results, config, enabled_models)

def _try_short_circuit(results, sc_config) -> ConsensusResult | None:
    valid = [r for r in results if r.verdict != Verdict.ERROR]
    if not valid: return None
    if sc_config.require_agreement and len({r.verdict for r in valid}) > 1:
        return None
    r = max(valid, key=lambda x: x.confidence)
    if r.verdict == Verdict.MALICIOUS and r.confidence >= sc_config.malicious_confidence:
        return ConsensusResult(final_verdict=r.verdict, confidence=r.confidence, ...)
    if r.verdict == Verdict.SAFE and r.confidence >= sc_config.safe_confidence:
        return ConsensusResult(...)
    return None
```

## Anti-patterns 看到的壞設計

- **GuardDog 的 dict-based result envelope**：字串 key 散落各處（`"issues"`, `"results"`, `"errors"`, `"path"`），新增 field 沒有 type check。aigate 的 dataclass `ModelResult` 好得多，不要退化。
- **Trivy 把 scanner 當 capability flag**：`scanners: [vuln, secret]` 這種 enum 無法表達「同類型但兩個不同 model」。aigate 需要「同時跑兩個不同 Claude model」的能力，model-instance list 形狀正確。
- **Backend 內部做 routing 決策**：LiteLLM 明顯避免這樣，backend 不知道別人存在。aigate 不要讓 ML backend 內部呼叫 `skip_llm()`。
- **Entry-points plugin system for 6 backends**：Grype 的 `NewDefaultMatchers` 15 個 matcher 都還是 hardcoded slice。過早的動態載入只會增加 debug 成本。
- **LangChain-style 深度抽象層**（Runnable → Chain → Agent）：對 aigate 這種「跑 N 個 model 投票」過度工程，目前的 `async def analyze_package` 一個方法夠了。
- **GuardDog semgrep ruleset 用 class attribute `RULE_NAME = ""` 當 registration key**：空字串預設值容易被遺漏，subclass 忘記設就被以空字串註冊。如果 aigate 未來走 attribute-based registration，改用 `abstractproperty` 或在 metaclass 檢查。

## Sources

- DataDog/guarddog — `guarddog/analyzer/analyzer.py`、`guarddog/analyzer/metadata/detector.py`、`guarddog/scanners/scanner.py`（main branch, 2026-04 fetch）
- ossf/package-analysis — README（main branch）：dynamic-analysis-only pipeline，signal combination via BigQuery loader
- BerriAI/litellm — `litellm/router.py`、docs.litellm.ai/docs/routing：model_list + router_settings + cooldown cache
- mandiant/capa — `capa/main.py`（master）：`find_file_capabilities` early-exit pattern
- anchore/grype — `grype/matcher/matchers.go`：`NewDefaultMatchers` hardcoded factory
- aquasecurity/trivy — `pkg/scanner/` 樹狀結構（確切檔案路徑 404，README 描述 scanner-as-capability 模型）
- aigate 本地 code：`src/aigate/backends/base.py:116`（AIBackend ABC）、`src/aigate/consensus.py:27`（BACKEND_MAP）、`src/aigate/consensus.py:144`（_aggregate_votes 加權投票）
