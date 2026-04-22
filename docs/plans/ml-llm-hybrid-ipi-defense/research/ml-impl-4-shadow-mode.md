# Shadow Mode — Production Playbook for aigate

本文件給出 aigate ML backend 進入 shadow mode → 晉升 production vote → 最終 short-circuit LLM 的完整操作手冊。不是理論，是可直接貼上實作的規格。

---

## Log schema (JSON, ready to paste)

每一次 `aigate check` / `aigate scan` 會 append 一行到 `~/.aigate/shadow.jsonl`。固定 schema，`schema_version` 先鎖 `1`：

```json
{
  "schema_version": 1,
  "event_id": "01JBXK8W3R5Q9A7F2H4Z6P8T0V",
  "ts": "2026-04-22T14:03:17.482Z",
  "aigate_version": "0.5.2",
  "session_id": "a8f3-anonymized-install-id",
  "package": {
    "name": "requests",
    "version": "2.31.0",
    "ecosystem": "pypi",
    "resolved_url": "https://files.pythonhosted.org/...",
    "sha256": "d2ee..."
  },
  "prefilter": {
    "outcome": "passed",
    "signals": [
      "typosquat_distance(LOW): reqests->requests=1",
      "dangerous_pattern(MEDIUM): exec()@setup.py:12"
    ],
    "ran_ms": 34
  },
  "ml_shadow": {
    "verdict": "SAFE",
    "confidence": 0.91,
    "latency_ms": 28,
    "model_version": "metadata-clf-2026-04-18",
    "features": {
      "age_days": 4102, "maintainer_count": 74, "downloads_30d": 3.1e8,
      "has_install_hook": false, "url_entropy_max": 3.4,
      "typosquat_min_distance": 1, "file_count": 42
    },
    "top_feature_contribs": [
      {"feature": "downloads_30d", "shap": -0.42},
      {"feature": "age_days", "shap": -0.31},
      {"feature": "has_install_hook", "shap": -0.18}
    ]
  },
  "llm_backends": [
    {"name": "claude", "verdict": "SAFE", "confidence": 0.95, "latency_ms": 4120, "cost_usd": 0.018},
    {"name": "gemini", "verdict": "SAFE", "confidence": 0.88, "latency_ms": 3340, "cost_usd": 0.009}
  ],
  "final_verdict": {
    "decision": "SAFE",
    "exit_code": 0,
    "source": "llm_consensus",
    "rationale_hash": "sha256:7a3c..."
  },
  "input_sample": {
    "captured": false,
    "reason": "sampling_rate=0.01 not hit"
  },
  "env": {"os": "darwin-25.4", "py": "3.12.7", "ci": false}
}
```

重點欄位的設計理由：

- `event_id` 用 ULID，允許時間排序 + 分布式去重。
- `features` + `top_feature_contribs` 保存 ML 輸入與 SHAP 前三名，日後做 error analysis 必備；feature dict 要固定鍵序才能 diff。
- `rationale_hash` 存摘要雜湊，完整 LLM 理由留在 side file（太大），避免 jsonl 膨脹。
- `input_sample.captured` 採 1% 隨機取樣，命中時把 resolver 下載的 source tarball SHA + 檔案清單一併 dump 到 `~/.aigate/samples/`，供重現。
- `session_id` 是安裝期產生的 anonymized UUID，用於 sessionise 但不識別使用者（類似 Snyk 的 anonymous analytics ID）。

---

## 儲存策略（隱私 / 本地 / 遠端 / rotation）

**本地 first**。aigate 是 dev CLI，預設只寫 `~/.aigate/shadow.jsonl`；以 `logging.handlers.RotatingFileHandler` 按 50 MB × 5 檔輪替，約涵蓋 200k 次 scan。

**遠端 opt-in**。使用者在 `.aigate.yml` 顯式啟用：

```yaml
telemetry:
  enabled: true            # 預設 false
  endpoint: https://telemetry.aigate.dev/v1/shadow
  include_features: true   # 是否上送 ml.features
  sample_rate: 1.0
```

隱私界線比照業界：
- Socket Firewall Free 收集「blocked/permitted package name、namespace、version、latency、machine-id」，**預設 always-on** 但 Enterprise 可關；我們採更嚴格：**預設 off**。
- Snyk CLI telemetry「不含 PII、只走自家 Analytics、不經第三方」。aigate 比照此原則：不送 cwd、git remote、env vars、檔案路徑；`package.name/version/ecosystem` 是 public registry 資訊可送。
- Ecosystem 內 lockfile scan 若包含私有 registry 名稱（`@mycompany/*`），telemetry 預設 hash scope name 再送，原始值留在本地。

CI 環境自動停 telemetry（偵測 `CI=true` / `GITHUB_ACTIONS`），避免放大倍數且通常是自動跑。

---

## 評估指標儀表板（what to compute）

假設 logs 已 load 成 pandas DataFrame `df`（flatten nested fields），以下為各指標的計算骨架。

| 指標 | 計算 | 晉升門檻建議 |
|---|---|---|
| **Agreement rate** | `(df.ml_verdict == df.llm_verdict).mean()` | ≥ 95% 才 promote 到 vote |
| **FP candidate rate** | `((df.ml_verdict=='MALICIOUS') & (df.llm_verdict=='SAFE')).mean()` | < 0.5% |
| **FN candidate rate** | `((df.ml_verdict=='SAFE') & (df.llm_verdict=='MALICIOUS')).mean()` | < 0.1%（更嚴） |
| **Calibration (Brier)** | bin by `ml_confidence` 10 buckets；each bucket 的實際 malicious 比例應 ≈ bucket 中心 | max \|bin_error\| < 0.08 |
| **Latency p50/p95/p99** | `df.ml_latency_ms.quantile([0.5,0.95,0.99])` | p95 < 150 ms（LLM ~ 3-5 s） |
| **Cost savings (hypothetical short-circuit)** | `df[df.ml_conf > 0.9].llm_cost_sum / df.llm_cost_sum` | > 60% 才值得 |
| **Ground-truth precision** | 從 disagreements 抽 N=100 人工標記 → `TP/(TP+FP)` | ≥ 0.9 |

Pandas sketch for calibration reliability diagram：

```python
df["bucket"] = pd.cut(df.ml_confidence, bins=10, labels=False)
rel = df.groupby(["bucket", "ml_verdict"]).agg(
    n=("event_id","count"),
    mean_conf=("ml_confidence","mean"),
    actual_malicious=("gold_label","mean"),   # 由人工標記 + OSV 回填
).reset_index()
rel["gap"] = (rel.mean_conf - rel.actual_malicious).abs()
```

SQL 版 agreement rate（若改灌 DuckDB）：

```sql
SELECT
  date_trunc('day', ts) AS day,
  SUM(CASE WHEN ml_verdict = final_verdict THEN 1 ELSE 0 END)::float / COUNT(*) AS agreement,
  SUM(CASE WHEN ml_verdict='MALICIOUS' AND final_verdict='SAFE' THEN 1 ELSE 0 END) AS fp_cand,
  SUM(CASE WHEN ml_verdict='SAFE' AND final_verdict='MALICIOUS' THEN 1 ELSE 0 END) AS fn_cand,
  quantile_cont(ml_latency_ms, 0.95) AS p95_ml_ms
FROM shadow_log WHERE ts > now() - INTERVAL 7 DAY
GROUP BY day ORDER BY day;
```

**Disagreement triage loop**：每週 export 所有 disagreements → 以 confidence × frequency 排序 → OSS 研究員人工標 100 筆，寫回 `gold.jsonl`；這份 gold set 也是未來 regression test 的 seed。

---

## Promotion criteria — 3 個業界範例

1. **Uber Michelangelo**（2025 H1）：shadow testing 已覆蓋 **75%+ 的 critical online use cases**，計畫 2025 H2 達 100%。採 intermediate/advanced tier；rollout 從 small traffic slice 起、auto-rollback 有閾值但 Uber 未公開具體數字。關鍵訊息：shadow 是 **default**、不是選配。
2. **GitHub Copilot Secret Scanning**（generic passwords GA, 2024-10-21）：先 few-shot prompt GPT-3.5-Turbo 蒐集 signal，再用 GPT-4 生成 test cases 擴充 **precision/recall** 評估集；GA 時已部署於 **350,000+ repos**；內建防護：每 push 最多偵測 100 passwords、test/mock/spec 檔跳過、單檔 5 個 FP 後就停發新 alert。FP 控制優先於 recall。
3. **Honeycomb Query Assistant**：上線時公布 LLM call 2-15 秒延遲是常態；OpenAI 月費約 **$30**、Redis $100/node，透過 rate limit per user per day 防濫用。關鍵學習：**對 LLM 誠實設 user expectation 比追求「看起來完美」更重要**。
4. **PayPal Quokka shadow platform**：model 晉升門檻以「P99 execution time」「data-load time」「model score distribution」「與 ATB 的相關性」為 gate；shadow duration 可由 data scientist 在 self-service UI **以行事曆方式預約可變時長**，model CI/CD + shadow 上線後開發部署時間降 **80%**。
5. **Datadog AI Guard**（2026 Preview）：主打 "**monitor-only mode**" 作為 rollout 起點 —「begin in monitor-only mode to observe agent behavior, tune policies, and review false positives」；評估結果以 trace 形式併入 APM，在熟悉的 observability pipe 內審核。

---

## aigate 建議的 promotion thresholds

三階段 gate，每階段要**全部**通過才能往下走：

**Stage 1: shadow-only → vote-participant**
- 累積樣本 ≥ 50,000 次 scan
- shadow duration ≥ 4 週（涵蓋一次週期性 registry 異動）
- agreement rate vs LLM consensus ≥ 95%
- 人工標記 100 個 disagreement 後，ML precision ≥ 0.9、recall ≥ 0.85
- calibration max bin error < 0.08
- latency p95 < 150 ms

**Stage 2: vote-participant → short-circuit high-confidence SAFE**
- Stage 1 條件持續 2 週不退化
- 在 ML confidence ≥ 0.95 桶中，**過去 90 天 0 個 confirmed malicious**（回填 OSV 驗證）
- 估算 cost saving ≥ 60%
- 使用者可見 FP rate 預估 < 0.5%（從 Stage 1 的 FP candidate rate × short-circuit 流量估）

**Stage 3: short-circuit MALICIOUS 亦生效**
- 在 ML confidence ≥ 0.98 桶中，precision ≥ 0.99
- OSS 外部審核 50 個 ML-only MALICIOUS 判定且 ≥ 49 人同意

保守採「**先只 short-circuit SAFE，不 short-circuit MALICIOUS**」—— 參照 Copilot Secret Scanning 的 FP 優先思維，錯殺比錯放代價更大。

---

## Kill switch 設計

三層機制，由快到慢：

1. **Runtime config flip**（秒級）：`.aigate.yml` 改 `ml.mode: shadow` 立即生效；`aigate` binary 每次啟動 reload，不需 re-install。
2. **Remote kill list**（分鐘級）：`~/.aigate/cache/kill.json` 每 24 小時 refresh；內容如 `{"disable_ml_version": ["metadata-clf-2026-04-18"]}`。ML backend 載入時檢查自身 version，命中就 degrade 回 shadow。
3. **Package downgrade**（小時級）：`pip install aigate==0.5.1` 回前一版。

**自動 rollback 觸發條件**（client 端本地偵測，無需連線 server）：
- 1 小時滑動視窗內 FP candidate rate > baseline × 3 且樣本 ≥ 200 → 自動降級成 shadow 並印 warning
- ML latency p95 > 500 ms 連續 15 分鐘 → 同上
- Prefilter 拒絕 + ML 卻判 SAFE 的比例飆升（可能是 model 被污染或 feature drift）

所有降級事件寫入 `~/.aigate/events.jsonl`，如 telemetry opt-in 則上送。

---

## Retroactive 驗證 pipeline

OSV / GHSA / OSSF `malicious-packages` repo 是事後 ground truth 金礦。pipeline：

1. **Daily cron**：`curl https://osv-vulnerabilities.storage.googleapis.com/all.zip` 下載 OSV dump（官方支援全量 download）。
2. **Filter**：只取 `PyPI` / `npm` ecosystem，且 `database_specific.type == "MALICIOUS"` 或來源是 ossf/malicious-packages。
3. **Join back**：對 `shadow.jsonl` 依 `(ecosystem, name, version)` 左連接；凡今日 OSV 新增的 malicious 版本，回填 `gold_label = "MALICIOUS"`、`gold_source = "OSV-MAL-..."`、`confirmed_at`。
4. **Score**：計算 aigate 當時的 verdict 是否正確，產出滾動 precision/recall/FN@detection-time 報表。
5. **Lead time 指標**：`confirmed_at - aigate.ts` 的分布；若 aigate 領先 OSV 平均 7+ 天，這本身就是 positioning story。
6. **Gold set 自動擴增**：所有 retroactively 確認的 malicious 進 `gold.jsonl`，作為下一輪 ML 訓練與 regression test 的 ground truth。

這條 pipeline 不需要 opt-in，因為它完全跑在 aigate 後台（或 CI），消費的是已授權的 shadow log。

---

## 是否對使用者暴露 shadow mode

**建議暴露，但僅限唯讀 preview**。理由：

- 開發者族群會想知道「下一版 aigate 的判斷會跟這版一樣嗎？」
- 提供 `aigate check pkg --show-shadow` 印出 ML 子判決，但 exit code 仍由現行 consensus 決定；這對 early adopter 產生 organic feedback。
- 仿 Datadog AI Guard「monitor-only mode」哲學：讓使用者自己先「觀察」新能力，不要在他們還沒信任前就改變行為。

**不建議**讓使用者用 `--ml-only` 做決策 — 那相當於把未 battle-tested 的 model 直接推到 production，違反 shadow mode 本意。真要給也只能藏在 `aigate debug ml-predict` 子指令下，不走正常 scan 流程。

---

## aigate 檔案改動清單

- `src/aigate/shadow_log.py`（新）：定義 `ShadowEvent` dataclass、`append_event()`、rotation、1% sample 邏輯。
- `src/aigate/telemetry.py`（新）：opt-in remote uploader、scope-name hashing、CI detection。
- `src/aigate/consensus.py`（改）：parallel 跑 ML backend + LLM backends，但 `mode=shadow` 時忽略 ML 在加權投票中的貢獻；發 event 給 `shadow_log`。
- `src/aigate/backends/ml_metadata.py`（新，本 series 他檔描述）：產出 `features` + `top_feature_contribs`。
- `src/aigate/kill_switch.py`（新）：remote kill list fetch、local circuit breaker（FP rate / latency triggers）。
- `src/aigate/retroactive.py`（新）：OSV daily pull + join script；也可移到 `scripts/` 並用 cron。
- `.aigate.yml`（範例更新）：新增 `ml:` 與 `telemetry:` sections。
- `docs/shadow-mode.md`（新）：使用者面向文件（opt-in 流程、隱私界線、如何 `--show-shadow`）。
- `tests/test_shadow_log.py`、`tests/test_retroactive.py`、`tests/test_kill_switch.py`（新）：schema 穩定性、rotation、OSV 匹配。
- `tests/fixtures/osv_sample.json`（新）：合成 OSV 回放資料。

---

## Sources

- [Uber — Raising the Bar on ML Model Deployment Safety](https://www.uber.com/blog/raising-the-bar-on-ml-model-deployment-safety/)
- [PayPal — Machine Learning Model CI/CD and Shadow Platform (Quokka)](https://medium.com/paypal-tech/machine-learning-model-ci-cd-and-shadow-platform-8c4f44998c78)
- [GitHub Docs — Responsible detection of generic secrets with Copilot secret scanning](https://docs.github.com/en/code-security/responsible-use/responsible-ai-generic-secrets)
- [GitHub Changelog — Copilot secret scanning for generic passwords is GA](https://github.blog/changelog/2024-10-21-copilot-secret-scanning-for-generic-passwords-is-generally-available/)
- [Datadog — Protect agentic AI applications with Datadog AI Guard](https://www.datadoghq.com/blog/ai-guard/)
- [Honeycomb — All the Hard Stuff Nobody Talks About when Building Products with LLMs](https://www.honeycomb.io/blog/hard-stuff-nobody-talks-about-llm)
- [ZenML LLMOps DB — Honeycomb Query Assistant case study](https://www.zenml.io/llmops-database/the-hidden-complexities-of-building-production-llm-features-lessons-from-honeycomb-s-query-assistant)
- [Snyk Docs — IDE and CLI usage telemetry](https://docs.snyk.io/developer-tools/snyk-cli-plugins-and-extensions/snyk-language-server/ide-and-cli-usage-telemetry)
- [Socket — Socket Firewall Free docs (telemetry)](https://docs.socket.dev/docs/socket-firewall-free)
- [OSV.dev — API docs](https://github.com/google/osv.dev/blob/master/docs/api/index.md)
- [OSSF — malicious-packages repository](https://github.com/ossf/malicious-packages)
- [Stripe — A primer on machine learning for fraud detection](https://stripe.com/guides/primer-on-machine-learning-for-fraud-protection)
- [Stripe — Using AI to create dynamic, risk-based Radar rules](https://stripe.com/blog/using-ai-dynamic-radar-rules)
- [DYCORA — Deployment and Shadow Mode Testing: Validating a New Model on Live Traffic](https://www.dycora.com/deployment-and-shadow-mode-testing-validating-a-new-model-on-live-traffic-without-user-impact/)
- [Wallaroo — AI Production Experiments: A/B Testing and Shadow Deployments](https://wallaroo.ai/ai-production-experiments-the-art-of-a-b-testing-and-shadow-deployments/)
