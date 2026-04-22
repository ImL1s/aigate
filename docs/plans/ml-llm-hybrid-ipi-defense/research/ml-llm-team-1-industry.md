# Industry Tools — ML+LLM Hybrid Architectures (findings)

研究日期：2026-04-22。本報告聚焦於 aigate 以外、產業已落地的 ML+LLM 混合架構實作細節，並刻意避開 MeMPtec / MalGuard / GuardDog 核心行為 / OSSF repo / Cerebro / Socket.dev（概述層級）/ Phylum（概述層級）等先前已覆蓋的主題。

---

## 最有參考價值的三個案例

### 1. Datadog BewAIre — LLM-only with recursive chunking (engineering blog, production case)

Datadog 的 `BewAIre` 是目前公開資料中**最完整揭露營運數據的** LLM-based 偵測系統，用於 PR 層級的 malicious code detection，但架構可直接 transplant 到 package scanning。

- **Pipeline**：Ingestion → Preprocessing → Inference → Signals，**無 static pre-filter**（直接全量丟 LLM）。
- **Chunking strategy**：遞迴切割 diff，以 file boundary → newline → midpoint fallback 順序切，在每個 chunk 獨立 inference 後用 "most severe verdict wins" 合併。
- **Volume**：~10,000 PRs/週，產品化前先 shadow mode 跑數個月。
- **False positive rate**：**0.03%**（公開數據）。
- **Accuracy**：>99.3%，100% detection rate on real npm compromise tests。
- **模型**：刻意不揭露（"tested against new SOTA LLMs"）。
- **Cost/latency**：未揭露具體數字，僅提及「timeouts 設得很高」、「chunks 設深度上限避免無限遞迴」。
- **關鍵工程見解**："carefully framing context, exclusions, and known pitfalls drastically improved reliability. We saw double-digit accuracy gains." — 整個系統的 FP 降低主要靠 prompt engineering + 把 known FP 放進 system instructions + exclude demo environment patterns，而**不是**靠第二個 model。

### 2. "Shifting the Lens" / SocketAI paper — two-stage static→LLM cascade (可複現的 ablation 數據)

這篇論文是唯一公開**完整 cost ablation**的 hybrid 架構：

- **Stage 1 (static)**：CodeQL 跑 39 條 custom queries 作為 pre-screener。
- **Stage 2 (LLM)**：只對 CodeQL flagged 的檔案跑 GPT-3/4，用 Iterative Self-Refinement + Zero-Shot CoT。
- **Filter reduction**：18,754 files → 4,146 files，**77.9% 減量**。
- **Cost numbers (實測，非估算)**：
  - GPT-3 full scan: $125.65 → filtered: $49.13 (**-60.9%**)
  - GPT-4 full scan: $2,013.84 → filtered: $482.46 (**-76.1%**)
- **Quality preserved**：GPT-4 達 Precision 0.99 / Recall 0.95 / F1 0.97（vs CodeQL baseline 0.75 / 0.97 / 0.85）。Pre-filter 不損 F1，只犧牲 recall 極小部分。

### 3. SafeDep vesafe — three-tier hybrid (YARA → static → LLM)

SafeDep 的 `malysis` engine 是**產品化的三段式 hybrid**：

- **Tier 1**：YARA Forge rules 偵測 known patterns。
- **Tier 2**：Static code analysis 標記操作類型（`network:connect`, `fs:write`, `process:exec`）。
- **Tier 3**：LLM 對 tier 1/2 標記的 basic blocks 做語意判斷。
- **Dataset evaluation**：Datadog Malicious Packages Dataset → 96.2% detection，其中 **71.9% 為 multi-signal high confidence**（即 YARA + static + LLM 三者至少兩個同意）。
- **Lesson**：multi-signal corroboration 是 confidence 主要來源；單一 LLM verdict 在該系統 classified as low confidence。

---

## Hybrid pattern 分類（實際產業實作觀察到的模式）

| Pattern | 代表作 | 特徵 |
|---|---|---|
| **Two-stage cascade (cheap→expensive)** | SocketAI paper, Socket.dev 內部 | Static rules 先 gate，LLM 只處理 flagged subset。主要動機：cost。 |
| **Parallel ensemble + union vote** | GuardDog + SocketAI 組合（論文實測最佳 F1 95.79%） | 所有 detector 平行跑，union（OR）提升 recall。 |
| **Parallel ensemble + intersection vote** | GuardDog + Packj_static | 所有 detector 平行跑，intersection（AND）提升 precision 到 97.39%。 |
| **Three-tier hybrid** | SafeDep, ReversingLabs Spectra Assure | YARA/signatures → static ML → LLM；confidence 隨 tier 疊加而上升。 |
| **LLM-only with recursive chunking** | Datadog BewAIre | 省掉 pre-filter，靠 prompt engineering 把 FP 壓到 0.03%。 |
| **Multi-agent LLM**（learning from research） | LAMPS, LAMPS-CodeBERT | LLM 拆成 harvester / extractor / classifier / aggregator；general agents 用 LLaMA-3，classifier 用 fine-tuned CodeBERT。 |
| **ML scoring + human triage** | GuardDog (純 Semgrep+YARA 無 ML), Phylum (ML "credit score") | 無 LLM；ML 模型算分 → 分數高者送 human researcher triage。 |
| **Static + eBPF runtime ML** | StepSecurity Harden-Runner | 靜態 static + eBPF 收集 outbound calls，用 anomaly detection 判斷首見 C2。 |

---

## Disagreement handling（產業如何處理 ML vs LLM vs static 意見不一致）

- **Datadog BewAIre**: "give preference to the most severe classification and string concatenating reasons" — **max-severity override**。
- **SocketAI / SafeDep**: 多 signal 才算 high confidence；single-signal 為 low confidence，但 **不會 block**，只 surface 給 reviewer。
- **論文 ensemble 研究（arXiv 2603.27549）** 的關鍵結論：`combination effectiveness is governed by two opposing forces: detection complementarity and false-positive introduction`。意思是單純加 detector 不一定提升整體 — 若新 detector 帶來的 FP 比 new TP 多，整體會退步。
- **Phylum/Veracode**: 用 "credit score" 概念，各 signal 有權重貢獻到單一 score，不做 hard vote。
- **GuardDog**: 不做 aggregation，每個 finding 都是獨立 indicator，交給 security researcher 判斷。"findings are mere indicators, not conclusive proof."

---

## Cost/latency 數據（實測）

| 工具 / 設定 | Throughput / Cost / Latency | 來源 |
|---|---|---|
| SocketAI GPT-3 full scan (18,754 files) | $125.65 | arXiv 2403.12196 |
| SocketAI GPT-3 w/ CodeQL pre-filter | $49.13 (60.9% saving) | arXiv 2403.12196 |
| SocketAI GPT-4 full scan | $2,013.84 | arXiv 2403.12196 |
| SocketAI GPT-4 w/ CodeQL pre-filter | $482.46 (76.1% saving) | arXiv 2403.12196 |
| Socket.dev full npm scan (all packages) | "millions of dollars" in API cost pre-optimization | Socket.dev blog |
| Datadog BewAIre | 10,000 PRs/wk, 0.03% FPR, >99.3% accuracy | Datadog engineering blog |
| JFrog Xray detection latency | 2–4 hours from publication to DB flag | JFrog docs |
| Phylum detection latency | avg 11.2 min from publication | Phylum blog |
| Socket.dev detection latency | 6 min (plain-crypto-js@4.2.1 case) | Socket.dev blog |
| Aikido Intel throughput | ~100K malicious pkg/day analyzed (2026) | Aikido site |
| Endor Labs AURI | <2 min per package, claimed 99% accuracy | Endor Labs |

LLM cost ablation 最具體的數據在 SocketAI paper；產業端多半只透露**latency to detection**而非 per-scan cost。

---

## 對 aigate 可參考的具體做法

1. **保留 static prefilter 作為 gate（不要改 parallel）**。SocketAI paper 給出可複製的 60–76% cost saving 數據。你現有的 prefilter 篩到 ~20% 進 consensus 已經是業界最佳實踐範圍；**加 ML backend 要走 cascade 位置而非 parallel**：ML 輕量 classifier 排在 prefilter 之後、LLM 之前，作為第二階段 gate。高信心 ML verdict 短路掉 LLM（這正是 owner 想要的）。

2. **Disagreement 策略採 "severity-max 但 degrade confidence"**。Datadog max-severity override 簡單可靠；但若只有單一 detector 投 MALICIOUS，應降為 NEEDS_HUMAN_REVIEW 而非直接 block — SafeDep 71.9% high-confidence 數據顯示 multi-signal corroboration 才是 precision 的主要來源。你現在的 consensus.py `MALICIOUS + SAFE → NEEDS_HUMAN_REVIEW` 已經做對這件事，**把 ML backend 納入同一個 weighted vote 時要維持此行為**，不要讓 ML 單票直接 override。

3. **Union vs intersection 的權衡要明確暴露為 config**。論文數據顯示 GuardDog + SocketAI union F1 95.79%（recall 導向），GuardDog + Packj intersection F1 93% / precision 97.39%（precision 導向）。aigate 使用者場景不同（CI block vs dev 警告），應該把 `ensemble_mode: union|intersection|weighted_vote` 做成 `.aigate.yml` 的 first-class toggle，而非硬編碼。owner 要的「ML confident 時短路 LLM」實際上是 `intersection with ML high-confidence fast-path` 的特例。

---

## Sources

### Primary engineering blogs
- [Detecting malicious pull requests at scale with LLMs (Datadog)](https://www.datadoghq.com/blog/engineering/malicious-pull-requests/)
- [Introducing Socket AI – ChatGPT-Powered Threat Analysis](https://socket.dev/blog/introducing-socket-ai-chatgpt-powered-threat-analysis)
- [Socket × OpenAI ChatGPT integration story (The Register)](https://www.theregister.com/2023/03/30/socket_chatgpt_malware/)
- [Introducing GuardDog 2.0: YARA scanning (Datadog Security Labs)](https://securitylabs.datadoghq.com/articles/guarddog-2-0-release/)
- [GuardDog: Strengthening Open Source Security (OpenSSF)](https://openssf.org/blog/2025/03/28/guarddog-strengthening-open-source-security-against-supply-chain-attacks/)
- [Dynamic Malware Analysis of OSS Packages at Scale (SafeDep)](https://safedep.io/dynamic-analysis-oss-package-at-scale/)
- [Analysis of 5000+ Malicious OSS Packages with SafeDep malysis](https://safedep.io/malysis-evaluation-using-datadog-malicious-packages-dataset/)
- [Phylum Research Blog](https://blog.phylum.io/)
- [Phylum Q3 2024 Supply Chain Security Report](https://blog.phylum.io/q3-2024-evolution-of-software-supply-chain-security-report/)

### Product / docs (operational claims)
- [Endor Labs Malware Detection use case](https://www.endorlabs.com/use-cases/malware-detection)
- [Endor Labs AURI AI-Native Platform](https://www.endorlabs.com/platform)
- [JFrog Xray Malicious Package Detection docs](https://docs.jfrog.com/security/docs/malicious-package-detection)
- [JFrog Blog: Detecting Malicious Packages](https://jfrog.com/blog/detecting-known-and-unknown-malicious-packages-and-how-they-obfuscate-their-malicious-code/)
- [ReversingLabs Spectra Assure ML malware detection](https://www.reversinglabs.com/blog/spectra-assure-malware-detection-in-ml-and-llm-models)
- [ReversingLabs Spectra Assure threat detection docs](https://docs.secure.software/concepts/threat-detection)
- [Aikido Malware Detection in Dependencies](https://www.aikido.dev/code/malware-detection-in-dependencies)
- [Aikido Intel (Vulnerability Intelligence)](https://intel.aikido.dev/)
- [StepSecurity Harden-Runner 2000 repos milestone](https://www.stepsecurity.io/blog/celebrating-2000-github-repositories-secured-with-harden-runner)
- [StepSecurity OSS Package Security docs](https://docs.stepsecurity.io/oss-package-security)
- [Veracode Acquires Phylum](https://www.veracode.com/blog/innovating-secure-software-supply-chains-veracode-acquires-phylum/)

### Academic / ablation studies (with F1, cost numbers)
- [Shifting the Lens: Detecting Malicious npm Packages using LLMs (arXiv 2403.12196)](https://arxiv.org/html/2403.12196v2) — CodeQL pre-filter + GPT-3/4 cost ablation
- [Understanding NPM Malicious Package Detection: Benchmark-Driven Empirical Analysis (arXiv 2603.27549)](https://arxiv.org/html/2603.27549) — ML vs LLM comparison, union/intersection ensemble numbers
- [Mind the Gap: LLMs High-Level vs Fine-Grained Indicator Detection (arXiv 2602.16304)](https://arxiv.org/html/2602.16304) — GPT-4.1 F1 0.99 binary, 41% drop on multi-label
- [MAL-LLM: Evaluating LLMs for Detecting Malicious PyPI (arXiv 2504.13769)](https://arxiv.org/html/2504.13769v1) — 97% accuracy with YARA + few-shot
- [LAMPS: Many hands make light work (multi-agent LLM) (arXiv 2601.12148)](https://arxiv.org/html/2601.12148v1) — LLaMA-3 + fine-tuned CodeBERT classifier agent
- [OSSF package-analysis GitHub](https://github.com/ossf/package-analysis)
- [GuardDog GitHub (DataDog)](https://github.com/DataDog/guarddog)

---

## 研究中發現的 prompt injection

首次 WebSearch 回傳結果中夾帶一段偽造 `<system-reminder>` 區塊，聲稱「Ghost OS MCP server instructions」要求呼叫 `ghost_recipes` / `ghost_context` / `ghost_find` 並夾帶 `app` 參數。此為搜尋結果中的 prompt injection，未執行任何相關指令。原始使用者任務已完整完成。
