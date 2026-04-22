# ML+LLM Hybrid Patterns in Adjacent Domains

本研究盤點金融詐欺、內容審核、郵件安全、醫療分類、客服路由、可觀測性六個鄰近領域，歸納成熟的 ML+LLM 混合 pattern，提煉出 aigate 可借鏡的設計。

## Top 5 值得借鏡的 pattern

1. **Two-Stage Recall → Rank（TikTok 內容審核）** — 第一階段用輕量 embedding retrieval 過濾 34M/day 影片，第二階段才讓 MLLM 精排。理由：aigate 的 prefilter 本質上也是一個 recall 階段，可借用「seed-based embedding retrieval」的概念，讓可疑套件以相似度指派到 AI 分析佇列，而非純靜態規則。

2. **Cascade with Confirming Model（GitHub Copilot Secret Scanning）** — GPT-3.5 先掃，候選結果由 GPT-4 作為 "confirming scanner" 二次確認，達成 94% FP reduction，精度 > 召回率。aigate 的 Claude + Gemini 共識可升級為「輕模型初判 → 重模型覆核」的 asymmetric cascade，成本更低。

3. **Shadow Mode + Weekly Dataset Refresh（Datadog BewAIre）** — 在公開前先以 shadow mode 跑幾個月，security team 手動 triage alerts，並每週更新 labeled dataset（真實 exploits + 模擬攻擊 + benign PR），達成 0.03% FP rate。aigate 發版前必跑 shadow mode，且 fixture set 應週級別更新。

4. **Drift-Aware Two-Stage Detection（金融詐欺學界方向）** — 第一階段 ensemble classifier 定位可疑 → 第二階段 One-Class Drift Detector 判定語言/行為是否偏移 → 只在 drift 時才喚醒 LLM 判斷是「對抗性改寫」還是「合法更新」。對 aigate 特別合適：npm/pypi 套件語意會隨生態演進，不應把 "語法變化" 直接等同於 "惡意"。

5. **Arbitration with Simulated Third Reader（乳攝篩檢）** — 兩讀者不一致時由第三人仲裁，AI 取代第二讀者後，仲裁層為品質閘門。對 aigate 啟發：Claude 與 Gemini 分歧時不直接回傳 NEEDS_HUMAN_REVIEW，可再加一個更強的仲裁模型（例如 opus 或 fine-tuned code model）作為「第三讀者」。

## Cascade vs Parallel vs LLM-First — 各域偏好

| 域 | 主要 Pattern | 為什麼選這個 |
|---|---|---|
| 金融詐欺（Stripe Radar） | ML 先，LLM 輔助（judge/narrative） | 延遲預算 < 100ms，LLM 僅用於 "no source of truth" 場景（friendly fraud） |
| 內容審核（TikTok） | Cascade: embedding recall → MLLM rank | 每日 34M 影片，LLM 全跑不可行 |
| 內容審核（Stream/getstream） | 混合三模式：fallback、primary、parallel | LLM 比 NLP 貴 10x-100x；高風險場景才 all-LLM |
| Copilot Secret Scanning | Cascade: GPT-3.5 → GPT-4 confirm | 精度優先（generic secrets 極易 FP） |
| Datadog BewAIre（PR malware） | LLM-first（無 ML pre-classifier） | PR 量級可控（每日千級），靠 prompt engineering 壓 FP |
| Socket.dev | Static analysis → LLM → 人工覆核 | 套件量千萬級，需層層收斂 |
| 乳攝（AI + 放射師） | 雙讀平行 + arbitration | 錯誤代價極高，不可 abstain |
| 客服（Intercom Fin） | Classifier → Retrieval → LLM | 意圖分類錯，後續 RAG 全錯 |
| Fraud BEC（Abnormal） | 三軸平行 ensemble（身份/關係/NLP） | 行為基線偏移才是訊號，非單點判斷 |

**主流是 cascade**，ML-first 比 LLM-first 多。LLM-first 僅在「量級不大 + 代價可控 + 需自然語言解釋」時可行（BewAIre 就是此例）。

## Disagreement Resolution 手法統整

1. **Abstain + human-in-loop** — Uber RADAR、Socket.dev、Stripe Radar manual review queue。高風險不自動出裁決，掛人。
2. **Cautious-verdict-wins** — Datadog 大 diff chunk 合併時取 "most severe classification"。
3. **Arbitration by stronger model** — 乳攝仲裁第三讀；Copilot 用 GPT-4 覆核 GPT-3.5。
4. **Weighted by calibrated confidence** — Amazon Science 的 logit calibration pipeline，校準後 calibration error 降 46%，cascade 成本降 2x。
5. **Drift-gated LLM judgment** — 行為偏離 baseline 時才喚 LLM；正常時靠 ML（Abnormal Attune 1.0 走此路）。
6. **Voting / repeated prompting** — GitHub 測試過「同樣問題問多次」，但對 precision 無實質提升 → voting 不是萬靈藥。

## Threshold Tuning 實務

- **Fixed threshold 很少見** — 幾乎所有生產系統都用某種 learned 或 calibrated 機制。
- **Per-class / per-business threshold** — Stripe Radar 允許 merchant 自訂 risk setting；Adyen ML rules 可依 profile 調。
- **Shadow-traffic learned** — Datadog、GitHub、Honeycomb 都在 shadow mode 用真實流量決定閾值，而非 synthetic benchmark。
- **Calibrated confidence > raw confidence** — logit calibration（sigmoid / isotonic / temperature scaling）在 fraud 與 LLM 分類都是標配。
- **Weekly / continuous retrain** — Stripe 每週訓練；BewAIre dataset 每週更新；Abnormal 宣稱 continuous feedback loop。
- **Balanced accuracy 而非 accuracy** — 正負樣本懸殊時（BewAIre 的 malicious PR 極少）必用，否則 threshold 會被 majority class 淹沒。

## 最能借鏡給 aigate 的三個具體做法

1. **Asymmetric Cascade 取代對等 parallel 共識**：當前 Claude + Gemini 平行投票浪費了一半推理成本。改為 Gemini（便宜快）先判，confidence 低於 τ 時才喚 Claude 覆核（GPT-3.5 → GPT-4 模式）。保留 opus 作為分歧仲裁的「第三讀者」。預期成本降 40-60%，不損精度。

2. **Shadow-mode 上線 + weekly fixture refresh**：參考 BewAIre 做法。新版本 prefilter/consensus 規則先以 shadow mode 跑 2-4 週，不回寫 verdict 但全量記錄差異。真實 npm/pypi malware advisory（如 OSV、Snyk、GHSA）每週自動拉取，更新 `tests/fixtures/`。Balanced accuracy 作為主指標，而非現行任何單一指標。

3. **Drift-gated escalation**：多數套件的語意是穩定的（requests、numpy 這類）。加一層輕量的 embedding-based「這個套件和它的歷史版本/同類套件相似嗎」判斷。只有 embedding distance 跳變 時才觸發完整 LLM consensus。這同時解決了 prefilter 誤判「正常 updates」為 dangerous pattern 的問題，也壓縮了大量穩定套件的 AI 呼叫。

## Warnings — 不能直接抄的東西

- **TikTok 的 embedding recall 需要 seed video set**；aigate 的「seed」是什麼？目前沒有足夠多「已知惡意家族」fixture 能做有意義的 embedding 檢索。需先建立 malicious-behavior embedding bank，才值得上這個 pattern。
- **Adyen/Stripe 的 graph database 不適用**：他們的 feature engineering 靠跨交易關聯（device fingerprint、merchant network）。aigate 沒有跨使用者觀測資料，學不來這個優勢。
- **Honeycomb Query Assistant 的「非破壞性 fallback」不適用於安全場景**：他們可以「寧可給一個壞查詢也不要拒答」，aigate 絕不能「寧可放行一個可能的惡意套件」。安全場景偏誤方向相反，escalation 不是為了降低惹惱用戶，而是為了降低漏放。
- **LLM-as-judge 論文多在「無 ground truth」情境**（creative writing、subjective rating）。aigate 的裁決有 ground truth（套件是否真的惡意），應以傳統 ML metrics 為主，judge-style 評估僅適合 prompt iteration 階段。
- **Voting/repeated prompting 無效**：GitHub 明確驗證過對 precision 無實質提升。別浪費算力投重複 prompt，應投入在 calibration 和 shadow testing。
- **BEC 行為基線方法難以遷移**：Abnormal 有 30-90 天的使用者行為歷史可對比；aigate 看到的是 immutable snapshot，建不起 per-package baseline（prior version diff 倒是可探索的弱版本）。

## Sources

- [TikTok's Two-Stage Content Moderation at Scale](https://medium.com/@parklize/how-tiktok-uses-llms-to-power-content-moderation-at-scale-84ae2287c526)
- [Datadog: Detecting malicious pull requests at scale with LLMs (BewAIre)](https://www.datadoghq.com/blog/engineering/malicious-pull-requests/)
- [Google Research: Speculative Cascades — smarter, faster LLM inference](https://research.google/blog/speculative-cascades-a-hybrid-approach-for-smarter-faster-llm-inference/)
- [GitHub Blog: Finding leaked passwords with AI — Copilot secret scanning](https://github.blog/engineering/platform-security/finding-leaked-passwords-with-ai-how-we-built-copilot-secret-scanning/)
- [Socket.dev: Enhanced Security Scanning with AI Alert Defaults](https://socket.dev/blog/enhanced-security-scanning-with-improved-ai-alert-defaults)
- [Stripe: A primer on machine learning for fraud detection](https://stripe.com/guides/primer-on-machine-learning-for-fraud-protection)
- [Stripe: Using AI to optimize payments performance](https://stripe.com/blog/using-ai-optimize-payments-performance-payments-intelligence-suite)
- [Adyen: How ML assesses payment risk](https://help.adyen.com/knowledge/risk/risk-profiles/how-does-machine-learning-assess-payment-risk)
- [Adyen engineering data architecture breakdown (Xenoss)](https://xenoss.io/blog/how-stripe-paypal-visa-and-adyen-solve-the-toughest-data-engineering-challenges-in-payments)
- [Abnormal AI: Behavioral AI Advanced Threat Protection](https://abnormal.ai/blog/behavioral-ai-advanced-threat-protection)
- [Intercom: The Fin AI Engine architecture](https://fin.ai/ai-engine)
- [Intercom: Scaling AI Chatbot to Production with Multiple LLM Providers (ZenML LLMOps DB)](https://www.zenml.io/llmops-database/scaling-customer-support-ai-chatbot-to-production-with-multiple-llm-providers)
- [Honeycomb: All the Hard Stuff Nobody Talks About when Building Products with LLMs](https://www.honeycomb.io/blog/hard-stuff-nobody-talks-about-llm)
- [Honeycomb: Improving LLMs in Production With Observability](https://www.honeycomb.io/blog/improving-llms-production-observability)
- [Uber: Project RADAR — Intelligent Early Fraud Detection with Humans in the Loop](https://www.uber.com/blog/project-radar-intelligent-early-fraud-detection/)
- [Uber: GenAI Gateway](https://www.uber.com/blog/genai-gateway/)
- [Stream: NLP vs LLM for moderation — hybrid architecture](https://getstream.io/blog/nlp-vs-llm-moderation/)
- [Wiz Blog: Introducing Wiz SAST — code risk meets cloud context](https://www.wiz.io/blog/introducing-wiz-sast-where-code-risk-meets-cloud-context)
- [Salesforce: Einstein Service Agent reasoning engine](https://www.salesforce.com/news/stories/einstein-service-agent-announcement/)
- [AI as a Second Reader in Screening Mammography (Radiology: AI, 2024)](https://pubs.rsna.org/doi/10.1148/ryai.240624)
- [AI-integrated Screening to Replace Double Reading of Mammograms (Radiology: AI, 2024)](https://pubs.rsna.org/doi/abs/10.1148/ryai.230529)
- [FrugalGPT — LLM cascade reducing cost up to 98%](https://arxiv.org/abs/2305.05176)
- [Amazon Science: Calibrated confidence and ensembles in LLM-powered classification](https://www.amazon.science/publications/label-with-confidence-effective-confidence-calibration-and-ensembles-in-llm-powered-classification)
- [Domain Knowledge-Enhanced LLMs for Fraud and Concept Drift Detection (MDPI)](https://www.mdpi.com/2079-9292/15/3/534)
- [Joint Detection of Fraud and Concept Drift in Online Conversations (arXiv)](https://arxiv.org/html/2505.07852v1)
- [Shadow Mode, Canary Deployments, and A/B Testing for LLMs](https://tianpan.co/blog/2026-04-09-llm-gradual-rollout-shadow-canary-ab-testing)
