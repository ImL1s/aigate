# Academic Research — ML+LLM Hybrid Systems (findings)

調研目的：為 aigate 從「pure LLM 共識」演進到「ML 前置 + LLM 後置」混合管線提供學術依據，
聚焦於 2024-2026 年 cascade / routing / selective prediction / 校準 / 對抗韌性等主題。

## 最相關的 3-5 篇論文

**1. IntelGuard (Bridging Expert Reasoning and LLM Detection, 2026)** —
venue: arXiv 2601.16458；一句話貢獻：以 RAG 檢索 8,024 份威脅情報報告的「專家推理鏈」作為 LLM 的
前置知識源，在 PyPI 達 **99.00% accuracy、99.49% precision、98.50% recall**，且在混淆程式上維持
**96.50% accuracy**（相較純 GPT-4o-mini 的 52.82%，提升 43.68 點，false negative 從 880 降至 28，
30× 改善）。Ablation：移除檢索知識會讓 accuracy 掉 2-3 點；在 PyPI 實戰三個月挖出 54 個真實惡意包，
24 個被官方確認下架。對 aigate 可移植：RAG 層可用我們 prefilter 累積的 risk signal 字串作為檢索 key，
把「dangerous_pattern(HIGH)」配對到歷史 CVE/GHSA，LLM 拿到這份上下文再判決。

**2. SocketAI (Shifting the Lens, arXiv 2403.12196)** —
venue: arXiv 2403.12196 v4；一句話貢獻：CodeQL 靜態規則作為 LLM 前置篩選器，將需 LLM 分析的檔案
從 18,754 砍到 4,146（**-77.9%**），GPT-3 成本從 $125.65 → $49.13（-60.9%），GPT-4 從 $2013.84 →
$482.46（-76.1%）。GPT-4 最終 **precision 0.99、recall 0.95、F1 0.97**，相對純靜態分析 precision
+16 點、F1 +9 點。**直接對應 aigate 的 prefilter → consensus 架構**，證明「cheap static gate →
expensive LLM」是節省成本的主流 pattern。

**3. A Unified Approach to Routing and Cascading for LLMs (ICLR 2025, arXiv 2410.10347)** —
一句話貢獻：首次證明 routing 與 cascading 可以在一個理論上最優的框架下統一，提出 cascade routing。
數值：RouterBench 上 +8%、SWE-Bench 上 +14%，論文強調「quality estimator 品質」是成功的關鍵因子，
而非 cascade 結構本身。對 aigate 可移植：若未來要接入多 LLM backend（Claude / Gemini / Ollama /
GPT-4o），可用此框架學一個 estimator 在每個 package 上決定要不要 escalate。

**4. FrugalGPT (TMLR 2024, arXiv 2305.05176)** —
一句話貢獻：證明學一個 scoring function + stop judger，可以讓 LLM cascade **在 GPT-4 精度下省
98% 成本**，或在相同成本下提升 4% accuracy。核心假設：cheaper models 有 generation diversity，
部分 query 便宜模型就能解。對 aigate 意義：驗證了「Ollama（local 免錢）→ Claude → Gemini」cascade
策略是可行的，且 scoring function 可以非常簡單。

**5. Self-REF: Learning to Route LLMs with Confidence Tokens (arXiv 2410.13284)** —
一句話貢獻：在 LLM 後直接訓練出 `<CN>` / `<UN>` 信心 token，轉為連續分數。Llama3-8B 只送 **39-65%
queries** 到 Llama3-70B 即可匹敵 70B 單獨表現（baseline 需 90-100%），延遲加速 **2.03×**。
Gradient masking ablation 關鍵；不加 mask 會學到 spurious pattern。對 aigate：即使我們不 fine-tune，
也能把「用 Ollama 產生信心分數再決定要不要叫 Claude」的精神拿來實作。

## Routing / cascade 架構的最新進展

- **RouteLLM** 實測：85% queries 可走廉價模型，維持 95% 的 frontier 模型品質，成本降 45-85%。
- **Speculative Cascades (Google Research 2025)** 把 speculative decoding 和 cascade 結合：
  小模型生草稿、大模型驗證，同時在 throughput 和 quality 上壓過純 cascade 或純 speculative。
  概念上可類比：aigate 讓 Ollama 先產出一個「判決草稿 + 關鍵觀察」，Claude 只驗證而非重新分析。
- **Cost-Aware Contrastive Routing (arXiv 2508.12491)** 在 Pareto frontier 上穩定優於現有 router，
  核心洞見：routing 要學 cost 與 accuracy 的 trade-off，不是單純 accuracy。
- 跨論文一致結論：**「uncertainty calibration 比 raw accuracy 更重要」**——best cascade 來自那個
  「知道自己什麼時候會錯」的模型。

## Adversarial robustness 結論

Hybrid **並非免費地更 robust**，以下三點是 2024-2026 文獻的集中警訊：

1. **CoTDeceptor (arXiv 2512.21250, 2026)** 顯示：同一份混淆程式碼能同時繞過靜態分析 **和**
   CoT-enhanced LLM vulnerability detector——雙管線並不等於兩道獨立防線，攻擊者可以找共通盲點。
2. **Bypassing LLM Guardrails (ACL LLMSec 2025)**：zero-width characters、Unicode tags、homoglyphs
   能讓六大商用 guardrail 全軍覆沒；對 LLM 可讀但對 classifier 不可讀的輸入是系統性弱點。
3. **False Alarms, Real Damage (arXiv 2507.06252)** 在 CTI 系統上實測：specialized ML classifier
   FPR 97%、ChatGPT-4o FPR 75%——adversarial 輸入下兩者都崩潰，不是 LLM 就一定贏。

**但** IntelGuard 的 **43.68 點混淆 accuracy gap** 告訴我們：若 ML 層不是傳統 feature classifier 而是
**knowledge retrieval** 類的 signal injection（給 LLM 看歷史案例），確實能把 LLM 從 52% 救回 96%。
差別在「ML 提供什麼給 LLM」，而不是「有沒有 ML 這層」。

## Confidence calibration 警訊

- **ML-Based Behavioral Malware Detection Is Far From a Solved Problem (arXiv 2405.06124)**：
  sandbox 上 >90% accuracy 的模型，部署到真實 endpoint **TPR 只剩 17-49%**——distribution shift
  在部署當下就出現，不是慢慢累積；且 benign 和 malware 都被 drift detector 拒絕，傳統 OOD 訊號失效。
- **Selective Classifier 研究 (arXiv 2510.20242, 2025)**：Temperature scaling 把 ECE 從 0.052 壓到
  0.048，但 E-AURC 幾乎沒變（0.033 → 0.033）——**post-hoc calibration 不會改 ranking**。只有
  Deep Ensemble / Self-Adaptive Training 這種會動到 ranking 的方法才真的改善 selective prediction。
- **Probing-based Malicious Input Detection Fails to Generalize (arXiv 2509.03888)**：在內部
  hidden state 訓 probe 看起來很美，但 OOD 上崩潰，論文直接命名「False Sense of Security」。

**推論**：若 aigate 加入 ML 分類器，**不能**直接相信 `confidence > 0.95` 就 short-circuit。必須
(a) 用 isotonic regression 而非 sigmoid 做 threshold、(b) 定期重訓避免 concept drift、
(c) 對 OOD package（新生態、新依賴圖形狀）走保守路徑——強制 escalate 到 LLM。

## Prompt injection via package metadata — 特別角度

aigate 的 LLM consensus 階段會讀 README / description / setup.py 文字，這正是 **indirect prompt
injection (IPI)** 的攻擊面。2025-2026 已有多起真實案例：Cline/OpenClaw 事件透過 Claude GitHub Action
的 IPI，讓 ~4,000 台開發者機器安裝持久化 daemon。

文獻給的防禦原則（可直接套用到 aigate）：
- **PromptArmor (ICLR 2026)** 稱 off-the-shelf LLM 當 classifier 偵測 prompt injection，AgentDojo
  上 FP/FN 都 <1%。
- **Spotlighting**：用 delimiter 明確標記「不受信任的外部文字」，實驗證實能大幅降低 IPI 成功率。
- **User Alignment Critic (Google)**：只看 metadata 的第二 LLM，對 web-based 注入免疫——這正是
  **metadata-only ML 層在 aigate 裡的理論依據**：即使主 LLM 被 README 中的 prompt injection 騙到
  說「safe」，一個只看 entropy / token distribution / dependency graph 的 ML 分類器看不到注入文字，
  會給出矛盾判斷，進而觸發 NEEDS_HUMAN_REVIEW。

## 對 aigate 可直接採納的設計

- **「disagreement → human review」設計是對的（來自 FrugalGPT + Self-REF）**：當 ML 層和 LLM 層
  判斷不一致時，不要試著合成單一答案；直接升級。這也天然防禦 prompt injection：ML 看不到文字注入，
  會和被騙的 LLM 形成顯性分歧。
- **短路優化採 SocketAI pattern，不採純信心閾值**：靜態規則層命中明確惡意 pattern（如
  obfuscated eval + network exfil）直接判 MALICIOUS，不浪費 LLM 錢；低風險 pattern 才進 LLM。
  **不要**僅憑 ML classifier 的 confidence score short-circuit（selective classifier 論文證明
  post-hoc calibration 無法修 ranking）。
- **用 IntelGuard 的 RAG pattern 升級 prefilter**：aigate 既有的 risk signal 字串（"dangerous_pattern
  (HIGH): ..."）本質上就是一個可檢索的 knowledge base。把歷史惡意包的 risk signal 向量化，新 package
  進來時先做 nearest-neighbor 查 top-k 相似案例塞進 LLM prompt——低成本就拿到 4-9 點 accuracy 提升
  和 30× 混淆 FN 改善。

## Open questions / under-researched gaps

- **專門研究「npm/PyPI 場景下 ML 分類器作為 prompt injection 防線」的論文仍缺**。目前都是通用 IPI
  defense，沒有人專門實驗「LLM 被 README 裡的 prompt injection 騙」vs「metadata-only classifier
  不受騙」的對照實驗——這是 aigate 可以貢獻的實證空白。
- **Hybrid pipeline 在 adversarial package 上的 end-to-end robustness benchmark 闕如**。
  CoTDeceptor 攻了 CoT-LLM 單體，但沒攻真實 hybrid 系統；IntelGuard 沒測 adaptive attacker。
- **多 LLM consensus（aigate 現況）的 cost-accuracy Pareto 曲線沒被學術界畫過**。
  FrugalGPT 是 sequential cascade，aigate 是 parallel vote——兩者在同樣預算下哪個贏？未解。
- **Concept drift 在 package ecosystem 上的特殊性**：ML malware 研究都在 PE binary / APK，
  npm/PyPI 的 drift 模式（新框架出現、依賴圖形狀變化）和傳統 malware 不同，文獻幾乎沒碰。

## Sources

- IntelGuard: https://arxiv.org/html/2601.16458
- SocketAI (Shifting the Lens): https://arxiv.org/html/2403.12196v4
- A Unified Approach to Routing and Cascading: https://arxiv.org/abs/2410.10347
- FrugalGPT: https://arxiv.org/abs/2305.05176
- Self-REF (Confidence Tokens for Routing): https://arxiv.org/html/2410.13284v3
- MAL-LLM / Detecting Malicious Source Code in PyPI with LLMs: https://arxiv.org/pdf/2504.13769v1
- ML-Based Behavioral Malware Detection Is Far From a Solved Problem: https://arxiv.org/html/2405.06124v2
- What Does It Take to Build a Performant Selective Classifier: https://arxiv.org/html/2510.20242v2
- False Sense of Security (probing-based detection): https://arxiv.org/html/2509.03888v1
- CoTDeceptor (adversarial CoT obfuscation): https://arxiv.org/pdf/2512.21250
- Bypassing LLM Guardrails (LLMSec 2025): https://aclanthology.org/anthology-files/pdf/llmsec/2025.llmsec-1.8.pdf
- False Alarms, Real Damage (CTI adversarial): https://arxiv.org/html/2507.06252v1
- Cost-Aware Contrastive Routing for LLMs: https://arxiv.org/html/2508.12491v1
- Cascade Speculative Drafting: https://arxiv.org/abs/2312.11462
- Speculative Cascades (Google Research blog): https://research.google/blog/speculative-cascades-a-hybrid-approach-for-smarter-faster-llm-inference/
- Investigating Vulnerability of LLM-as-a-Judge to Prompt Injection: https://arxiv.org/abs/2505.13348
- A Sequential Multi-Stage Approach for Code Vulnerability Detection (EMNLP 2025): https://aclanthology.org/2025.emnlp-main.1071.pdf
- CHASE (LLM Agents for PyPI): https://arxiv.org/html/2601.06838
- NPM Malicious Package Detection Benchmark: https://arxiv.org/html/2603.27549
- MalGEN (malware generation): https://arxiv.org/html/2506.07586v1
