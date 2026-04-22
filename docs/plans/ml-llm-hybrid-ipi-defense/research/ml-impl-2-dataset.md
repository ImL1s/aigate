# Dataset Acquisition & Training Data Pipeline

目標：為 aigate 的 metadata-only ML 分類器建立一套可重現、可授權、可抗 concept drift 的 PyPI / npm 訓練資料流程。本份研究聚焦在 **來源盤點 → 良性樣本採集 → 類別不平衡 → 時序切分 → 大量 metadata 抓取 → 去重 → 法律**。

## 惡意樣本來源 (ranked by quality + licensability)

| 來源 | 樣本數（PyPI / npm / 其他）| License | 格式 | 更新頻率 | 推薦權重 |
|---|---|---|---|---|---|
| **OSSF malicious-packages** | PyPI ≈ 11k；npm ≈ 210k+；RubyGems ≈ 970；NuGet ≈ 770；其他 <50 | Apache-2.0 | OSV JSON (`MAL-YYYY-NNNNNN.json`) | 每日自動更新 | ★★★★★ primary ground truth |
| **Datadog malicious-software-packages-dataset** | 22,868 total across npm + PyPI + IDE ext + AI Skills | Apache-2.0 | 加密 ZIP（password `infected`）+ `manifest.json` | Rolling | ★★★★★ 含 source code，人工驗證 |
| **pypi_malregistry** (lxyeternal) | 9,503 packages / 10,823 versions (PyPI only) | 未明示 (academic) | 原始 tar.gz 歸檔，`pkg/version/archive` | 最後更新 2026-01-23 | ★★★★ 最完整的 PyPI source-code corpus |
| **GitHub Advisory Database (GHSA)** | 查詢 `type:malware` (數千條) | CC-BY-4.0 | 每條 advisory 一個 JSON（`advisories/github-reviewed/YYYY/MM/GHSA-*/*.json`） | 持續 | ★★★★ 作為交叉驗證 |
| **Backstabber's Knife Collection** | 歷史 dataset，需要機構 email 申請 | 研究用、非公開 | 未公開 | 未明 | ★★ 只能做 qualitative，不適合重新散布 |
| **Snyk Vulnerability DB** | advisory level | 專有（需 API key，禁止 redistribution） | JSON (API) | 持續 | ★★ 僅作為驗證標籤，不得 bundle |
| **Socket.dev threat feed** | 部落格+blog posts，沒有 bulk dataset | 文章授權 | HTML/RSS | 不穩定 | ★ 人工 triage |

**OSSF 計算**（從 `https://ossf.github.io/malicious-packages/stats/all.json` 2026-04-22 快照加總）：
- PyPI 總計 ≈ **11,031** 筆報告（2023-02 一次性匯入 6,170、2024-06 匯入 1,715 為主）
- npm 總計 ≈ **210,000+** 筆（2025-11 單月 142,163、2025-08 單月 35,204，疑似大規模 campaign 或 Amazon Inspector 的 bulk ingest）
- **重要警訊**：npm 的數字被 2025 年兩次巨量尖峰嚴重主導。建議實務上只取 **2025-07 之前** 的資料做訓練 baseline，避免單一 campaign 污染分布。

## 每個來源的取得方式

### OSSF Malicious Packages Repo

結構（以 `osv/malicious/<ecosystem>/<package_name>/MAL-YYYY-NNNNNN.json` 為準）：

```
malicious-packages/
├── osv/
│   ├── malicious/
│   │   ├── pypi/<pkg>/MAL-*.json
│   │   ├── npm/<pkg>/MAL-*.json
│   │   └── rubygems/...
│   └── withdrawn/            # false positives，移出時會加 withdrawn timestamp
└── site/stats/all.json       # 每日統計
```

OSV 1.5.0 schema 重要欄位：`id`、`summary`、`details`、`affected[].package.{ecosystem,name}`、`affected[].ranges`、`credits[]`、`aliases[]`（常含 GHSA-id 交叉參照）、`database_specific`。只有 metadata，**沒有** malicious source code。

取得 script：

```python
# 一次性 clone 最省事（repo ~ 幾百 MB）
# git clone --depth 1 https://github.com/ossf/malicious-packages
import json, pathlib
root = pathlib.Path("malicious-packages/osv/malicious")
records = []
for eco in ("pypi", "npm"):
    for p in (root / eco).rglob("MAL-*.json"):
        with p.open() as f:
            r = json.load(f)
        pkg = r["affected"][0]["package"]["name"]
        published = r.get("published", "")  # ISO-8601
        records.append({
            "id": r["id"], "ecosystem": eco, "name": pkg,
            "published": published,
            "versions": [e.get("introduced") for rg in r["affected"][0].get("ranges", []) for e in rg.get("events", [])],
            "summary": r.get("summary", ""),
            "aliases": r.get("aliases", []),
        })
# pandas.DataFrame(records) → 匯出 parquet
```

Apache-2.0 允許 redistribution，aigate 可以把 `MAL-ID → package_name → published_date` 這張表 bundle 進 repo 的 fixtures。

### Datadog malicious-software-packages-dataset

22,868 筆，`samples/<ecosystem>/<classification>/` 下每個 package 一個加密 ZIP，password `infected`。每個 ecosystem 有 `manifest.json` 列出 `package_name → affected_versions`（`null` 代表整個 package 是 malicious intent，非 null 代表僅 compromised 某些版本）。檔名內嵌發現日期。

```bash
git clone --depth 1 https://github.com/DataDog/malicious-software-packages-dataset
./extract.sh  # bundled helper，會把全部 ZIP 解到 /tmp
```

**用途**：aigate 的 metadata-only model 其實不需要 source code，但這份 dataset 的 `manifest.json` 是乾淨的 labeled list，而且 **每筆都人工驗證**，品質極高。建議純用 manifest 做 label join，source code 留給 rule/YARA pipeline（例如 GuardDog）用。

### pypi_malregistry

`git clone` 後結構 `packages/<name>/<version>/<archive.tar.gz>`。約 9,503 package / 10,823 version，含 source code。需要自行從 `setup.py` / `PKG-INFO` / `METADATA` 抽 metadata：

```python
import tarfile, email
def extract_metadata(tgz_path):
    with tarfile.open(tgz_path) as tf:
        for m in tf.getmembers():
            if m.name.endswith(("PKG-INFO", "METADATA")):
                return email.message_from_bytes(tf.extractfile(m).read())
```

License 沒寫清楚（repo README 未明示），基於 academic fair use，建議 aigate **不重新打包散布**，僅在 training pipeline 中引用。

### GitHub Advisory Database (GHSA)

```bash
git clone --depth 1 https://github.com/github/advisory-database
find advisory-database/advisories -name '*.json' -path '*malware*'
# 或 GitHub REST API
curl "https://api.github.com/advisories?type=malware&ecosystem=pip&per_page=100"
```

每筆 JSON 有 `identifiers`、`cve_id`、`summary`、`affected[]`、`published_at`。**CC-BY-4.0**，可 redistribute。

### Snyk / PyPI Advisory / npm Advisory

- **Snyk** 的 vuln DB 須 API key，ToS 禁止 bulk redistribution。**不要** bundle。
- **PyPI** 本身沒有獨立 advisory DB；透過 GHSA 的 PIP ecosystem 即可涵蓋。
- **npm audit** 的資料源也已併入 GHSA。

### Socket.dev / 其他

Socket 公開只有 blog post，沒有結構化 dataset。可寫 scraper 抓 IOC（package name 清單）做額外 signal，但不能當 primary source。

## 良性樣本 sourcing 策略

**反直覺重點**：「熱門 package 一定良性」是錯的。著名反例 `event-stream`（npm，2018, 每週 2M 下載）、`ua-parser-js`（2021）、`@solana/web3.js`（2024 MAL-2024-11183）在被攻擊時都在 top 下載榜。單純 `downloads > N` 濾除是 **不夠的**。

建議多層濾網：

1. **Baseline**：從 BigQuery `bigquery-public-data.pypi.file_downloads` 或 npm 的 download stats 取 top N（N = 100k）。
2. **Age filter**：`first_release_date < now - 2 years` 且 `last_release < now - 6 months`（最近還在更新但非剛上線）。新上線 < 90 天的 package 風險最高，不納入良性。
3. **Diff against known bad**：跟 OSSF + Datadog + GHSA + pypi_malregistry 做 anti-join，**並 match typosquat 變體**（見下方 dedup 段落）。
4. **Repo sanity**：有 `project_urls.Repository` 或 `homepage` 指向可 resolve 的 GitHub repo，stars ≥ 10。
5. **Owner reputation**：排除作者帳號註冊 < 90 天、或 email domain 為 disposable 的。

即使這樣過濾，你要有 **約 0.1–0.5% 的 label noise（良性樣本實際是還沒被發現的惡意）** 的心理準備。這個 noise 是真實世界 base rate，不必強求 0%。

**樣本量建議**：PyPI 50k benign + 5k malicious（10:1），npm 100k benign + 10k malicious。更高的比例（如 1:100）更貼近現實但會讓訓練不穩；1:10 搭配 `class_weight='balanced'` 是文獻常見折衷。

## Class imbalance 處理

實際 base rate 約 0.01%–0.1% malicious。MeMPtec (WWW 2024) 與 MalGuard (USENIX Security 2025) 的共同做法：**不做合成過採樣（SMOTE 在稀疏 metadata 特徵上幾乎都有害），而是用 class weight + 精挑過採樣比例**。

SMOTE 在 metadata 特徵（很多 binary flag、name 字串 embedding）上會產生「不存在的 package」，產生 overfitting 風險（被 Imbalance Datasets in Malware Detection 2025 review 與 TESSERACT 論文都點名）。

建議先試、依此順序：

```python
from sklearn.utils.class_weight import compute_class_weight
from sklearn.ensemble import GradientBoostingClassifier
import numpy as np

cw = compute_class_weight("balanced", classes=np.array([0, 1]), y=y_train)
# 等價 dict：{0: w_benign, 1: w_malicious}
clf = GradientBoostingClassifier()  # 或 LightGBM scale_pos_weight=cw[1]/cw[0]
clf.fit(X_train, y_train, sample_weight=np.where(y_train == 1, cw[1], cw[0]))
```

若要試 resampling，選 **under-sample benign** 而非 SMOTE over-sample malicious：

```python
from imblearn.under_sampling import RandomUnderSampler
X_res, y_res = RandomUnderSampler(sampling_strategy=0.2, random_state=42).fit_resample(X_train, y_train)
# 留下 1 malicious : 5 benign，保留多樣性但降低 imbalance
```

**絕對不要** 在 val/test 上 resample。只對 train fold 動手。評估時用 PR-AUC（不是 ROC-AUC）和 **fixed-precision recall**（例如 precision=0.99 下的 recall），這才符合 CI/CD 場景。

## Train/val/test split 協議

TESSERACT (USENIX Security 2019, Pendlebury et al.) 已經把這問題寫成定論：**random split 會嚴重高估 malware classifier 的真實表現**，來源包括 temporal bias（未來 leak 到過去）與 spatial bias（test 集 malicious 比例失真）。

**強制採用時序切分**：

```python
# 假設 df 有 'published_at' (datetime) 與 'label' (0/1)
df = df.sort_values("published_at")
# 三個固定 cutoff
train = df[df.published_at <  "2024-01-01"]
val   = df[(df.published_at >= "2024-01-01") & (df.published_at < "2024-07-01")]
test  = df[df.published_at >= "2024-07-01"]

# 關鍵 invariant：test 集裡沒有任何 package name 曾出現在 train（across versions）
train_names = set(train["name"])
test = test[~test["name"].isin(train_names)]
val  = val[~val["name"].isin(train_names)]
```

另加兩條規則：
1. **Spatial ratio invariant**：val 與 test 內部保持接近真實 base rate（例如 1:100 benign），否則 precision 會被灌水。TESSERACT 稱為 `phi` 參數。
2. **AUT metric**：報告時間衰減，不只報單點 F1。`AUT = (1/T) Σ F1_t`，T 為月數。

對 aigate：建議 cutoff 以「aigate release v1.0 發佈前 3 個月」為 test boundary，並每季重新 rolling 評估 drift。

## 大量 metadata 抓取 (rate-limit-safe)

**PyPI**：三條路徑，優先序：
1. **BigQuery `bigquery-public-data.pypi.distribution_metadata`** — 核心 METADATA 欄位（name、version、author、requires_dist、upload_time、size、digests）都有，一次 SQL 全撈，免費層 1 TiB/月。
   ```sql
   SELECT name, version, author, author_email, home_page, upload_time, summary
   FROM `bigquery-public-data.pypi.distribution_metadata`
   WHERE upload_time < '2024-01-01'
   ```
2. **ecosyste.ms open-data dumps** — CC-BY，npm/PyPI/RubyGems metadata dump 可直接下載 parquet；API 限 5000 req/hr，dump 免費。
3. **PyPI JSON API** `https://pypi.org/pypi/<name>/json` — 只有當 BigQuery/ecosyste.ms 欄位不足時才補抓，加 `If-Modified-Since` header 並 cache。

**npm**：
1. **CouchDB replication** 是官方建議方式：`https://replicate.npmjs.com/_all_docs` 或 `_changes?feed=continuous&include_docs=true`。`registry.npmjs.org/<pkg>` 的 crawler policy 禁止大規模抓取，**用 replicate endpoint 才合法**。
   ```python
   import httpx
   # 初次 bulk（約幾小時）：
   r = httpx.get("https://replicate.npmjs.com/_all_docs?include_docs=true&limit=10000&skip=0")
   # 之後 incremental：
   r = httpx.get(f"https://replicate.npmjs.com/_changes?since={seq}&include_docs=true")
   ```
2. **Libraries.io Zenodo dump** (DOI 10.5281/zenodo.3626071) — CC-BY-SA-4.0，5 GB 壓縮 / 25 GB 解開，含 36 個 registry，適合建立一次性的 historical snapshot。**注意 SA 條款**：衍生 dataset 若再散布要保持相同授權。

## Deduplication

Typosquat 家族是最大汙染源。`requests` 的 `reqeusts` / `requesets` / `requersts` / `requests2` / `python-requests` 等在 OSSF 裡常各有數十筆，若不 dedup 會讓模型只學「Levenshtein 距離近 = 惡意」這種 shortcut。

實務三層 dedup：

1. **Exact code hash**：對 Datadog/pypi_malregistry 的 source code，算 SHA-256 after normalization（strip whitespace + comments）。完全重複的 campaign 批次只保一筆。
2. **Name family cluster**：對所有 malicious package name 做 Levenshtein / edit-ratio clustering（例如 `rapidfuzz` cluster with threshold 0.85），每個 cluster 內 train 時只抽 sample，避免資料集被單一 typosquat campaign 主導。
   ```python
   from rapidfuzz import fuzz, process
   import networkx as nx
   G = nx.Graph()
   for i, a in enumerate(names):
       for j, b in enumerate(names[i+1:], i+1):
           if fuzz.ratio(a, b) > 85:
               G.add_edge(a, b)
   clusters = list(nx.connected_components(G))
   # train 時每個 cluster 限額 (e.g., 最多 5 筆) 做 stratified sampling
   ```
3. **Behavior hash**（若有 source code）：對 AST 做 simhash，相同 obfuscation template 的變體歸為一家。MalGuard 論文用類似技巧將 ~10k 樣本縮成 ~2k 個 unique behavior families。

評估時報告兩套數字：`per-package F1` 與 `per-family F1`，後者才反映真實泛化能力。

## 建議的 aigate 最小可行訓練集

**v0.1 階段**（metadata-only, PyPI + npm 雙 ecosystem）：

- **PyPI**：5,000 malicious（OSSF + Datadog + pypi_malregistry 三源交集後去重，取 2023-01 到 2024-06 之間）+ 50,000 benign（BigQuery top-downloaded，age > 2yr + active-within-6mo + repo sanity）
- **npm**：8,000 malicious（OSSF 扣除 2025 兩次巨量尖峰，取 2022–2024 穩定期）+ 80,000 benign（replicate.npmjs.com dump + download stats filter）
- **Split**：train < 2024-01-01，val 2024-01 到 2024-06，test > 2024-06（截至抓取日）
- **Dedup**：name-family cluster 限額 5 筆/cluster

Rationale：
- 10:1 ratio 足以在 class-weight balanced 下訓練出有用的 baseline，同時保留未來擴充空間。
- npm 2025 尖峰（`2025-08` 35k、`2025-11` 142k）疑似單一 campaign 或 bulk ingest 造成；納入會讓 val 分布嚴重偏斜。等拿到 v0.1 baseline 再決定要不要作為 adversarial test set。
- 5k/8k 的 malicious 數字也對齊 MeMPtec、MalGuard 論文的 corpus 規模，便於對比。

## 法律 / 授權注意事項

| 來源 | 可 bundle 進 aigate repo? | 動作 |
|---|---|---|
| OSSF malicious-packages | 可 (Apache-2.0) | 可把抽取好的 label table 放 `data/labels/ossf.parquet`，保留 NOTICE |
| Datadog dataset | 可 (Apache-2.0) | manifest.json 可 bundle，加密 ZIP 不必 bundle |
| pypi_malregistry | **不建議** redistribute（license 未明） | 僅在 training script 中 `git clone`，不打包 |
| GHSA | 可 (CC-BY-4.0) | 加 attribution 即可 |
| Libraries.io Zenodo | 可 (CC-BY-SA-4.0) | **SA 條款**：衍生 benign list 若散布需同授權 |
| ecosyste.ms | 可 (CC-BY-4.0) | 加 attribution |
| Snyk | **禁止** redistribute | 只能作內部驗證，ToS 禁止 bundle |
| Backstabber's Knife | 研究用，需申請 | 不 bundle、不在公開 pipeline 引用 |
| PyPI/npm 原始 registry | public domain metadata | 抓取需遵守 crawler policy（npm → 用 replicate endpoint） |

建議 aigate 採取 **「distribute labels, not payloads」** 策略：repo 裡只放 `(package_name, ecosystem, label, published_at, source)` tuple，實際 metadata/source 在 build 時由 script 從 upstream 抓，這樣既不觸碰授權邊界，也確保 dataset 可被第三方重新 bootstrap。

## Sources

- [OSSF malicious-packages repository](https://github.com/ossf/malicious-packages)
- [OSSF malicious packages statistics (all.json)](https://ossf.github.io/malicious-packages/stats/all.json)
- [OSV schema](https://ossf.github.io/osv-schema/)
- [Example OSV record MAL-2024-11183 (@solana/web3.js)](https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/@solana/web3.js/MAL-2024-11183.json)
- [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)
- [DataDog GuardDog](https://github.com/DataDog/guarddog)
- [pypi_malregistry (ASE 2023)](https://github.com/lxyeternal/pypi_malregistry)
- [An Empirical Study of Malicious Code In PyPI Ecosystem (ASE 2023)](https://lcwj3.github.io/img_cs/pdf/An%20Empirical%20Study%20of%20Malicious%20Code%20In%20PyPI%20Ecosystem.pdf)
- [GitHub Advisory Database (type:malware filter)](https://github.com/advisories?query=type%3Amalware)
- [github/advisory-database repo](https://github.com/github/advisory-database)
- [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/)
- [MeMPtec: Malicious Package Detection using Metadata Information (WWW 2024, arXiv)](https://arxiv.org/html/2402.07444)
- [MalGuard (USENIX Security 2025)](https://www.usenix.org/system/files/usenixsecurity25-gao-xingan.pdf)
- [TESSERACT (USENIX Security 2019, extended)](https://arxiv.org/html/2402.01359v1)
- [Breaking Out from the TESSERACT (2025)](https://arxiv.org/html/2506.23814v1)
- [Imbalance Datasets in Malware Detection review 2025](https://thesai.org/Downloads/Volume16No1/Paper_126-Imbalance_Datasets_in_Malware_Detection.pdf)
- [BigQuery PyPI dataset (PyPI docs)](https://docs.pypi.org/api/bigquery/)
- [Analyzing PyPI package downloads (packaging.python.org)](https://packaging.python.org/guides/analyzing-pypi-package-downloads/)
- [npm REPLICATE-API docs](https://github.com/npm/registry/blob/main/docs/REPLICATE-API.md)
- [npm crawler policy](https://docs.npmjs.com/policies/crawlers/)
- [Libraries.io Zenodo dump (DOI 10.5281/zenodo.3626071)](https://zenodo.org/records/3626071)
- [ecosyste.ms open data releases](https://packages.ecosyste.ms/open-data)
- [GuardDog 2.0 release notes](https://securitylabs.datadoghq.com/articles/guarddog-2-0-release/)
- [SafeDep: Analysis of 5000+ Malicious Open Source Packages (using Datadog dataset)](https://safedep.io/malysis-evaluation-using-datadog-malicious-packages-dataset/)
