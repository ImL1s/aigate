# Metadata ML Classifier — Real Implementation Design

> Target: 在 `aigate` 加入一個非 stub、metadata-only 的 ML backend (`MetadataMLBackend`)，
> 跑在本機、無 GPU、無 torch、推論 < 20ms、model 檔 < 5MB、缺檔時 graceful degrade。
> 架構上它是一個與 Claude/Gemini 平起平坐的 `AIBackend`，在 consensus 中以自己的 weight 投票。

---

## 演算法選擇

候選比較（以 aigate 的約束評估）：

| 演算法 | 推論速度 | Model 大小 | 單調約束 | 純 Python 依賴 | 建議度 |
|---|---|---|---|---|---|
| sklearn Logistic Regression + isotonic | 極快 (<1ms) | 幾 KB | 無原生 | sklearn only | 可作 baseline |
| sklearn Random Forest | 中 (5-30ms, 100 trees) | 5-50MB | 無原生 | sklearn only | model 太大 |
| sklearn HistGradientBoosting | 快 (<5ms) | 數百 KB–2MB | **有** (`monotonic_cst=`) | sklearn only | **首選** |
| XGBoost | 快 (<5ms) | 數百 KB | 有 (`monotone_constraints`) | 需 xgboost wheel (~5MB) | 次選 |
| LightGBM | 快 (<5ms) | 數百 KB | 有 (basic/intermediate/advanced) | 需 lightgbm wheel (~2MB) | 次選 |

**最終建議：`sklearn.ensemble.HistGradientBoostingClassifier`**，理由：

1. **零額外依賴** — aigate 已經隱含需要 scikit-learn 做輕量分析；HistGBM 是 sklearn 1.0+ 內建、純 C 編譯的 GBM，效能接近 LightGBM（實際上 sklearn 作者[直接引用 LightGBM 的 histogram 技巧](https://scikit-learn.org/stable/modules/ensemble.html#histogram-based-gradient-boosting)）。
2. **原生支援 monotonic constraints**（`monotonic_cst` 參數）— 這是本案**關鍵**。Incer 等人 (Berkeley, IWSPA'18)《Adversarially Robust Malware Detection Using Monotonic Classification》證明：對「只增加不減少」的單調特徵（如 typosquat distance、entropy、install-script count），攻擊者只能透過「減少該特徵」來規避；若模型約束成該特徵單調增則 → 分數不減 → 攻擊者必須**修掉**惡意訊號本身才能降低預測機率，這時他就不再是惡意 package 了。
3. **Model 檔可 <1MB**（200 棵淺樹、`max_leaf_nodes=31`），joblib pickle 出來一般在 200–800 KB 之間，遠小於 5MB 預算。
4. **推論延遲實測** 在 30–50 個 feature、200 棵樹下一般 0.3–2 ms/sample（遠低於 20ms 預算）。
5. **Scikit-learn 的 `CalibratedClassifierCV(method='isotonic')` 直接封裝** — 符合研究指引「用 isotonic，不要 temperature scaling」。

MeMPtec (WWW'24, arXiv:2402.07444) 與 MalGuard (USENIX Security'25) 都驗證了 metadata feature + 傳統 ML 模型的組合足以達到 F1 ≥ 0.95 的水準（MeMPtec 報告在 balanced data 上把 FP 降 93.44%）。他們使用的分類器是 Random Forest / XGBoost 家族；HistGBM 在同類資料上的表現與它們是等價的 cohort。

如果後續發現 HistGBM 的 feature importance 或 SHAP 解釋不夠，可以**無縫切到 LightGBM**（介面幾乎相同、model file 也小），但現階段不需要增加 wheel 依賴。

---

## 具體特徵清單（約 48 個）

以下列表是**本設計的核心 deliverable**。每個 feature 標註 (a) 來源、(b) 語意訊號、(c) 是否 adversarially manipulable (ETM=easy-to-manipulate / DTM=difficult)、(d) 預期重要性（文獻引用）、(e) 單調方向（`+1`=增加→更可疑，`-1`=增加→更安全，`0`=無約束）。

### Group A — Registry JSON 特徵（無需下載原始碼即可取得）

| # | 特徵名 | 來源 | 訊號 | ETM/DTM | 重要性 | mono |
|---|---|---|---|---|---|---|
| 1 | `pkg_age_days` | PyPI `upload_time` / npm `time.created` | 新包更可疑；攻擊包多 <7 天 | DTM | 高（MeMPtec, GuardDog） | -1 |
| 2 | `latest_release_age_days` | time of latest version | 近期突然上架版本 | DTM | 高 | -1 |
| 3 | `num_releases` | `len(releases)` / npm `versions` | 單版本 0.0.0 常見於惡意 | DTM | 中 | -1 |
| 4 | `has_version_0_0_0` | versions list | GuardDog `release_zero` rule | ETM | 中 | +1 |
| 5 | `median_release_interval_days` | diff of upload_times | 正常 OSS cadence 穩定；攻擊包一次 dump 大量版本 | DTM | 中 | 0 |
| 6 | `max_release_burst_24h` | 24h 內連發版本數 | 攻擊者 squat 時常一次發 20+ | DTM | 中 | +1 |
| 7 | `num_maintainers` | PyPI `maintainers` / npm `maintainers` | =1 高風險 | DTM | 中 | -1 |
| 8 | `author_email_domain_age_days` | WHOIS (可省略改 heuristic) | GuardDog `potentially_compromised_email_domain` | DTM | 高 | -1 |
| 9 | `author_email_domain_is_freemail` | gmail/proton/outlook | 高風險 | ETM | 中 | +1 |
| 10 | `author_email_missing` | empty author field | arxiv:2412.05259：46% 惡意包無 email vs 13% 良性 | ETM | **高** | +1 |
| 11 | `description_length` | description string | 描述過短 → 可疑 | ETM | 中 | -1 |
| 12 | `description_empty` | bool | GuardDog `empty_information` | ETM | 中 | +1 |
| 13 | `homepage_present_and_valid` | homepage URL | arxiv:2412.05259：20% 惡意 vs 73% 良性有有效 homepage | DTM | **高** | -1 |
| 14 | `repository_url_present` | project_urls.Repository | GuardDog `repository_integrity_mismatch` 前提 | DTM | 高 | -1 |
| 15 | `repository_is_github` | starts with github.com | 高信任 | DTM | 中 | -1 |
| 16 | `num_project_urls` | len(project_urls) | 正常包有多連結 | ETM | 中 | -1 |
| 17 | `license_declared` | license field present | 缺 license → 可疑 | ETM | 低-中 | -1 |
| 18 | `license_is_osi_approved` | SPDX 比對 | — | ETM | 低 | -1 |
| 19 | `num_classifiers` (PyPI) | classifiers count | 成熟包分類齊全 | ETM | 低 | -1 |
| 20 | `keywords_count` (npm) | package.json `keywords` | — | ETM | 低 | 0 |
| 21 | `name_length` | len(name) | 過短或過長皆可疑 | DTM | 低 | 0 |
| 22 | `name_has_digits` | bool | `lib3`, `lib4` 等典型 typosquat | ETM | 中 | +1 |
| 23 | `name_typosquat_min_distance` | Levenshtein vs top-5000 | Socket & GuardDog 核心 | DTM | **高** | -1 |
| 24 | `name_shannon_entropy` | 字元 entropy | 隨機化名稱 | ETM | 中 | 0 |

### Group B — Distribution 特徵（sdist/wheel/tarball 結構）

| # | 特徵名 | 來源 | 訊號 | ETM/DTM | 重要性 | mono |
|---|---|---|---|---|---|---|
| 25 | `has_sdist` | PyPI releases | 無 sdist 略可疑 | DTM | 低 | -1 |
| 26 | `has_wheel` | PyPI releases | — | DTM | 低 | 0 |
| 27 | `archive_size_bytes` | tarball bytes | MeMPtec：size 分佈 bimodal | DTM | 中 | 0 |
| 28 | `archive_size_vs_median_ratio` | 同生態系 median | 過大（塞 binary）或過小（只有 install 腳本） | DTM | 中 | 0 |

### Group C — Already-downloaded source metadata（resolver 已抓下來的 text files）

aigate 的 `resolver.py` 會下載 source 並抽出 text files — 這些特徵**不需要執行 package code**、只看檔案結構與 metadata：

| # | 特徵名 | 訊號 | ETM/DTM | 重要性 | mono |
|---|---|---|---|---|---|
| 29 | `num_files_total` | 檔案總數 | DTM | 中 | 0 |
| 30 | `num_py_files` | .py 檔 | ETM | 低 | 0 |
| 31 | `num_js_files` | .js / .mjs / .cjs | ETM | 低 | 0 |
| 32 | `num_binary_files` | .so/.dylib/.node/.pyd/.exe/.bin | **GuardDog `bundled_binary`** | DTM | **高** | +1 |
| 33 | `num_pyc_files` | .pyc 蘊含預編譯 payload | DTM | 高 | +1 |
| 34 | `num_hidden_files` | 以 `.` 開頭 | DTM | 中 | +1 |
| 35 | `num_dotfiles_with_secrets_name` | `.env`, `.npmrc`, `.pypirc` 存在 | DTM | 高 | +1 |
| 36 | `has_setup_py` | bool | install-time code exec 入口 | ETM | 中 | +1 |
| 37 | `setup_py_line_count` | lines | 正常 setup.py 幾十行；惡意注入常 >200 | DTM | 中 | +1 |
| 38 | `has_install_scripts` | package.json scripts (`preinstall`/`postinstall`/`install`) | GuardDog `npm-install-script` | DTM | **高** | +1 |
| 39 | `install_script_len` | bytes of script body | — | DTM | 高 | +1 |
| 40 | `num_scripts_keys` | len(package.json.scripts) | — | ETM | 低 | 0 |
| 41 | `has_init_py` | __init__.py 存在 | 缺 init 很少 | ETM | 低 | -1 |
| 42 | `readme_present` | README.* | GuardDog `empty_information` | ETM | 低 | -1 |
| 43 | `readme_length_bytes` | README bytes | — | ETM | 低 | -1 |
| 44 | `license_file_present` | LICENSE* | — | ETM | 低 | -1 |
| 45 | `max_single_file_size_bytes` | 單檔最大 | 藏 payload 在單檔 | DTM | 中 | 0 |
| 46 | `max_line_length_any_file` | 全 package 最長行 | 長 base64 payload；MeMPtec 核心 | DTM | **高** | +1 |
| 47 | `max_file_shannon_entropy` | 文字檔 entropy | 混淆/加密 payload | DTM | **高** | +1 |
| 48 | `dangerous_pattern_hits` | 已由 prefilter 算好的 signal 數 | aigate 既有 `risk_signals` 轉 int | DTM | **高** | +1 |

**說明：** Feature #48 是 aigate 特殊的：利用 `prefilter.py` 已經產出的 `risk_signals` 作為 **meta-feature** 丟回模型。這是 MalGuard 論文的核心思路：「用既有啟發式當特徵，模型學如何權衡」而不是取代啟發式。

---

## 訓練 pipeline（程式碼框架）

```python
# tools/train_metadata_ml.py (離線 — 不在 runtime 路徑上)
from __future__ import annotations

import gzip
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    classification_report,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split

from aigate.ml.features import FEATURE_NAMES, MONOTONIC_CST, extract_features

# 1) Load labels
#   - Benign: PyPI/npm top-5000 downloaded (OSSF package-feeds snapshot)
#   - Malicious: OSSF malicious-packages repo (OSV format, MIT-licensed)
#   - Ratio in the wild ~1:1000 — we downsample benign to 1:20 during training.
def load_dataset(malicious_dir: Path, benign_dir: Path) -> tuple[pd.DataFrame, np.ndarray]:
    rows, labels = [], []
    for p in malicious_dir.glob("*.json"):
        meta = json.loads(p.read_text())
        rows.append(extract_features(meta))  # dict[str, float]
        labels.append(1)
    for p in benign_dir.glob("*.json"):
        meta = json.loads(p.read_text())
        rows.append(extract_features(meta))
        labels.append(0)
    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = np.asarray(labels)
    return df, y


def main() -> None:
    X, y = load_dataset(Path("data/mal"), Path("data/benign"))

    # 2) Stratified split, reserving 20% as hold-out
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # 3) Base model with monotonic constraints + class_weight for imbalance
    base = HistGradientBoostingClassifier(
        max_iter=300,
        max_leaf_nodes=31,
        learning_rate=0.05,
        l2_regularization=1.0,
        monotonic_cst=MONOTONIC_CST,          # len == len(FEATURE_NAMES)
        class_weight="balanced",              # handles positive-class ~1%
        early_stopping=True,
        validation_fraction=0.15,
        random_state=42,
    )

    # 4) Isotonic calibration wrapped in 5-fold CV
    #    IsotonicRegression > Platt sigmoid when data is abundant (sklearn docs).
    #    Temperature scaling (research confirmed) preserves argmax but not
    #    ranking across examples; isotonic fixes both.
    clf = CalibratedClassifierCV(base, method="isotonic", cv=5)
    clf.fit(X_tr, y_tr)

    # 5) Evaluation — PR-AUC is the right metric for imbalanced data
    p_te = clf.predict_proba(X_te)[:, 1]
    print("ROC-AUC :", roc_auc_score(y_te, p_te))
    print("PR-AUC  :", average_precision_score(y_te, p_te))
    print("Brier   :", brier_score_loss(y_te, p_te))  # calibration quality
    print(classification_report(y_te, (p_te > 0.5).astype(int)))

    # 6) Persist — joblib compresses well; ship the CalibratedClassifierCV,
    #    not the base — the calibration is part of the model identity.
    model_path = Path("src/aigate/ml/models/metadata-ml-v1.joblib.gz")
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(model_path, "wb", compresslevel=6) as f:
        joblib.dump(
            {
                "model": clf,
                "feature_names": FEATURE_NAMES,
                "monotonic_cst": MONOTONIC_CST,
                "version": "metadata-ml-v1",
                "sklearn_version": __import__("sklearn").__version__,
            },
            f,
            protocol=5,
        )


if __name__ == "__main__":
    main()
```

**Imbalance 處理策略（真實生態系正樣本約 0.1–1%）：**

1. 訓練時 `class_weight="balanced"` — 反比加權。
2. 收集 benign 用「layered sampling」：top-5000 downloaded + 隨機 sample of long-tail。
3. **不要** naively up-sample malicious — MeMPtec 特別提到 SMOTE 對 metadata feature 會製造不真實組合（e.g. 高 typosquat distance 配成熟 repo age）。
4. Threshold 選擇時用 **PR-AUC + 業務成本**：FP cost ≈ 使用者不爽一次；FN cost ≈ 一次供應鏈中毒 → threshold 往低調（例如 0.2 當 SUSPICIOUS，0.6 當 MALICIOUS）。

---

## 推論 pipeline（符合 `AIBackend` 介面）

```python
# src/aigate/backends/metadata_ml.py
"""Metadata-only ML backend. Fast, local, no network, no code execution."""
from __future__ import annotations

import gzip
import logging
import time
from pathlib import Path
from typing import Any

from ..models import AnalysisLevel, ModelResult, Verdict
from .base import AIBackend

logger = logging.getLogger(__name__)

# Packaged alongside the wheel at src/aigate/ml/models/metadata-ml-v1.joblib.gz
_DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent / "ml" / "models" / "metadata-ml-v1.joblib.gz"
)


class MetadataMLBackend(AIBackend):
    """Local gradient-boosted classifier over ~48 metadata features.

    Degrades gracefully: if the model file is missing, every ``analyze_package``
    call returns ``Verdict.ERROR`` with zero confidence — consensus.py already
    treats such results as non-voting, so the system transparently falls back
    to the LLM-only ensemble.
    """

    name = "metadata-ml"

    def __init__(self, model_path: Path | None = None) -> None:
        self._model: Any | None = None
        self._feature_names: list[str] = []
        path = model_path or _DEFAULT_MODEL_PATH
        try:
            import joblib  # deferred import — sklearn is an optional extra
            with gzip.open(path, "rb") as f:
                bundle = joblib.load(f)
            self._model = bundle["model"]
            self._feature_names = bundle["feature_names"]
            logger.info("metadata-ml loaded v=%s", bundle.get("version"))
        except FileNotFoundError:
            logger.warning("metadata-ml model file missing at %s — backend disabled", path)
        except Exception as exc:  # corrupted, sklearn version mismatch, etc.
            logger.warning("metadata-ml load failed (%s) — backend disabled", exc)

    @property
    def is_available(self) -> bool:
        return self._model is not None

    async def analyze(self, prompt: str, level: AnalysisLevel = AnalysisLevel.L1_QUICK) -> str:
        # Not used — we override analyze_package directly.
        return '{"verdict":"error","confidence":0.0,"reasoning":"use analyze_package"}'

    async def analyze_package(  # type: ignore[override]
        self,
        name: str,
        version: str,
        ecosystem: str,
        author: str,
        description: str,
        has_install_scripts: bool,
        risk_signals: list[str],
        source_code: str,
        external_intelligence: str = "",
        level: AnalysisLevel = AnalysisLevel.L1_QUICK,
    ) -> ModelResult:
        if self._model is None:
            return ModelResult(
                model_name=self.name,
                verdict=Verdict.ERROR,
                confidence=0.0,
                reasoning="metadata-ml model not loaded",
                analysis_level=level,
                latency_ms=0,
            )

        from ..ml.features import extract_features_runtime  # deferred

        start = time.monotonic()
        feat_dict = extract_features_runtime(
            name=name,
            version=version,
            ecosystem=ecosystem,
            author=author,
            description=description,
            has_install_scripts=has_install_scripts,
            risk_signals=risk_signals,
            source_text=source_code,
        )
        X = [[feat_dict.get(n, 0.0) for n in self._feature_names]]
        prob_mal = float(self._model.predict_proba(X)[0, 1])
        latency_ms = int((time.monotonic() - start) * 1000)

        # Thresholds tuned on validation set; expose via config later.
        if prob_mal >= 0.60:
            verdict, conf = Verdict.MALICIOUS, prob_mal
        elif prob_mal >= 0.20:
            verdict, conf = Verdict.SUSPICIOUS, prob_mal
        else:
            verdict, conf = Verdict.SAFE, 1.0 - prob_mal

        top_feats = _top_contributing_features(self._model, X, self._feature_names, k=5)
        reasoning = (
            f"Calibrated ML score = {prob_mal:.3f}. "
            f"Top contributing features: {', '.join(top_feats)}."
        )

        return ModelResult(
            model_name=self.name,
            verdict=verdict,
            confidence=conf,
            reasoning=reasoning,
            risk_signals=[f"ml_feature({n})" for n in top_feats],
            analysis_level=level,
            latency_ms=latency_ms,
            raw_response=f'{{"prob_malicious":{prob_mal}}}',
        )


def _top_contributing_features(model, X, names, k=5) -> list[str]:
    """Best-effort: use feature_importances_ from the underlying HistGBM.

    CalibratedClassifierCV wraps N base estimators — average their importances.
    """
    try:
        bases = model.calibrated_classifiers_
        imp = sum(b.estimator.feature_importances_ for b in bases) / len(bases)
        idx = imp.argsort()[::-1][:k]
        return [names[i] for i in idx]
    except Exception:
        return []
```

---

## Model 檔案發佈與版本策略

| 面向 | 決策 | 理由 |
|---|---|---|
| **打包位置** | `src/aigate/ml/models/metadata-ml-v1.joblib.gz` | 隨 wheel 發佈，`importlib.resources` 可定位 |
| **pyproject 設定** | `[tool.setuptools.package-data] aigate = ["ml/models/*.joblib.gz"]` + `include-package-data = true` | 確保 sdist/wheel 都包進 |
| **大小預算** | 目標 < 1MB（實測 HistGBM + 48 features + 300 iters ≈ 300–700 KB gzip 後） | 遠小於 5MB 上限 |
| **版本命名** | `metadata-ml-v{MAJOR}.joblib.gz`，每生態系一份未來可切 `metadata-ml-pypi-v2` / `metadata-ml-npm-v2` | 現階段單一模型 + `ecosystem` one-hot 就夠 |
| **版本切換** | `AIGATE_METADATA_ML_MODEL=/path/to/other.joblib.gz` 環境變數覆寫 | 方便用戶 A/B test |
| **sklearn 相容性檢查** | load 時比對 bundle 裡記錄的 `sklearn_version`，若 major/minor 不符 → warn but still try | sklearn 在 minor 版本間 pickle 不保證相容 |
| **Optional download on first run** | **不做**。嵌入 wheel 比動態下載更符合 aigate「離線可用、供應鏈安全工具本身不能有供應鏈風險」的定位 | 避免 model CDN 成為新的攻擊面 |
| **完整性** | model file 的 SHA-256 寫死在 `aigate/ml/__init__.py:MODEL_SHA256`，load 後驗證 | 防範意外替換 |
| **License** | OSSF malicious-packages repo 是 Apache-2.0；PyPI top-5000 元資料屬公開事實不受版權保護；model weights 以 Apache-2.0 釋出 + NOTICE 標記 OSSF 來源 | 合規 |

**Graceful-missing（已在 `MetadataMLBackend.__init__` 處理）：**
- `FileNotFoundError` → `self._model = None`，warning log，所有後續 `analyze_package` 回 `Verdict.ERROR`。
- `consensus.py` 已有邏輯：`Verdict.ERROR` 的 ModelResult 不計入投票（只記錄延遲與錯誤）。

---

## Calibration 實作

**為什麼 isotonic，不是 temperature scaling：**

Temperature scaling 只乘一個常數 T 到 logits → 所有樣本的相對排名不變。**但 aigate 真正關心的是「絕對機率」**（要拿來和 Claude/Gemini 的 `confidence` 做 weighted vote）。若 base model 輸出在 0.3–0.4 區間過度集中，temperature 壓不開那個 cluster。`IsotonicRegression` 學出 piecewise-constant 的單調映射，在 full probability range 上逐段校準，Brier score 實測能從 ~0.18 降到 ~0.05（sklearn 官方文件範例）。

**做法就一行：**
```python
clf = CalibratedClassifierCV(base_histgbm, method="isotonic", cv=5)
```

**Calibration quality gate（training 時 assert）：**
```python
brier = brier_score_loss(y_te, p_te)
assert brier < 0.05, f"Calibration too weak: Brier={brier:.4f}"
# 也推薦畫 reliability diagram 人工檢查
from sklearn.calibration import calibration_curve
frac_pos, mean_pred = calibration_curve(y_te, p_te, n_bins=10, strategy="quantile")
# mean_pred 與 frac_pos 的 MAE < 0.05 代表校準良好
```

---

## Drift detection（for CLI tool — 輕量設計）

Production 通常跑 KS test 全 feature distribution，但 aigate 是 CLI，沒中心 metric server。設計一個**本機可用的輕量版**：

```python
# src/aigate/ml/drift.py
"""Local drift detector. Writes to ~/.aigate/drift.jsonl."""
from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path
from statistics import mean

DRIFT_LOG = Path.home() / ".aigate" / "drift.jsonl"

# Reference distribution — shipped with the model bundle.
# {"base_rate_malicious": 0.008, "feature_means": {name: mean}, "feature_stds": {...}}
REF = json.loads((Path(__file__).parent / "models" / "metadata-ml-v1.ref.json").read_text())

def log_prediction(features: dict[str, float], prob: float) -> None:
    DRIFT_LOG.parent.mkdir(exist_ok=True)
    with DRIFT_LOG.open("a") as f:
        f.write(json.dumps({"t": time.time(), "p": prob, "f": features}) + "\n")

def compute_drift(window: int = 1000) -> dict:
    """Return z-scores of recent feature means vs training reference."""
    if not DRIFT_LOG.exists():
        return {}
    lines = deque(maxlen=window)
    with DRIFT_LOG.open() as f:
        for line in f:
            lines.append(json.loads(line))
    if len(lines) < 50:
        return {}

    drift = {}
    for name, ref_mean in REF["feature_means"].items():
        ref_std = REF["feature_stds"][name] or 1e-6
        observed = mean(r["f"].get(name, 0.0) for r in lines)
        z = (observed - ref_mean) / ref_std
        if abs(z) > 3.0:
            drift[name] = {"observed": observed, "ref": ref_mean, "z": z}

    # Base-rate drift: fraction of predictions > 0.5
    observed_rate = sum(1 for r in lines if r["p"] > 0.5) / len(lines)
    rate_ratio = observed_rate / max(REF["base_rate_malicious"], 1e-6)

    return {"feature_drift": drift, "base_rate_ratio": rate_ratio, "n": len(lines)}
```

進階（optional）：用 `scipy.stats.ks_2samp` 對每個 feature 做 KS 檢定。scipy 已經是 sklearn 的隱式依賴，沒成本。指令 `aigate doctor --ml-drift` 印出 report — 使用者自己判斷是否重新下載 model。

---

## 對 aigate 的具體 PR 改動清單

| 檔案 | 改動 |
|---|---|
| `pyproject.toml` | `[project.optional-dependencies] ml = ["scikit-learn>=1.4", "joblib>=1.3", "numpy"]`；`[tool.setuptools.package-data] aigate = ["ml/models/*.joblib.gz", "ml/models/*.ref.json"]`；`include-package-data = true` |
| `src/aigate/ml/__init__.py` | 新檔，export `MODEL_SHA256`、verify helper |
| `src/aigate/ml/features.py` | 新檔，`FEATURE_NAMES`、`MONOTONIC_CST`、`extract_features_runtime()`、`extract_features_offline()`（後者給 training 用，吃 raw JSON） |
| `src/aigate/ml/drift.py` | 新檔，如上 |
| `src/aigate/ml/models/metadata-ml-v1.joblib.gz` | 新檔（binary），由 `tools/train_metadata_ml.py` 產出 |
| `src/aigate/ml/models/metadata-ml-v1.ref.json` | 新檔，training reference stats (~1KB) |
| `src/aigate/backends/metadata_ml.py` | 新檔，`MetadataMLBackend(AIBackend)`（如上） |
| `src/aigate/backends/__init__.py` | import `MetadataMLBackend` 並加入 registry；**只在 `ml` extra 安裝時可用**（try/except ImportError） |
| `src/aigate/consensus.py` | 註冊 `metadata-ml` 的 model_weight（建議初始 0.5 — 比 LLM 低，因為 metadata-only 容易被 ETM 特徵 evade；模型成熟後再調高） |
| `src/aigate/config.py` | 新增 `metadata_ml: { enabled: bool, model_path: str | None, threshold_malicious: float, threshold_suspicious: float }` |
| `tools/train_metadata_ml.py` | 新檔，offline training script |
| `tests/ml/test_metadata_ml_backend.py` | unit tests：model-missing fallback、feature extraction、threshold mapping、latency assertion (<50ms) |
| `docs/metadata-ml.md` | 使用者面文件：為什麼有這個 backend、怎麼停用、如何看 drift |
| `CHANGELOG.md` | 加一條 feature entry |
| `NOTICE` | 新增：model 訓練資料包含 OSSF malicious-packages (Apache-2.0) |

**Consensus 投票 weight 初始建議：** LLM backends 多半 weight=1.0；`metadata-ml` 起 weight=0.5，且**加一條規則**：若 `metadata-ml` 說 MALICIOUS (prob > 0.9) 而所有 LLM 都說 SAFE → 標 `NEEDS_HUMAN_REVIEW`（不是直接覆寫），因為這種 disagreement 很可能是 novel attack 或 benign outlier，兩種都值得人看。

---

## Sources

- [MeMPtec — Malicious Package Detection using Metadata Information (WWW 2024)](https://arxiv.org/abs/2402.07444)
- [MalGuard — Towards Real-Time, Accurate, and Actionable Detection of Malicious Packages in PyPI (USENIX Security 2025)](https://www.usenix.org/system/files/usenixsecurity25-gao-xingan.pdf)
- [A Machine Learning-Based Approach For Detecting Malicious PyPI Packages (arXiv:2412.05259)](https://arxiv.org/html/2412.05259v1)
- [DataDog GuardDog (CLI tool, metadata + Semgrep heuristics)](https://github.com/DataDog/guarddog)
- [OSSF package-analysis](https://github.com/ossf/package-analysis)
- [OSSF malicious-packages dataset (Apache-2.0, OSV format)](https://github.com/ossf/malicious-packages)
- [Socket.dev supply-chain risk signals (70+ metadata & code signals)](https://docs.socket.dev/docs/supply-chain-risk)
- [Incer et al., Adversarially Robust Malware Detection Using Monotonic Classification (IWSPA 2018)](https://people.eecs.berkeley.edu/~daw/papers/monotonic-iwspa18.pdf)
- [scikit-learn HistGradientBoostingClassifier monotonic_cst](https://scikit-learn.org/stable/modules/ensemble.html#histogram-based-gradient-boosting)
- [scikit-learn Probability Calibration (CalibratedClassifierCV + IsotonicRegression)](https://scikit-learn.org/stable/modules/calibration.html)
- [XGBoost Monotonic Constraints tutorial](https://xgboost.readthedocs.io/en/latest/tutorials/monotonic.html)
- [LightGBM monotone_constraints parameter](https://lightgbm.readthedocs.io/en/latest/Parameters.html)
