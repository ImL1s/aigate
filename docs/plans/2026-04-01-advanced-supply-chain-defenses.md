# Advanced Supply Chain Defenses Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 4 practical defense layers inspired by 2026 state-of-art: dependency cooldown gate, provenance risk signals, install-script safety recommendations, and package age/freshness checks.

**Architecture:** Each defense is a lightweight check added to the existing prefilter or enrichment pipeline. No new infrastructure — just new signals and CLI flags. The cooldown gate is the most impactful: it would have prevented the axios 1.14.1 attack (published and exploited within hours).

**Tech Stack:** Python 3.11+, httpx (existing), PyPI/npm registry APIs.

**Research basis:**
- [pip v26 `--uploaded-prior-to`](https://ichard26.github.io/blog/2026/01/whats-new-in-pip-26.0/)
- [Dependency cooldown movement](https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down.html)
- [npm provenance + Sigstore](https://docs.npmjs.com/generating-provenance-statements/)
- [PyPI attestations](https://blog.deps.dev/pypi-attestations/)
- [Deno install sandbox model](https://deno.com/blog/deno-protects-npm-exploits)
- [CodeHunter Behavioral Intent Profiles](https://www.helpnetsecurity.com/2026/02/11/codehunter-behavioral-malware-analysis/)

---

## Task 1: Package Freshness Check (Age Signal)

A package published in the last 24-72 hours is statistically more likely to be malicious. This is the simplest and most effective new signal.

**Files:**
- Modify: `src/aigate/prefilter.py` (add freshness check)
- Modify: `src/aigate/resolver.py` (fetch publish date from registry)
- Test: `tests/unit/test_freshness.py`

**Step 1: Write failing test**

```python
# tests/unit/test_freshness.py
from aigate.prefilter import check_package_freshness

def test_package_published_today_flagged():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    result = check_package_freshness(now)
    assert len(result) > 0
    assert any("recently_published" in s for s in result)

def test_package_published_30_days_ago_safe():
    from datetime import datetime, timedelta, timezone
    old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    result = check_package_freshness(old)
    assert len(result) == 0

def test_package_published_3_days_ago_flagged():
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    result = check_package_freshness(recent, threshold_days=7)
    assert len(result) > 0

def test_no_publish_date_flagged():
    result = check_package_freshness("")
    assert any("no_publish_date" in s for s in result)
```

**Step 2: Implement**

```python
# In prefilter.py
def check_package_freshness(
    publish_date: str,
    threshold_days: int = 7,
) -> list[str]:
    """Flag packages published within threshold_days as suspicious."""
    signals = []
    if not publish_date:
        signals.append("no_publish_date: package has no publish date metadata")
        return signals
    try:
        from datetime import datetime, timezone
        pub = datetime.fromisoformat(publish_date.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - pub).days
        if age < threshold_days:
            signals.append(
                f"recently_published(MEDIUM): published {age} days ago "
                f"(threshold: {threshold_days} days)"
            )
    except (ValueError, TypeError):
        pass
    return signals
```

Wire into `run_prefilter()` after metadata checks.

**Step 3: Commit**

```bash
git commit -m "feat: add package freshness check — flag recently published packages"
```

---

## Task 2: Provenance Risk Signal

The provenance module already fetches attestation data. Wire it into the prefilter as a risk signal: no provenance = suspicious for popular packages.

**Files:**
- Modify: `src/aigate/prefilter.py` (add provenance signal)
- Modify: `src/aigate/models.py` (ensure ProvenanceInfo accessible)
- Test: `tests/unit/test_provenance_signal.py`

**Step 1: Write failing test**

```python
# tests/unit/test_provenance_signal.py
from aigate.prefilter import check_provenance_signal

def test_no_provenance_flagged():
    result = check_provenance_signal(attestation_count=0, has_provenance=False)
    assert any("no_provenance" in s for s in result)

def test_has_provenance_safe():
    result = check_provenance_signal(attestation_count=3, has_provenance=True)
    assert len(result) == 0

def test_provenance_available_but_not_verified():
    result = check_provenance_signal(attestation_count=1, has_provenance=True, verified=False)
    assert any("unverified_provenance" in s for s in result)
```

**Step 2: Implement**

```python
def check_provenance_signal(
    attestation_count: int = 0,
    has_provenance: bool = False,
    verified: bool | None = None,
) -> list[str]:
    """Flag packages without provenance attestation."""
    signals = []
    if not has_provenance and attestation_count == 0:
        signals.append(
            "no_provenance(LOW): no Sigstore/SLSA provenance attestation found"
        )
    elif has_provenance and verified is False:
        signals.append(
            "unverified_provenance(MEDIUM): provenance exists but verification failed"
        )
    return signals
```

Wire into `run_prefilter()` when enrichment data is available.

**Step 3: Commit**

```bash
git commit -m "feat: add provenance attestation risk signal"
```

---

## Task 3: Install Script Safety Recommendations

When aigate detects a package has install scripts (postinstall, setup.py with exec), recommend using `--ignore-scripts` or `--no-build-isolation`.

**Files:**
- Modify: `src/aigate/reporters/terminal.py` (add safety recommendation)
- Modify: `src/aigate/models.py` (add recommendation field to AnalysisReport)
- Test: `tests/unit/test_safety_recommendations.py`

**Step 1: Write failing test**

```python
# tests/unit/test_safety_recommendations.py
from aigate.prefilter import generate_safety_recommendations

def test_npm_with_install_scripts_recommends_ignore():
    recs = generate_safety_recommendations(
        ecosystem="npm", has_install_scripts=True, risk_signals=["has_install_scripts"]
    )
    assert any("--ignore-scripts" in r for r in recs)

def test_pypi_with_setup_py_exec_recommends_no_build():
    recs = generate_safety_recommendations(
        ecosystem="pypi", has_install_scripts=True,
        risk_signals=["dangerous_pattern(HIGH): exec in setup.py"]
    )
    assert any("--no-build-isolation" in r or "inspect setup.py" in r for r in recs)

def test_safe_package_no_recommendations():
    recs = generate_safety_recommendations(
        ecosystem="pypi", has_install_scripts=False, risk_signals=[]
    )
    assert len(recs) == 0

def test_cargo_with_build_rs_recommends_review():
    recs = generate_safety_recommendations(
        ecosystem="cargo", has_install_scripts=True, risk_signals=["has_install_scripts"]
    )
    assert any("build.rs" in r for r in recs)
```

**Step 2: Implement**

```python
def generate_safety_recommendations(
    ecosystem: str,
    has_install_scripts: bool,
    risk_signals: list[str],
) -> list[str]:
    """Generate actionable safety recommendations based on findings."""
    recs = []
    if not has_install_scripts and not risk_signals:
        return recs

    high_signals = [s for s in risk_signals if "HIGH" in s or "CRITICAL" in s]

    if ecosystem == "npm" and has_install_scripts:
        recs.append("Consider: npm install --ignore-scripts (disables postinstall)")
    elif ecosystem == "pypi" and high_signals:
        recs.append("Consider: inspect setup.py before installing")
        recs.append("Consider: pip install --no-build-isolation for sandboxed build")
    elif ecosystem == "cargo" and has_install_scripts:
        recs.append("Consider: review build.rs before building")

    if any("recently_published" in s for s in risk_signals):
        recs.append("Consider: wait 7 days before installing newly published packages")

    if any("no_provenance" in s for s in risk_signals):
        recs.append("Consider: prefer packages with Sigstore provenance attestation")

    return recs
```

Wire into terminal reporter output.

**Step 3: Commit**

```bash
git commit -m "feat: add safety recommendations for risky packages"
```

---

## Task 4: Dependency Cooldown Configuration

Add a `cooldown_days` config option. When set, aigate warns if a package version was published within that window. This is the single most effective defense against rapid-deploy attacks like axios 1.14.1.

**Files:**
- Modify: `src/aigate/config.py` (add `cooldown_days` field)
- Modify: `src/aigate/cli.py` (add `--cooldown` flag to check command)
- Modify: `src/aigate/prefilter.py` (use config cooldown)
- Test: `tests/unit/test_cooldown.py`

**Step 1: Write failing test**

```python
# tests/unit/test_cooldown.py
from aigate.config import Config

def test_config_default_cooldown_zero():
    config = Config()
    assert config.cooldown_days == 0  # disabled by default

def test_config_cooldown_from_yaml(tmp_path):
    yaml_content = "cooldown_days: 7\n"
    (tmp_path / ".aigate.yml").write_text(yaml_content)
    config = Config.load(tmp_path)
    assert config.cooldown_days == 7

def test_freshness_uses_config_cooldown():
    from aigate.prefilter import check_package_freshness
    from datetime import datetime, timedelta, timezone
    # 3 days ago, cooldown = 7 → flagged
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    result = check_package_freshness(recent, threshold_days=7)
    assert len(result) > 0
    # 3 days ago, cooldown = 1 → safe
    result2 = check_package_freshness(recent, threshold_days=1)
    assert len(result2) == 0
```

**Step 2: Implement**

Add to Config dataclass:
```python
cooldown_days: int = 0  # 0 = disabled, 7 = recommended
```

Wire into prefilter: if `config.cooldown_days > 0`, pass as `threshold_days` to `check_package_freshness()`.

Add CLI flag:
```python
@click.option("--cooldown", type=int, default=None, help="Override cooldown days (0=disabled, 7=recommended)")
```

**Step 3: Commit**

```bash
git commit -m "feat: add dependency cooldown gate configuration"
```

---

## Task 5: Update Docs and README

**Files:**
- Modify: `README.md` (add cooldown + provenance to features)
- Modify: `docs/configuration.md` (document cooldown_days)
- Modify: `docs/attack-detection.md` (add freshness + provenance signals)

**Commit:**

```bash
git commit -m "docs: add cooldown, provenance, and safety recommendations documentation"
```

---

## Dependency Graph

```
Task 1 (Freshness check) ← foundation
Task 2 (Provenance signal) ← independent
Task 3 (Safety recommendations) ← depends on Task 1 (uses freshness signal)
Task 4 (Cooldown config) ← depends on Task 1 (configures threshold)
Task 5 (Docs) ← depends on all
```

## Execution Order

1. **Tasks 1, 2** in sequence (both modify prefilter.py)
2. **Tasks 3, 4** after Task 1
3. **Task 5** last

## Impact on axios 1.14.1 Attack

| Defense | Would it have caught axios? |
|---------|:-------------------------:|
| Freshness check (default 7 days) | **YES** — published and exploited same day |
| Provenance signal | **YES** — published via CLI, no trusted publishing |
| Safety recommendation | **YES** — "npm install --ignore-scripts" blocks RAT |
| Cooldown gate (7 days) | **YES** — version < 7 days old, flagged |
| Behavior chain (already done) | **YES** — download+execute+persist chain |
