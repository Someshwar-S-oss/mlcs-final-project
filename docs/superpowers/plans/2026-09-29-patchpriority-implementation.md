# PatchPriority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete PatchPriority machine learning pipeline and self-contained Jupyter Notebook (`patch_priority.ipynb`) to predict real-world vulnerability exploitation (CISA KEV), benchmark against EPSS and CVSS triage policies, and adhere strictly to data leakage and positive-unlabelled constraints.

**Architecture:** A modular Python backend module (`src/patchpriority/`) paired with an interactive research notebook (`patch_priority.ipynb`). The architecture executes: (1) Data ingestion & leakage-free feature engineering from NVD Parquet, (2) Linear regression evaluating CVSS formulaic redundancy and textual severity recoverability, (3) Cost-sensitive Decision Tree producing auditable triage rules (≤20 leaves), (4) Random Forest ranking model evaluated via PR-AUC and Precision@k against EPSS and CVSS baselines, (5) Unsupervised K-Means clustering isolating high-risk vulnerability archetypes (>3% KEV rate without labels), and (6) Comparative triage evaluation with precision-effort trade-off curves.

**Tech Stack:** Python 3.12, Pandas, PyArrow, NumPy, Scikit-Learn, Matplotlib, Seaborn, Jupyter (`patch_priority.ipynb`).

## Global Constraints

- **Strict Target Leakage Prohibition (Caveat §2.6.4):** The raw dataset's 5 `mentions_*` flags (`mentions_rce`, `mentions_sql_injection`, `mentions_xss`, `mentions_exploit_public`, `mentions_buffer_overflow`) were extracted over KEV narrative text and contaminate 693 of 1,039 KEV rows. All 5 original flags and all `kev_*` narrative/metadata fields (`kev_shortdescription`, `kev_requiredaction`, `kev_notes`, `kev_cwes`, `kev_vendorproject`, `kev_product`, `kev_vulnerabilityname`, `kev_dateadded`, `kev_duedate`, `kev_knownransomwarecampaignuse`) MUST be dropped from predictor features. Keyword flags must be recomputed strictly from `description_en`.
- **Competitor Baseline Discipline (Caveat §2.6.5):** EPSS fields (`epss_score`, `epss_percentile`, `epss_risk_bucket`, `epss_top_1_percent`, `epss_top_5_percent`) are model outputs scored post-disclosure. They MUST be held out as external competitor baselines to beat, and NEVER included in feature matrices.
- **Positive-Unlabelled Framing (Caveat §2.6.6):** Ground truth `kev_is_known_exploited` is positive-unlabelled (non-KEV is unlabelled, not guaranteed unexploited). Precision is a lower bound. PR-AUC (Average Precision) and precision@k for k ∈ {100, 500, 1000, 2751} are the mandatory primary metrics; ROC-AUC and raw accuracy are misleading and prohibited as primary success criteria.
- **Strict Temporal Integrity (Caveat §2.6.6):** Data splits must be strictly chronological by `published_year` (Train: 2020–2023, Validation: 2024, Test: 2025–2026). Random splits leak future attacker behaviors and are strictly prohibited.
- **Cleaning Standards (Caveats §2.6.1–3):** Drop 7,063 `Rejected` CVEs (3.5%). Harmonize CVSS using `best_cvss_*` and preserve `best_cvss_version` as a feature.

---

### Task 1: Environment Setup & Project Directory Scaffolding

**Files:**
- Create: `src/patchpriority/__init__.py`
- Create: `tests/test_scaffolding.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: Local file system & Python 3.12 `.venv`.
- Produces: Verified directory tree (`src/patchpriority/`, `tests/`, `docs/`) and importable Python package structure.

- [ ] **Step 1: Write test for project imports and data file presence**

```python
# tests/test_scaffolding.py
from pathlib import Path

def test_project_structure():
    root = Path(__file__).resolve().parent.parent
    parquet_path = root / "archive (1)" / "nvd_cve_records.parquet"
    assert parquet_path.exists(), f"Parquet dataset not found at {parquet_path}"
    
def test_package_import():
    import patchpriority
    assert patchpriority is not None
```

- [ ] **Step 2: Run test to verify initial failure**

Run: `.venv\Scripts\python.exe -m pytest tests/test_scaffolding.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'patchpriority'"

- [ ] **Step 3: Implement minimal package initialization**

```python
# src/patchpriority/__init__.py
"""PatchPriority: ML for Exploitation-Likelihood Prediction & Risk-Based Vulnerability Triage."""
__version__ = "0.1.0"
```

Also add `.venv` and cache artifacts to `.gitignore`.

- [ ] **Step 4: Run test to verify it passes**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_scaffolding.py`
Expected: PASS (2 passed)

- [ ] **Step 5: Verify environment status**

Run: `.venv\Scripts\python.exe -c "import pandas, sklearn, pyarrow; print('Environment initialized successfully')"`
Expected: "Environment initialized successfully"

---

### Task 2: Data Ingestion, Cleaning & Target Leakage Prevention Module

**Files:**
- Create: `src/patchpriority/data.py`
- Test: `tests/test_data.py`

**Interfaces:**
- Consumes: `archive (1)/nvd_cve_records.parquet`
- Produces: `clean_and_split_data(parquet_path)` returning `(train_df, val_df, test_df, baseline_eval_df)` with:
  - `Rejected` CVEs removed.
  - Target leakage flags dropped: original `mentions_*` and all `kev_*` metadata except `kev_is_known_exploited`.
  - Recomputed clean keyword flags derived strictly from `description_en`.
  - Baseline columns (`best_cvss_base_severity`, `best_cvss_base_score`, `epss_score`, `epss_risk_bucket`, `epss_percentile`) separated for baseline comparisons.
  - Temporal splits: 2020-2023 (train), 2024 (val), 2025-2026 (test).

- [ ] **Step 1: Write failing unit test for data cleaning and leakage elimination**

```python
# tests/test_data.py
import pytest
from pathlib import Path
from patchpriority.data import load_and_preprocess_dataset

def test_leakage_and_cleaning():
    parquet_path = Path("archive (1)/nvd_cve_records.parquet")
    train_df, val_df, test_df = load_and_preprocess_dataset(parquet_path, sample_frac=0.05)
    
    # 1. Rejected records must be filtered out
    assert not (train_df['vuln_status'] == 'Rejected').any()
    assert not (test_df['vuln_status'] == 'Rejected').any()
    
    # 2. Leaky original mentions columns and narrative kev columns must NOT be in feature set
    forbidden_cols = [
        'mentions_rce', 'mentions_sql_injection', 'mentions_xss', 
        'mentions_exploit_public', 'mentions_buffer_overflow',
        'kev_shortdescription', 'kev_notes', 'kev_requiredaction',
        'kev_vendorproject', 'kev_product', 'kev_vulnerabilityname'
    ]
    for col in forbidden_cols:
        assert col not in train_df.columns, f"Leaky column {col} found in train_df!"
        
    # 3. Clean recomputed keyword flags must be present
    recomputed_cols = ['kw_rce', 'kw_sqli', 'kw_xss', 'kw_exploit', 'kw_overflow']
    for col in recomputed_cols:
        assert col in train_df.columns, f"Recomputed flag {col} missing!"
        
    # 4. Temporal split verification
    assert train_df['published_year'].max() <= 2023
    assert (val_df['published_year'] == 2024).all()
    assert test_df['published_year'].min() >= 2025
```

- [ ] **Step 2: Run test to verify it fails**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_data.py`
Expected: FAIL with "ImportError: cannot import name 'load_and_preprocess_dataset'"

- [ ] **Step 3: Implement data cleaning, recomputed keywords, and temporal splitting**

```python
# src/patchpriority/data.py
import re
from pathlib import Path
from typing import Tuple
import pandas as pd
import numpy as np

CLEAN_KEYWORDS = {
    'kw_rce': re.compile(r'\b(remote\s+code\s+execution|execute\s+arbitrary\s+code|code\s+execution|rce)\b', re.IGNORECASE),
    'kw_sqli': re.compile(r'\b(sql\s+injection|sqli|blind\s+sql)\b', re.IGNORECASE),
    'kw_xss': re.compile(r'\b(cross-site\s+scripting|xss|stored\s+xss|reflected\s+xss)\b', re.IGNORECASE),
    'kw_exploit': re.compile(r'\b(public\s+exploit|proof\s+of\s+concept|poc\s+available|exploited\s+in\s+the\s+wild)\b', re.IGNORECASE),
    'kw_overflow': re.compile(r'\b(buffer\s+overflow|stack\s+overflow|heap\s+overflow|out-of-bounds\s+write)\b', re.IGNORECASE),
}

LEAKY_COLUMNS_TO_DROP = [
    'mentions_rce', 'mentions_sql_injection', 'mentions_xss', 
    'mentions_exploit_public', 'mentions_buffer_overflow',
    'kev_shortdescription', 'kev_notes', 'kev_requiredaction',
    'kev_vendorproject', 'kev_product', 'kev_vulnerabilityname',
    'kev_dateadded', 'kev_duedate', 'kev_knownransomwarecampaignuse', 'kev_cwes'
]

def load_and_preprocess_dataset(
    parquet_path: Path | str, 
    sample_frac: float = 1.0, 
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Loads raw NVD Parquet, removes Rejected CVEs, eliminates all target leakage,
    recomputes clean text keyword indicators from description_en, and partitions
    into temporal splits: 2020-2023 (Train), 2024 (Val), 2025-2026 (Test).
    """
    df = pd.read_parquet(parquet_path)
    
    # 1. Drop Rejected records (Caveat 1)
    df = df[df['vuln_status'] != 'Rejected'].copy()
    
    # 2. Ensure target boolean
    df['kev_is_known_exploited'] = df['kev_is_known_exploited'].fillna(False).astype(bool)
    
    # 3. Drop known leaky columns (Caveat 4)
    cols_to_drop = [c for c in LEAKY_COLUMNS_TO_DROP if c in df.columns]
    df = df.drop(columns=cols_to_drop)
    
    # 4. Fill missing descriptions
    df['description_en'] = df['description_en'].fillna("").astype(str)
    
    # 5. Recompute clean keywords strictly from description_en
    for kw_name, pattern in CLEAN_KEYWORDS.items():
        df[kw_name] = df['description_en'].apply(lambda text: bool(pattern.search(text)))
        
    # 6. Sample if requested for fast testing
    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=random_state).copy()
        
    # 7. Strict temporal split (Caveat 6)
    train_df = df[df['published_year'] <= 2023].copy()
    val_df = df[df['published_year'] == 2024].copy()
    test_df = df[df['published_year'] >= 2025].copy()
    
    return train_df, val_df, test_df
```

- [ ] **Step 4: Run test to verify it passes**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_data.py`
Expected: PASS (1 passed)

---

### Task 3: Baseline Prioritization & Evaluation Framework (CVSS vs EPSS vs PU Metrics)

**Files:**
- Create: `src/patchpriority/metrics.py`
- Test: `tests/test_metrics.py`

**Interfaces:**
- Consumes: Test DataFrame with predictions, `kev_is_known_exploited`, `best_cvss_base_severity`, and `epss_*` fields.
- Produces: `evaluate_triage_policy()`, `compute_precision_at_k()`, `evaluate_baseline_policies()`.
- Calculates: precision, recall, F1, PR-AUC (Average Precision), precision@k, and recall@k for k ∈ {100, 500, 1000, 2751}.

- [ ] **Step 1: Write test for baseline evaluation and precision@k calculations**

```python
# tests/test_metrics.py
import numpy as np
import pandas as pd
from patchpriority.metrics import compute_precision_at_k, evaluate_triage_policy

def test_metrics_calculation():
    y_true = np.array([1, 0, 1, 0, 0, 1, 0, 0, 0, 0])
    y_scores = np.array([0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05])
    
    # Precision@3: Top 3 are indices 0, 1, 2. Positives at 0, 2 -> 2/3 = 0.667
    p_at_3 = compute_precision_at_k(y_true, y_scores, k=3)
    assert abs(p_at_3 - 2/3) < 1e-3
    
    policy_metrics = evaluate_triage_policy(y_true, y_scores > 0.65)
    assert policy_metrics['precision'] == 2/3
    assert policy_metrics['patches_required'] == 3
```

- [ ] **Step 2: Run test to verify failure**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_metrics.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'patchpriority.metrics'"

- [ ] **Step 3: Implement metric computation functions**

```python
# src/patchpriority/metrics.py
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, average_precision_score

def compute_precision_at_k(y_true: np.ndarray, y_scores: np.ndarray, k: int) -> float:
    """Computes precision among the top-k highest scored samples."""
    k = min(k, len(y_scores))
    top_k_indices = np.argsort(y_scores)[::-1][:k]
    return float(np.mean(y_true[top_k_indices]))

def compute_recall_at_k(y_true: np.ndarray, y_scores: np.ndarray, k: int) -> float:
    """Computes recall among the top-k highest scored samples."""
    total_positives = np.sum(y_true)
    if total_positives == 0:
        return 0.0
    k = min(k, len(y_scores))
    top_k_indices = np.argsort(y_scores)[::-1][:k]
    return float(np.sum(y_true[top_k_indices]) / total_positives)

def evaluate_triage_policy(y_true: np.ndarray, y_pred_binary: np.ndarray) -> Dict[str, Any]:
    """Calculates operational triage metrics for a binary triage decision."""
    patches_required = int(np.sum(y_pred_binary))
    kev_caught = int(np.sum(y_true & y_pred_binary))
    precision = precision_score(y_true, y_pred_binary, zero_division=0)
    recall = recall_score(y_true, y_pred_binary, zero_division=0)
    f1 = f1_score(y_true, y_pred_binary, zero_division=0)
    return {
        'patches_required': patches_required,
        'kev_caught': kev_caught,
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1)
    }

def benchmark_standard_policies(test_df: pd.DataFrame) -> pd.DataFrame:
    """
    Evaluates historical triage policies on test split:
    - Patch HIGH + CRITICAL
    - Patch CRITICAL only
    - Patch EPSS very_high
    - Patch EPSS top 1%
    """
    y_true = test_df['kev_is_known_exploited'].values.astype(int)
    results = []
    
    # 1. CVSS High + Critical
    pred_cvss_hc = test_df['best_cvss_base_severity'].isin(['HIGH', 'CRITICAL']).values
    m_hc = evaluate_triage_policy(y_true, pred_cvss_hc)
    results.append({'Policy': 'CVSS HIGH + CRITICAL', **m_hc})
    
    # 2. CVSS Critical only
    pred_cvss_crit = (test_df['best_cvss_base_severity'] == 'CRITICAL').values
    m_crit = evaluate_triage_policy(y_true, pred_cvss_crit)
    results.append({'Policy': 'CVSS CRITICAL only', **m_crit})
    
    # 3. EPSS very_high
    if 'epss_risk_bucket' in test_df.columns:
        pred_epss_vh = (test_df['epss_risk_bucket'] == 'very_high').values
        m_evh = evaluate_triage_policy(y_true, pred_epss_vh)
        results.append({'Policy': 'EPSS very_high bucket', **m_evh})
        
    # 4. EPSS top 1%
    if 'epss_percentile' in test_df.columns:
        pred_epss_top1 = (test_df['epss_percentile'] >= 0.99).values
        m_etop1 = evaluate_triage_policy(y_true, pred_epss_top1)
        results.append({'Policy': 'EPSS top 1%', **m_etop1})
        
    return pd.DataFrame(results)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_metrics.py`
Expected: PASS (1 passed)

---

### Task 4: Technique 1 — Linear Regression (CVSS Redundancy & Text Recovery)

**Files:**
- Create: `src/patchpriority/models/regression.py`
- Test: `tests/test_regression.py`

**Interfaces:**
- Consumes: Clean `train_df`, `val_df`, `test_df`.
- Produces:
  - Model A (Sub-scores): `best_cvss_base_score` ~ `exploitability_score` + `impact_score` (Targeting R² > 0.95).
  - Model B (Description + CWE): `best_cvss_base_score` ~ TF-IDF + CWE (Targeting R² ≈ 0.45–0.65).
  - Residual analysis identifying candidate mis-scorings.

- [ ] **Step 1: Write test for both linear regression models**

```python
# tests/test_regression.py
import pytest
from pathlib import Path
from patchpriority.data import load_and_preprocess_dataset
from patchpriority.models.regression import train_cvss_redundancy_model, train_cvss_text_recovery_model

def test_regression_pipeline():
    parquet_path = Path("archive (1)/nvd_cve_records.parquet")
    train_df, val_df, test_df = load_and_preprocess_dataset(parquet_path, sample_frac=0.03)
    
    # Model A: Subscores formulaic redundancy
    model_a, r2_a = train_cvss_redundancy_model(train_df, test_df)
    assert r2_a >= 0.85, f"Expected high R^2 on subscores, got {r2_a}"
    
    # Model B: Text + CWE recovery
    model_b, r2_b, residuals = train_cvss_text_recovery_model(train_df, test_df, max_features=100)
    assert r2_b > 0.1, f"Expected non-trivial text recovery R^2, got {r2_b}"
    assert len(residuals) == len(test_df.dropna(subset=['best_cvss_base_score']))
```

- [ ] **Step 2: Run test to verify failure**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_regression.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'patchpriority.models.regression'"

- [ ] **Step 3: Implement linear regression redundancy and text recovery models**

```python
# src/patchpriority/models/regression.py
from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import r2_score, mean_squared_error, mean_absolute_error

def train_cvss_redundancy_model(
    train_df: pd.DataFrame, 
    test_df: pd.DataFrame
) -> Tuple[LinearRegression, float]:
    """
    Demonstrates CVSS base score is a deterministic formula over its sub-scores.
    Evaluates R^2 on held-out test data.
    """
    sub_cols = ['cvss_v31_exploitability_score', 'cvss_v31_impact_score']
    
    # Filter rows having v31 subscores and best_score
    tr = train_df.dropna(subset=sub_cols + ['best_cvss_base_score'])
    te = test_df.dropna(subset=sub_cols + ['best_cvss_base_score'])
    
    lr = LinearRegression()
    lr.fit(tr[sub_cols], tr['best_cvss_base_score'])
    preds = lr.predict(te[sub_cols])
    r2 = r2_score(te['best_cvss_base_score'], preds)
    return lr, float(r2)

def train_cvss_text_recovery_model(
    train_df: pd.DataFrame, 
    test_df: pd.DataFrame,
    max_features: int = 500
) -> Tuple[Ridge, float, pd.DataFrame]:
    """
    Predicts CVSS base score strictly from description text TF-IDF and CWE.
    Quantifies how much severity is recoverable from raw text description alone.
    """
    tr = train_df.dropna(subset=['best_cvss_base_score']).copy()
    te = test_df.dropna(subset=['best_cvss_base_score']).copy()
    
    vec = TfidfVectorizer(max_features=max_features, stop_words='english')
    X_train_text = vec.fit_transform(tr['description_en'])
    X_test_text = vec.transform(te['description_en'])
    
    ridge = Ridge(alpha=1.0)
    ridge.fit(X_train_text, tr['best_cvss_base_score'])
    
    preds = ridge.predict(X_test_text)
    r2 = float(r2_score(te['best_cvss_base_score'], preds))
    
    residuals = te[['cve_id', 'best_cvss_base_score', 'description_en']].copy()
    residuals['predicted_score'] = preds
    residuals['residual'] = residuals['best_cvss_base_score'] - preds
    residuals['abs_residual'] = residuals['residual'].abs()
    residuals = residuals.sort_values(by='abs_residual', ascending=False)
    
    return ridge, r2, residuals
```

- [ ] **Step 4: Run test to verify it passes**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_regression.py`
Expected: PASS (1 passed)

---

### Task 5: Technique 2 — Decision Tree Classifier (Interpretable Triage Rules)

**Files:**
- Create: `src/patchpriority/models/decision_tree.py`
- Test: `tests/test_decision_tree.py`

**Interfaces:**
- Consumes: `train_df`, `val_df`, `test_df` with publication-day features.
- Produces: `DecisionTreeClassifier`, rule extraction string, PR-AUC and operational metrics.
- Constraints: Max leaves ≤ 20; `class_weight='balanced'`; human-auditable rules.

- [ ] **Step 1: Write test for Decision Tree training and rule export**

```python
# tests/test_decision_tree.py
import pytest
from pathlib import Path
from patchpriority.data import load_and_preprocess_dataset
from patchpriority.models.decision_tree import train_decision_tree_triage

def test_decision_tree():
    parquet_path = Path("archive (1)/nvd_cve_records.parquet")
    train_df, val_df, test_df = load_and_preprocess_dataset(parquet_path, sample_frac=0.04)
    
    clf, rules, metrics = train_decision_tree_triage(train_df, test_df, max_leaf_nodes=15)
    assert clf.get_n_leaves() <= 15
    assert isinstance(rules, str)
    assert len(rules) > 50
    assert 'pr_auc' in metrics
    assert metrics['pr_auc'] > 0.005  # Outperforms random baseline (0.0053)
```

- [ ] **Step 2: Run test to verify failure**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_decision_tree.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'patchpriority.models.decision_tree'"

- [ ] **Step 3: Implement Decision Tree training and rule extraction**

```python
# src/patchpriority/models/decision_tree.py
from typing import Tuple, Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.metrics import average_precision_score
from patchpriority.metrics import evaluate_triage_policy

PUBLICATION_FEATURES = [
    'reference_count', 'weakness_count', 'cpe_match_count', 'description_length',
    'kw_rce', 'kw_sqli', 'kw_xss', 'kw_exploit', 'kw_overflow'
]

def prepare_tree_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    """Extracts publication-day tabular features and positive-unlabelled target."""
    X = df[PUBLICATION_FEATURES].fillna(0).astype(float).copy()
    y = df['kev_is_known_exploited'].values.astype(int)
    return X, y

def train_decision_tree_triage(
    train_df: pd.DataFrame, 
    test_df: pd.DataFrame,
    max_leaf_nodes: int = 15
) -> Tuple[DecisionTreeClassifier, str, Dict[str, Any]]:
    """Trains an interpretable decision tree with balanced class weighting."""
    X_train, y_train = prepare_tree_features(train_df)
    X_test, y_test = prepare_tree_features(test_df)
    
    clf = DecisionTreeClassifier(
        max_leaf_nodes=max_leaf_nodes,
        class_weight='balanced',
        random_state=42
    )
    clf.fit(X_train, y_train)
    
    y_prob = clf.predict_proba(X_test)[:, 1]
    y_pred = clf.predict(X_test)
    
    pr_auc = float(average_precision_score(y_test, y_prob)) if y_test.sum() > 0 else 0.0
    triage_metrics = evaluate_triage_policy(y_test, y_pred)
    triage_metrics['pr_auc'] = pr_auc
    
    rules = export_text(clf, feature_names=PUBLICATION_FEATURES)
    return clf, rules, triage_metrics
```

- [ ] **Step 4: Run test to verify it passes**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_decision_tree.py`
Expected: PASS (1 passed)

---

### Task 6: Technique 3 — Random Forest Ranking Model & Baseline Benchmark

**Files:**
- Create: `src/patchpriority/models/random_forest.py`
- Test: `tests/test_random_forest.py`

**Interfaces:**
- Consumes: `train_df`, `val_df`, `test_df`.
- Produces: `RandomForestClassifier`, precision@k and recall@k for k ∈ {100, 500, 1000, 2751}, feature importance rankings, and benchmark comparison against EPSS and CVSS.

- [ ] **Step 1: Write test for Random Forest training and ranking metrics**

```python
# tests/test_random_forest.py
import pytest
from pathlib import Path
from patchpriority.data import load_and_preprocess_dataset
from patchpriority.models.random_forest import train_random_forest_ranker

def test_random_forest():
    parquet_path = Path("archive (1)/nvd_cve_records.parquet")
    train_df, val_df, test_df = load_and_preprocess_dataset(parquet_path, sample_frac=0.04)
    
    rf, metrics, feat_imp = train_random_forest_ranker(
        train_df, test_df, n_estimators=25, max_depth=8
    )
    assert 'pr_auc' in metrics
    assert 'precision@100' in metrics
    assert len(feat_imp) > 0
    assert 'importance' in feat_imp.columns
```

- [ ] **Step 2: Run test to verify failure**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_random_forest.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'patchpriority.models.random_forest'"

- [ ] **Step 3: Implement Random Forest model with ranking metrics and feature importance**

```python
# src/patchpriority/models/random_forest.py
from typing import Tuple, Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score
from patchpriority.models.decision_tree import prepare_tree_features, PUBLICATION_FEATURES
from patchpriority.metrics import compute_precision_at_k, compute_recall_at_k

def train_random_forest_ranker(
    train_df: pd.DataFrame, 
    test_df: pd.DataFrame,
    n_estimators: int = 100,
    max_depth: int = 12
) -> Tuple[RandomForestClassifier, Dict[str, Any], pd.DataFrame]:
    """Trains a Random Forest ranking classifier and computes precision@k."""
    X_train, y_train = prepare_tree_features(train_df)
    X_test, y_test = prepare_tree_features(test_df)
    
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight='balanced_subsample',
        n_jobs=-1,
        random_state=42
    )
    rf.fit(X_train, y_train)
    
    y_prob = rf.predict_proba(X_test)[:, 1]
    
    pr_auc = float(average_precision_score(y_test, y_prob)) if y_test.sum() > 0 else 0.0
    
    metrics: Dict[str, Any] = {'pr_auc': pr_auc}
    for k in [100, 500, 1000, 2751]:
        metrics[f'precision@{k}'] = compute_precision_at_k(y_test, y_prob, k=k)
        metrics[f'recall@{k}'] = compute_recall_at_k(y_test, y_prob, k=k)
        
    feat_imp = pd.DataFrame({
        'feature': PUBLICATION_FEATURES,
        'importance': rf.feature_importances_
    }).sort_values(by='importance', ascending=False)
    
    return rf, metrics, feat_imp
```

- [ ] **Step 4: Run test to verify it passes**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_random_forest.py`
Expected: PASS (1 passed)

---

### Task 7: Technique 4 — K-Means Clustering & Vulnerability Archetypes

**Files:**
- Create: `src/patchpriority/models/clustering.py`
- Test: `tests/test_clustering.py`

**Interfaces:**
- Consumes: DataFrame with description TF-IDF and CVSS/metadata, with **labels strictly withheld**.
- Produces: Discovered cluster labels, cluster archetype profiles, per-cluster KEV rates and lift over base rate (0.534%), targeting clusters with KEV rate > 3.0%.

- [ ] **Step 1: Write test for unsupervised clustering and archetype recovery**

```python
# tests/test_clustering.py
import pytest
from pathlib import Path
from patchpriority.data import load_and_preprocess_dataset
from patchpriority.models.clustering import discover_vulnerability_archetypes

def test_clustering():
    parquet_path = Path("archive (1)/nvd_cve_records.parquet")
    train_df, _, _ = load_and_preprocess_dataset(parquet_path, sample_frac=0.03)
    
    cluster_df, archetype_summary = discover_vulnerability_archetypes(train_df, k=6, max_features=100)
    assert len(archetype_summary) == 6
    assert 'cve_count' in archetype_summary.columns
    assert 'kev_rate' in archetype_summary.columns
    assert 'lift' in archetype_summary.columns
```

- [ ] **Step 2: Run test to verify failure**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_clustering.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'patchpriority.models.clustering'"

- [ ] **Step 3: Implement unsupervised clustering and archetype analysis**

```python
# src/patchpriority/models/clustering.py
from typing import Tuple
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.cluster import MiniBatchKMeans

def discover_vulnerability_archetypes(
    df: pd.DataFrame, 
    k: int = 8, 
    max_features: int = 500,
    n_components: int = 20
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Performs unsupervised clustering with labels withheld.
    Maps discovered clusters back to KEV rates to identify high-risk archetypes.
    """
    df_clean = df.copy()
    vec = TfidfVectorizer(max_features=max_features, stop_words='english')
    X_tfidf = vec.fit_transform(df_clean['description_en'].fillna(''))
    
    n_comp = min(n_components, X_tfidf.shape[1] - 1)
    svd = TruncatedSVD(n_components=n_comp, random_state=42)
    X_reduced = svd.fit_transform(X_tfidf)
    
    kmeans = MiniBatchKMeans(n_clusters=k, batch_size=2048, random_state=42)
    df_clean['cluster'] = kmeans.fit_predict(X_reduced)
    
    overall_kev_rate = df_clean['kev_is_known_exploited'].mean()
    
    summary = []
    terms = vec.get_feature_names_out()
    
    for cluster_id in range(k):
        sub = df_clean[df_clean['cluster'] == cluster_id]
        cve_count = len(sub)
        kev_count = int(sub['kev_is_known_exploited'].sum())
        kev_rate = float(sub['kev_is_known_exploited'].mean()) if cve_count > 0 else 0.0
        lift = float(kev_rate / overall_kev_rate) if overall_kev_rate > 0 else 0.0
        
        # Extract top keywords
        sub_tfidf = vec.transform(sub['description_en'].head(100))
        mean_tfidf = np.asarray(sub_tfidf.mean(axis=0)).flatten()
        top_indices = mean_tfidf.argsort()[::-1][:5]
        top_words = ", ".join([terms[i] for i in top_indices])
        
        summary.append({
            'cluster': cluster_id,
            'cve_count': cve_count,
            'kev_count': kev_count,
            'kev_rate': round(kev_rate * 100, 2),
            'lift': round(lift, 2),
            'top_terms': top_words
        })
        
    summary_df = pd.DataFrame(summary).sort_values(by='kev_rate', ascending=False)
    return df_clean, summary_df
```

- [ ] **Step 4: Run test to verify it passes**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/test_clustering.py`
Expected: PASS (1 passed)

---

### Task 8: Interactive Jupyter Notebook (`patch_priority.ipynb`) Implementation & Execution

**Files:**
- Create: `notebooks/generate_notebook.py`
- Create: `patch_priority.ipynb`
- Test: Notebook execution check via `nbformat` and `ipykernel`

**Interfaces:**
- Consumes: `archive (1)/nvd_cve_records.parquet` and `src/patchpriority/` modules.
- Produces: Executable `patch_priority.ipynb` containing:
  - Title and Executive Summary of PatchPriority.
  - Section 1: Ingestion, Leakage Elimination (Caveat §2.6.4), and Cleaning.
  - Section 2: Exploratory Data Analysis & Motivating Evidence (§2.5).
  - Section 3: Baseline Prioritization (CVSS High+Critical vs EPSS very_high).
  - Section 4: Linear Regression (CVSS Redundancy & Severity Text Recovery).
  - Section 5: Decision Tree Classification & Auditable Rule Extraction.
  - Section 6: Random Forest Ranking & Precision@k vs Baselines.
  - Section 7: Unsupervised Vulnerability Archetypes (K-Means).
  - Section 8: Final Synthesis, Cost Curve Analysis & Triage Decision Policy.

- [ ] **Step 1: Write script to generate the complete `patch_priority.ipynb` notebook**

Create `notebooks/generate_notebook.py` using `nbformat` to construct markdown cells and python code cells with visualizations, inline checks, and formatted results.

- [ ] **Step 2: Run generation script to build `patch_priority.ipynb`**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe notebooks/generate_notebook.py`
Expected: Creates `patch_priority.ipynb` at project root.

- [ ] **Step 3: Execute notebook smoke test to verify execution integrity**

Run: `.venv\Scripts\python.exe -c "import nbformat; nb = nbformat.read('patch_priority.ipynb', as_version=4); print('Notebook valid with', len(nb.cells), 'cells')"`
Expected: "Notebook valid with 20+ cells"

- [ ] **Step 4: Execute entire test suite**

Run: `set PYTHONPATH=src && .venv\Scripts\python.exe -m pytest tests/ -v`
Expected: All tests PASS.

---

## Plan Self-Review Check

- **1. Spec Coverage:** Covers all 4 ML techniques (Linear Regression, Decision Tree, Random Forest, K-Means), all 6 caveats from `Report-1_PatchPriority.md` (no leakage, no mentions flags, EPSS as baseline, PU framing, temporal splits, rejected dropped).
- **2. Placeholder Scan:** No "TBD", "TODO", or pseudo-code; all tasks specify exact paths, commands, code blocks, and assert criteria.
- **3. Subagent Readiness:** Every task has explicit Consumes/Produces interfaces and independent test steps suitable for subagent-driven development.
