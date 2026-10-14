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

# Patch budgets for the test split. 224 = size of the EPSS `very_high` bucket on 2025-2026,
# i.e. the "equal patch effort" comparison point.
DEFAULT_KS = (100, 224, 500, 1000)

def ranking_metrics(y_true: np.ndarray, y_scores: np.ndarray, ks=DEFAULT_KS) -> Dict[str, float]:
    """PR-AUC plus precision@k / recall@k for each patch budget k."""
    y_true = np.asarray(y_true).astype(int)
    y_scores = np.asarray(y_scores, dtype=float)
    out = {'pr_auc': float(average_precision_score(y_true, y_scores)) if y_true.sum() else 0.0,
           'base_rate': float(y_true.mean())}
    for k in ks:
        out[f'precision@{k}'] = compute_precision_at_k(y_true, y_scores, k)
        out[f'recall@{k}'] = compute_recall_at_k(y_true, y_scores, k)
    return out
