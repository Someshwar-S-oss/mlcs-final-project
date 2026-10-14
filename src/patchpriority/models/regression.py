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
    Demonstrates CVSS v3.1 base score is a deterministic formula over its sub-scores.
    Evaluates R^2 on held-out test data.
    """
    sub_cols = ['cvss_v31_exploitability_score', 'cvss_v31_impact_score']
    target_col = 'cvss_v31_base_score'
    
    # Filter rows having v31 subscores and base score
    tr = train_df.dropna(subset=sub_cols + [target_col])
    te = test_df.dropna(subset=sub_cols + [target_col])
    
    lr = LinearRegression()
    lr.fit(tr[sub_cols], tr[target_col])
    preds = lr.predict(te[sub_cols])
    r2 = float(r2_score(te[target_col], preds))
    return lr, r2

def train_cvss_text_recovery_model(
    train_df: pd.DataFrame, 
    test_df: pd.DataFrame,
    max_features: int = 500
) -> Tuple[Ridge, Dict[str, float], pd.DataFrame]:
    """
    Predicts CVSS base score strictly from description text TF-IDF.
    Quantifies how much severity is recoverable from raw text description alone.
    Returns model, metrics dict (train_r2, test_r2, test_mae), and residuals DataFrame.
    """
    # Score 0.0 means "no impact"/placeholder, not a real severity; it dominated the residual outliers.
    tr = train_df[train_df['best_cvss_base_score'] > 0].copy()
    te = test_df[test_df['best_cvss_base_score'] > 0].copy()
    
    vec = TfidfVectorizer(max_features=max_features, stop_words='english')
    X_train_text = vec.fit_transform(tr['description_en'])
    X_test_text = vec.transform(te['description_en'])
    
    ridge = Ridge(alpha=1.0)
    ridge.fit(X_train_text, tr['best_cvss_base_score'])
    
    train_preds = ridge.predict(X_train_text)
    test_preds = ridge.predict(X_test_text)
    
    metrics = {
        'train_r2': float(r2_score(tr['best_cvss_base_score'], train_preds)),
        'test_r2': float(r2_score(te['best_cvss_base_score'], test_preds)),
        'test_mae': float(mean_absolute_error(te['best_cvss_base_score'], test_preds))
    }
    
    residuals = te[['cve_id', 'best_cvss_base_score', 'description_en']].copy()
    residuals['predicted_score'] = test_preds
    residuals['residual'] = residuals['best_cvss_base_score'] - test_preds
    residuals['abs_residual'] = residuals['residual'].abs()
    residuals = residuals.sort_values(by='abs_residual', ascending=False)
    
    return ridge, metrics, residuals
