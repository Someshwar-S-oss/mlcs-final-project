import pytest
from pathlib import Path
from patchpriority.data import load_and_preprocess_dataset
from patchpriority.models.regression import train_cvss_redundancy_model, train_cvss_text_recovery_model

def test_regression_pipeline():
    parquet_path = Path("archive (1)/nvd_cve_records.parquet")
    train_df, val_df, test_df = load_and_preprocess_dataset(parquet_path, sample_frac=0.04)
    
    # Model A: Subscores formulaic redundancy
    model_a, r2_a = train_cvss_redundancy_model(train_df, test_df)
    assert r2_a >= 0.85, f"Expected high R^2 on subscores, got {r2_a}"
    
    # Model B: Text recovery
    model_b, metrics_b, residuals = train_cvss_text_recovery_model(train_df, test_df, max_features=200)
    assert metrics_b['train_r2'] > 0.3, f"Expected train R^2 > 0.3, got {metrics_b['train_r2']}"
    assert 'test_r2' in metrics_b
    assert len(residuals) == (test_df['best_cvss_base_score'] > 0).sum()
