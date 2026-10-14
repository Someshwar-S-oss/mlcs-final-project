import pytest
from pathlib import Path
from patchpriority.data import load_and_preprocess_dataset
from patchpriority.models.random_forest import train_random_forest_ranker

def test_random_forest():
    parquet_path = Path("archive (1)/nvd_cve_records.parquet")
    train_df, val_df, test_df = load_and_preprocess_dataset(parquet_path, sample_frac=0.04)
    
    rf, metrics, feat_imp = train_random_forest_ranker(
        train_df, test_df, n_estimators=25, max_tfidf=50
    )
    assert 'pr_auc' in metrics
    assert 'precision@100' in metrics
    assert len(feat_imp) > 0
    assert 'importance' in feat_imp.columns
