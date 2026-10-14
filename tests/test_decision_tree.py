import pytest
from pathlib import Path
from patchpriority.data import load_and_preprocess_dataset
from patchpriority.models.decision_tree import train_decision_tree_triage

def test_decision_tree():
    parquet_path = Path("archive (1)/nvd_cve_records.parquet")
    train_df, val_df, test_df = load_and_preprocess_dataset(parquet_path, sample_frac=0.04)
    
    pipe, rules, metrics = train_decision_tree_triage(train_df, test_df, max_leaf_nodes=15, max_tfidf=50)
    assert pipe[-1].get_n_leaves() <= 15
    assert isinstance(rules, str)
    assert len(rules) > 50
    assert 'pr_auc' in metrics
