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
