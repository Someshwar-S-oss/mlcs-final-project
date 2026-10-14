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
