from pathlib import Path

def test_project_structure():
    root = Path(__file__).resolve().parent.parent
    parquet_path = root / "archive (1)" / "nvd_cve_records.parquet"
    assert parquet_path.exists(), f"Parquet dataset not found at {parquet_path}"
    
def test_package_import():
    import patchpriority
    assert patchpriority.__version__ == "0.1.0"
