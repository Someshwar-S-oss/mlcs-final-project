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

# Base metrics shared by CVSS v3.1 and v4.0; harmonised into `cvss_<metric>` (v3.1 preferred).
CVSS_METRICS = [
    'attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction',
    'confidentiality_impact', 'integrity_impact', 'availability_impact',
]

# Post-publication enrichers that prioritise exploited CVEs: NVD and CISA-ADP (Vulnrichment).
ENRICHER_SOURCES = ['nvd@nist.gov', '134c704f-9b21-4f2e-91b3-4a467353bcc0']

def load_cna_cwe(weaknesses_csv: Path | str) -> pd.Series:
    """First CWE per CVE as supplied by the CNA. CWEs added later by NVD or CISA-ADP are
    excluded: both enrich KEV CVEs first, so their CWEs leak the label."""
    w = pd.read_csv(weaknesses_csv, usecols=['cve_id', 'weakness_source', 'cwe_id'])
    w = w[~w['weakness_source'].isin(ENRICHER_SOURCES)]
    return w.groupby('cve_id')['cwe_id'].first()

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
        df[kw_name] = df['description_en'].apply(lambda text: int(bool(pattern.search(text))))
        
    # 6. Publication-day categorical features
    weaknesses_csv = Path(parquet_path).with_name('nvd_cve_weaknesses.csv')
    df['cna_cwe'] = df['cve_id'].map(load_cna_cwe(weaknesses_csv)) if weaknesses_csv.exists() else np.nan
    df['cna_cwe'] = df['cna_cwe'].fillna('NONE')
    for m in CVSS_METRICS:
        df[f'cvss_{m}'] = df[f'cvss_v31_{m}'].fillna(df[f'cvss_v40_{m}']).fillna('NA')

    # 7. Sample if requested for fast testing
    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=random_state).copy()
        
    # 8. Strict temporal split (Caveat 6)
    train_df = df[df['published_year'] <= 2023].copy()
    val_df = df[df['published_year'] == 2024].copy()
    test_df = df[df['published_year'] >= 2025].copy()
    
    return train_df, val_df, test_df
