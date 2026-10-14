"""Publication-day feature set shared by every classifier and the scoring service.

Only fields known the day a CVE is published are allowed. Excluded because they leak
the KEV label (NVD and CISA-ADP enrich KEV CVEs first; CISA adds a reference on listing):
`vuln_status`, `reference_count`, `cpe_match_count`, `weakness_count`, `primary_cwe_id`,
`cvss_*_source`, reference tags, and every `epss_*` / `kev_*` column.
"""
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from patchpriority.data import CLEAN_KEYWORDS, CVSS_METRICS

TEXT_FEATURE = 'description_en'
CATEGORICAL_FEATURES = ['source_identifier', 'cna_cwe'] + [f'cvss_{m}' for m in CVSS_METRICS]
NUMERIC_FEATURES = ['best_cvss_base_score', 'description_length'] + list(CLEAN_KEYWORDS)
FEATURES = [TEXT_FEATURE] + CATEGORICAL_FEATURES + NUMERIC_FEATURES


def make_preprocessor(max_tfidf: int = 20000, ngram_range=(1, 2), scale_numeric: bool = True) -> ColumnTransformer:
    """TF-IDF over the description + one-hot categoricals + numeric columns."""
    numeric = [SimpleImputer(strategy='constant', fill_value=-1)]
    if scale_numeric:
        numeric.append(StandardScaler())
    return ColumnTransformer([
        ('text', TfidfVectorizer(max_features=max_tfidf, ngram_range=ngram_range, min_df=3,
                                 sublinear_tf=True, stop_words='english'), TEXT_FEATURE),
        ('cat', OneHotEncoder(handle_unknown='infrequent_if_exist', min_frequency=20), CATEGORICAL_FEATURES),
        ('num', make_pipeline(*numeric), NUMERIC_FEATURES),
    ])
