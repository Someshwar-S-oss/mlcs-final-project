from typing import Tuple, Dict, Any
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline, make_pipeline
from patchpriority.features import FEATURES, make_preprocessor
from patchpriority.metrics import ranking_metrics

def train_random_forest_ranker(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    n_estimators: int = 300,
    min_samples_leaf: int = 50,
    max_tfidf: int = 300
) -> Tuple[Pipeline, Dict[str, Any], pd.DataFrame]:
    """Random Forest ranker over the publication-day feature set; returns precision@k and
    Gini importances. Unigram TF-IDF is capped at `max_tfidf` terms to keep trees tractable."""
    pipe = make_pipeline(
        make_preprocessor(max_tfidf=max_tfidf, ngram_range=(1, 1), scale_numeric=False),
        RandomForestClassifier(
            n_estimators=n_estimators,
            min_samples_leaf=min_samples_leaf,
            class_weight='balanced_subsample',
            n_jobs=-1,
            random_state=42
        )
    )
    pipe.fit(train_df[FEATURES], train_df['kev_is_known_exploited'].astype(int))
    y_prob = pipe.predict_proba(test_df[FEATURES])[:, 1]
    metrics = ranking_metrics(test_df['kev_is_known_exploited'].values, y_prob)

    feat_imp = pd.DataFrame({
        'feature': pipe[0].get_feature_names_out(),
        'importance': pipe[-1].feature_importances_
    }).sort_values(by='importance', ascending=False)
    return pipe, metrics, feat_imp
