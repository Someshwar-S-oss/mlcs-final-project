from typing import Tuple, Dict, Any
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.pipeline import Pipeline, make_pipeline
from patchpriority.features import FEATURES, make_preprocessor
from patchpriority.metrics import evaluate_triage_policy, ranking_metrics

def train_decision_tree_triage(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    max_leaf_nodes: int = 15,
    max_tfidf: int = 200
) -> Tuple[Pipeline, str, Dict[str, Any]]:
    """Cost-sensitive CART bounded to `max_leaf_nodes`, exported as an auditable rule set.
    Numerics stay unscaled so thresholds read in real units (e.g. CVSS score > 8.5)."""
    pipe = make_pipeline(
        make_preprocessor(max_tfidf=max_tfidf, ngram_range=(1, 1), scale_numeric=False),
        DecisionTreeClassifier(max_leaf_nodes=max_leaf_nodes, class_weight='balanced', random_state=42)
    )
    y_train = train_df['kev_is_known_exploited'].astype(int)
    y_test = test_df['kev_is_known_exploited'].values.astype(int)
    pipe.fit(train_df[FEATURES], y_train)

    metrics = evaluate_triage_policy(y_test, pipe.predict(test_df[FEATURES]))
    metrics.update(ranking_metrics(y_test, pipe.predict_proba(test_df[FEATURES])[:, 1]))
    rules = export_text(pipe[-1], feature_names=list(pipe[0].get_feature_names_out()))
    return pipe, rules, metrics
