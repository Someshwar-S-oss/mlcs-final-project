import numpy as np
import pandas as pd
from patchpriority.metrics import compute_precision_at_k, evaluate_triage_policy

def test_metrics_calculation():
    y_true = np.array([1, 0, 1, 0, 0, 1, 0, 0, 0, 0])
    y_scores = np.array([0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05])
    
    # Precision@3: Top 3 are indices 0, 1, 2. Positives at 0, 2 -> 2/3 = 0.667
    p_at_3 = compute_precision_at_k(y_true, y_scores, k=3)
    assert abs(p_at_3 - 2/3) < 1e-3
    
    policy_metrics = evaluate_triage_policy(y_true, y_scores > 0.65)
    assert abs(policy_metrics['precision'] - 2/3) < 1e-3
    assert policy_metrics['patches_required'] == 3
