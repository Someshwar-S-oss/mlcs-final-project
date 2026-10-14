from typing import Tuple
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.cluster import MiniBatchKMeans

def discover_vulnerability_archetypes(
    df: pd.DataFrame, 
    k: int = 30,
    max_features: int = 2000,
    n_components: int = 50
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Performs unsupervised clustering with labels withheld.
    Maps discovered clusters back to KEV rates to identify high-risk archetypes.
    """
    df_clean = df.copy()
    vec = TfidfVectorizer(max_features=max_features, stop_words='english')
    X_tfidf = vec.fit_transform(df_clean['description_en'].fillna(''))
    
    n_comp = min(n_components, X_tfidf.shape[1] - 1)
    svd = TruncatedSVD(n_components=n_comp, random_state=42)
    X_reduced = svd.fit_transform(X_tfidf)
    
    kmeans = MiniBatchKMeans(n_clusters=k, batch_size=2048, random_state=42)
    df_clean['cluster'] = kmeans.fit_predict(X_reduced)
    
    overall_kev_rate = df_clean['kev_is_known_exploited'].mean()
    
    summary = []
    terms = vec.get_feature_names_out()
    
    for cluster_id in range(k):
        sub = df_clean[df_clean['cluster'] == cluster_id]
        cve_count = len(sub)
        kev_count = int(sub['kev_is_known_exploited'].sum())
        kev_rate = float(sub['kev_is_known_exploited'].mean()) if cve_count > 0 else 0.0
        lift = float(kev_rate / overall_kev_rate) if overall_kev_rate > 0 else 0.0
        
        # Extract top keywords
        sub_tfidf = vec.transform(sub['description_en'].head(100))
        mean_tfidf = np.asarray(sub_tfidf.mean(axis=0)).flatten()
        top_indices = mean_tfidf.argsort()[::-1][:5]
        top_words = ", ".join([terms[i] for i in top_indices])
        
        summary.append({
            'cluster': cluster_id,
            'cve_count': cve_count,
            'kev_count': kev_count,
            'kev_rate': round(kev_rate * 100, 2),
            'lift': round(lift, 2),
            'top_terms': top_words
        })
        
    summary_df = pd.DataFrame(summary).sort_values(by='kev_rate', ascending=False)
    return df_clean, summary_df
