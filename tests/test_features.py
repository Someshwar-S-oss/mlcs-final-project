from patchpriority.features import FEATURES

def test_no_leaky_features():
    # Each of these is populated mostly *because* a CVE was exploited (see features.py docstring).
    leaky = {'vuln_status', 'reference_count', 'cpe_match_count', 'weakness_count', 'primary_cwe_id',
             'last_modified', 'kev_is_known_exploited'}
    assert not leaky & set(FEATURES)
    assert not [f for f in FEATURES if f.startswith(('epss_', 'kev_', 'mentions_'))]
