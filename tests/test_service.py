import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from patchpriority.data import load_and_preprocess_dataset
from patchpriority.features import FEATURES
from patchpriority.models.logistic import TARGET, make_logistic_ranker
from patchpriority.service import make_handler, prepare_records

def test_score_endpoint():
    train_df, _, _ = load_and_preprocess_dataset(Path("archive (1)/nvd_cve_records.parquet"), sample_frac=0.05)
    pipe = make_logistic_ranker().fit(train_df[FEATURES], train_df[TARGET].astype(int))
    bundle = {'pipeline': pipe, 'base_rate': float(train_df[TARGET].mean()), 'trained_through': 2023}

    server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(bundle))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_port}/score'

    def post(payload):
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method='POST')
        return json.loads(urllib.request.urlopen(req).read())

    try:
        rows = post([
            {'cve_id': 'A', 'description_en': 'Windows Kernel Elevation of Privilege Vulnerability',
             'source_identifier': 'secure@microsoft.com', 'best_cvss_base_score': 7.8},
            {'cve_id': 'B', 'description_en': 'Stored XSS in the WordPress plugin settings page.'},
        ])
        assert [r['cve_id'] for r in rows] == ['A', 'B']
        assert all(0 <= r['exploit_probability'] <= 1 for r in rows)
        assert rows[0]['exploit_probability'] > rows[1]['exploit_probability']

        with pytest.raises(urllib.error.HTTPError) as e:
            post({'cve_id': 'C'})  # missing description_en
        assert e.value.code == 400
    finally:
        server.shutdown()

def test_prepare_records_rejects_non_objects():
    with pytest.raises(ValueError):
        prepare_records(['not an object'])
