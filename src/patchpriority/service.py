"""Exploitation-risk scoring service for newly published CVEs.

    python -m patchpriority.service train                 # fit on 2020-2024, save the model
    python -m patchpriority.service score CVE-2025-24085  # score CVEs from the dataset
    python -m patchpriority.service serve --port 8000     # HTTP API

POST /score accepts one CVE object or a list of them. Only `description_en` is required;
other fields (see INPUT_FIELDS) improve the score when present. Response per CVE:
{"cve_id", "exploit_probability", "lift"}, where lift = probability / training base rate.
"""
import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import joblib
import pandas as pd

from patchpriority.data import CLEAN_KEYWORDS, load_and_preprocess_dataset
from patchpriority.features import CATEGORICAL_FEATURES, FEATURES
from patchpriority.models.logistic import TARGET, make_logistic_ranker

DEFAULT_DATA = Path('archive (1)/nvd_cve_records.parquet')
DEFAULT_MODEL = Path('artifacts/ranker.joblib')
INPUT_FIELDS = ['cve_id', 'description_en', 'best_cvss_base_score'] + CATEGORICAL_FEATURES
MAX_BODY_BYTES = 1_000_000


def prepare_records(records: list[dict]) -> pd.DataFrame:
    """Turn raw CVE dicts into the model's feature frame (derived columns recomputed)."""
    for r in records:
        if not isinstance(r, dict) or not isinstance(r.get('description_en'), str):
            raise ValueError('each CVE must be an object with a string "description_en"')
    df = pd.DataFrame(records).reindex(columns=INPUT_FIELDS)
    df['description_en'] = df['description_en'].fillna('')
    df['description_length'] = df['description_en'].str.len()
    for kw_name, pattern in CLEAN_KEYWORDS.items():
        df[kw_name] = df['description_en'].apply(lambda text: int(bool(pattern.search(text))))
    df['best_cvss_base_score'] = pd.to_numeric(df['best_cvss_base_score'], errors='coerce')
    df['cna_cwe'] = df['cna_cwe'].fillna('NONE')
    df[CATEGORICAL_FEATURES] = df[CATEGORICAL_FEATURES].fillna('NA').astype(str)
    return df


def score(bundle: dict, df: pd.DataFrame) -> list[dict]:
    p = bundle['pipeline'].predict_proba(df[FEATURES])[:, 1]
    return [{'cve_id': cid if isinstance(cid, str) else None,
             'exploit_probability': round(float(prob), 6),
             'lift': round(float(prob / bundle['base_rate']), 2)}
            for cid, prob in zip(df['cve_id'], p)]


def train(data: Path, model: Path, through_year: int = 2024) -> dict:
    train_df, val_df, test_df = load_and_preprocess_dataset(data)
    fit_df = pd.concat([train_df, val_df, test_df])
    fit_df = fit_df[fit_df['published_year'] <= through_year]
    pipe = make_logistic_ranker().fit(fit_df[FEATURES], fit_df[TARGET].astype(int))
    bundle = {'pipeline': pipe, 'base_rate': float(fit_df[TARGET].mean()), 'trained_through': through_year}
    model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model)
    print(f'Trained on {len(fit_df):,} CVEs (<= {through_year}), saved {model}')
    return bundle


def make_handler(bundle: dict):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == '/health':
                self._send(200, {'status': 'ok', 'trained_through': bundle['trained_through']})
            else:
                self._send(404, {'error': 'not found'})

        def do_POST(self):
            if self.path != '/score':
                return self._send(404, {'error': 'not found'})
            length = int(self.headers.get('Content-Length') or 0)
            if not 0 < length <= MAX_BODY_BYTES:
                return self._send(413 if length else 400, {'error': f'body must be 1..{MAX_BODY_BYTES} bytes'})
            try:
                payload = json.loads(self.rfile.read(length))
                records = payload if isinstance(payload, list) else [payload]
                self._send(200, score(bundle, prepare_records(records)))
            except (ValueError, TypeError) as e:
                self._send(400, {'error': str(e)})

    return Handler


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('command', choices=['train', 'score', 'serve'])
    ap.add_argument('cve_ids', nargs='*', help='CVE IDs to score (score command)')
    ap.add_argument('--data', type=Path, default=DEFAULT_DATA)
    ap.add_argument('--model', type=Path, default=DEFAULT_MODEL)
    ap.add_argument('--through-year', type=int, default=2024)
    ap.add_argument('--port', type=int, default=8000)
    args = ap.parse_args(argv)

    if args.command == 'train':
        train(args.data, args.model, args.through_year)
        return
    if not args.model.exists():
        sys.exit(f'{args.model} not found; run `python -m patchpriority.service train` first')
    bundle = joblib.load(args.model)

    if args.command == 'score':
        parts = load_and_preprocess_dataset(args.data)
        df = pd.concat(parts).set_index('cve_id', drop=False)
        missing = [c for c in args.cve_ids if c not in df.index]
        found = df.loc[[c for c in args.cve_ids if c in df.index]]
        for row in score(bundle, found):
            print(f"{row['cve_id']}  p={row['exploit_probability']:.4f}  lift={row['lift']}x  "
                  f"in KEV: {bool(found.loc[row['cve_id'], TARGET])}")
        for c in missing:
            print(f'{c}  not in dataset')
    else:
        server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(bundle))
        print(f'Serving on http://127.0.0.1:{args.port}  (POST /score, GET /health)')
        server.serve_forever()


if __name__ == '__main__':
    main()
