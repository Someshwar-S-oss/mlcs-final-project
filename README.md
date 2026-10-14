# PatchPriority

Predicts which newly published CVEs attackers will actually exploit (CISA KEV), using only
information available on publication day. Course project for Machine Learning Cloud Services;
the proposal is `Report-1_PatchPriority.md`, the full analysis is `patch_priority.ipynb`.

## Setup

```sh
python -m venv .venv && .venv/Scripts/activate      # Windows (source .venv/bin/activate elsewhere)
pip install -e ".[notebook,dev]"
```

The dataset lives in `archive (1)/` (Kaggle `afr1ste/nvd-cve-cvss-kev-vulnerabilities-2020-2026`).

## Use

```sh
pytest                                              # ~2 min, runs on data samples
python notebooks/generate_notebook.py               # rebuild + execute the notebook (~2 min)

python -m patchpriority.service train               # fit ranker on 2020-2024 -> artifacts/ranker.joblib
python -m patchpriority.service score CVE-2026-32201
python -m patchpriority.service serve --port 8000   # HTTP API
curl -X POST localhost:8000/score -d '{"cve_id": "x", "description_en": "Microsoft Exchange Server Remote Code Execution Vulnerability", "source_identifier": "secure@microsoft.com", "best_cvss_base_score": 9.8}'
```

`/score` takes one CVE object or a list. Only `description_en` is required; `source_identifier`,
`cna_cwe`, `best_cvss_base_score` and `cvss_*` metrics (see `patchpriority.features`) improve the score.
It returns `exploit_probability` and `lift` (probability ÷ training base rate).

## Layout

| Path | What |
|---|---|
| `src/patchpriority/data.py` | Load, drop rejected/leaky columns, temporal split |
| `src/patchpriority/features.py` | Leak-free publication-day feature set + preprocessing |
| `src/patchpriority/metrics.py` | Precision@k, PR-AUC, CVSS/EPSS baseline policies |
| `src/patchpriority/models/` | Regression, decision tree, random forest, logistic ranker, K-Means |
| `src/patchpriority/service.py` | Train / score / serve CLI |

## Results (test split 2025–2026, 0.36% exploited)

| Ranker | PR-AUC | Precision in top 224 |
|---|---|---|
| CVSS base score | 0.016 | 4.0% |
| Decision tree (15 leaves) | 0.018 | 3.1% |
| Random forest | 0.060 | 7.6% |
| **Logistic, text + metadata (served)** | **0.087** | **13.4%** |
| EPSS (scored later with exploit telemetry; upper bound) | 0.323 | 36.6% |
