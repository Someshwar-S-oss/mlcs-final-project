# Report 1 — Project Proposal
**Course:** Machine Learning Cloud Services
**Date:** 05 September 2026

---

## 1. Project Title

**PatchPriority: Machine Learning for Exploitation-Likelihood Prediction and Risk-Based Vulnerability Triage on the National Vulnerability Database**

*Short title:* PatchPriority — Predicting Which Vulnerabilities Attackers Actually Use

---

## 2. Dataset

### 2.1 One-Line Description

> A snapshot of 201,542 software vulnerabilities disclosed between 2020 and 2026, taken from the U.S. National Vulnerability Database and joined to CISA's catalogue of vulnerabilities confirmed exploited in the wild and to FIRST's EPSS exploitation-probability scores — giving each vulnerability its severity rating, technical characteristics, affected products, and a ground-truth label for whether attackers were ever actually observed using it.

### 2.2 Source and Provenance

| Attribute | Detail |
|---|---|
| Dataset name | NVD CVE CVSS KEV EPSS Vulnerabilities 2020–2026 |
| Kaggle | `afr1ste/nvd-cve-cvss-kev-vulnerabilities-2020-2026` |
| Upstream sources | NVD CVE JSON 2.0 feeds (NIST) · CISA Known Exploited Vulnerabilities Catalog · FIRST EPSS current scores |
| Snapshot build date | 2026-05-02T09:53:36Z |
| Coverage | 2020-01-02 → 2026-04-28 |
| Records | **201,542 CVEs** (main table), 106 columns |
| Supporting tables | 1,550,739 CPE product-match rows · 260,862 CWE weakness rows · 708,018 reference rows · 1,585 KEV catalogue rows · 329,934 EPSS score rows |
| Positive label | **1,039 CVEs (0.52%)** present in CISA KEV |
| EPSS model | v2025.03.14, scores dated 2026-05-01 |
| Total size | ~124 MB compressed / ~600 MB uncompressed |
| Licence | Public U.S. Government sources (NVD, CISA) + FIRST EPSS; convenience snapshot, freely usable with attribution |

**Package contents.** `nvd_cve_records.csv` (and an identical `.parquet`, 41 MB vs 181 MB — use the Parquet) is the main CVE-level table. Four normalised child tables (`nvd_cve_cpe_matches`, `nvd_cve_weaknesses`, `nvd_cve_references`, `cisa_kev_catalog`, `first_epss_current`) join on `cve_id`. Six pre-aggregated summary tables and a 190-row `data_dictionary.csv` ship with it.

**Why this dataset:** it is one of the few public security datasets carrying a **ground-truth label for real-world exploitation** rather than a severity opinion. That single property is what makes the research question below answerable.

### 2.3 Data Dictionary — `nvd_cve_records` (main table, 106 columns)

Columns are grouped by function. The package includes its own `data_dictionary.csv`; the groupings and notes below are the analytical reading of it.

#### A. Identity and metadata (11 columns)

| Column | Type | Description |
|---|---|---|
| `cve_id` | str | CVE identifier, e.g. `CVE-2024-3400` — primary key, no duplicates |
| `source_identifier` | str | CNA (CVE Numbering Authority) that published the record |
| `published` / `published_date` / `published_year` | str / datetime / int | Disclosure timestamp — **the basis for the temporal train/test split** |
| `last_modified` / `last_modified_date` | str / datetime | Most recent NVD revision |
| `vuln_status` | str | NVD analysis state: `Modified`, `Analyzed`, `Deferred`, `Rejected`, `Awaiting Analysis`, `Undergoing Analysis`, `Received` |
| `description_en` | str | Free-text English vulnerability description — the primary NLP feature source |
| `description_length` | int | Character count of the description |
| `reference_count`, `weakness_count`, `cpe_match_count`, `cve_tag_count` | int | Pre-computed child-table counts; usable directly as numeric features |

#### B. CVSS base metrics — four versions (76 columns)

The dataset carries **parallel metric blocks for CVSS v4.0, v3.1, v3.0 and v2.0**, since scoring standards changed over the period. Each block repeats the same structure with a version prefix (`cvss_v40_*`, `cvss_v31_*`, `cvss_v30_*`, `cvss_v2_*`):

| Column pattern | Type | Description |
|---|---|---|
| `*_source`, `*_type` | str | Scoring organisation and whether Primary or Secondary |
| `*_vector` | str | Full CVSS vector string, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| `*_base_score` | float | Numeric severity, 0.0–10.0 |
| `*_base_severity` | str | `NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `*_attack_vector` | str | `NETWORK` / `ADJACENT_NETWORK` / `LOCAL` / `PHYSICAL` — how remote the attacker can be |
| `*_attack_complexity` | str | `LOW` / `HIGH` — conditions beyond attacker control |
| `*_privileges_required` | str | `NONE` / `LOW` / `HIGH` — access needed before attacking |
| `*_user_interaction` | str | `NONE` / `REQUIRED` — must a victim click something |
| `*_scope` | str | `UNCHANGED` / `CHANGED` — can impact cross a security boundary |
| `*_confidentiality_impact`, `*_integrity_impact`, `*_availability_impact` | str | `NONE` / `LOW` / `HIGH` — the CIA triad |
| `*_exploitability_score`, `*_impact_score` | float | The two CVSS sub-scores that combine into the base score |

CVSS v4.0 adds `attack_requirements`, `sub_confidentiality_impact`, `sub_integrity_impact`, `sub_availability_impact` and `exploit_maturity`.

**Harmonised columns** (use these rather than picking a version manually):

| Column | Type | Description |
|---|---|---|
| `best_cvss_version` | str | Which version supplied the preferred score |
| `best_cvss_base_score` | float | Preferred base score — v4.0, else v3.1, else v3.0, else v2.0 |
| `best_cvss_base_severity` | str | Severity label for the preferred score |

#### C. Weakness classification (1 column + child table)

| Column | Type | Description |
|---|---|---|
| `primary_cwe_id` | str | First CWE (Common Weakness Enumeration) ID, e.g. `CWE-79` cross-site scripting, `CWE-502` unsafe deserialisation |

Full many-to-many weakness mappings are in `nvd_cve_weaknesses.csv` (260,862 rows).

#### D. Description-derived keyword flags (5 columns) — ⚠ **see §2.6, these leak**

| Column | Type | Description |
|---|---|---|
| `mentions_rce` | bool | Description mentions remote code execution |
| `mentions_sql_injection` | bool | Description mentions SQL injection |
| `mentions_xss` | bool | Description mentions cross-site scripting |
| `mentions_exploit_public` | bool | Description mentions a public exploit |
| `mentions_buffer_overflow` | bool | Description mentions a buffer overflow |

#### E. Exploitation ground truth — the target (11 columns)

| Column | Type | Description |
|---|---|---|
| **`kev_is_known_exploited`** | bool | **PRIMARY TARGET** — True when CISA has confirmed real-world exploitation |
| `kev_dateadded` | str | When CISA added it — enables time-to-exploitation analysis |
| `kev_duedate` | str | Federal remediation deadline under CISA BOD 22-01 |
| `kev_knownransomwarecampaignuse` | str | `Known` (201 CVEs) / `Unknown` (838) — ransomware association |
| `kev_vendorproject`, `kev_product`, `kev_vulnerabilityname` | str | KEV-side product identification |
| `kev_shortdescription`, `kev_requiredaction`, `kev_notes`, `kev_cwes` | str | KEV catalogue narrative fields — **populated only for KEV rows; never use as features** |

#### F. EPSS exploitation probability (7 columns)

| Column | Type | Description |
|---|---|---|
| `epss_score` | float | FIRST EPSS probability (0–1) of exploitation in the next 30 days |
| `epss_percentile` | float | Rank among all scored CVEs |
| `epss_risk_bucket` | str | `low` / `medium` / `high` / `very_high` |
| `epss_top_1_percent`, `epss_top_5_percent` | bool | Percentile ≥ 0.99 / ≥ 0.95 |
| `epss_score_date`, `epss_model_version` | str | Snapshot provenance |

#### G. Child tables

| Table | Rows | Key columns |
|---|---|---|
| `nvd_cve_cpe_matches` | 1,550,739 | `cpe_vendor`, `cpe_product`, `cpe_version`, version range bounds, `vulnerable` |
| `nvd_cve_weaknesses` | 260,862 | `cwe_id`, `weakness_source`, `weakness_type` |
| `nvd_cve_references` | 708,018 | `reference_url`, `reference_source`, `reference_tags` (e.g. `Exploit`, `Patch`, `Vendor Advisory`) |
| `cisa_kev_catalog` | 1,585 | Full KEV catalogue including pre-2020 entries |
| `first_epss_current` | 329,934 | Full EPSS snapshot including CVEs outside this date range |

### 2.4 Target Distribution

| Split | CVEs | KEV positives | Rate |
|---|---:|---:|---:|
| All records | 201,542 | 1,039 | 0.516 % |
| After dropping `Rejected` | 194,479 | 1,039 | 0.534 % |

**Severity distribution:**

| `best_cvss_base_severity` | CVEs | Share |
|---|---:|---:|
| MEDIUM | 92,522 | 45.9 % |
| HIGH | 72,065 | 35.8 % |
| CRITICAL | 23,423 | 11.6 % |
| *(no score)* | 8,974 | 4.5 % |
| LOW | 4,512 | 2.2 % |
| NONE | 46 | 0.02 % |

At **0.53 % positives (1 in 187)**, this is a severe class-imbalance problem — accuracy is meaningless as a metric, and PR-AUC replaces ROC-AUC throughout.

### 2.5 Motivating Evidence — Computed From This Dataset

The numbers below were computed directly from `nvd_cve_records.csv` and establish that the research question is real rather than assumed.

| Triage strategy | Patches required | KEV caught | Recall | **Precision** |
|---|---:|---:|---:|---:|
| Patch all HIGH + CRITICAL | 95,488 | 908 | 87.4 % | **0.95 %** |
| Patch all CRITICAL only | 23,423 | 389 | 37.4 % | 1.66 % |
| Patch EPSS `very_high` bucket | 2,751 | 530 | 51.0 % | **19.27 %** |
| Patch EPSS top 1 % | 1,628 | 427 | 41.1 % | 26.23 % |

**The industry-standard policy — "patch everything rated High or Critical" — demands 95,488 patches and is wrong 99.05 % of the time.** Switching to the EPSS `very_high` bucket needs **34.7× fewer patches** at **20.3× better precision**, while still catching just over half of everything attackers actually used.

That gap is the project. If a probabilistic score already beats CVSS by 20×, the open question is how much further a purpose-built model can go — and, critically, whether it can do so using only information available *on the day a CVE is published*, which is when the triage decision must actually be made.

Two further signals confirm the problem is learnable:

**CWE categories carry strong, security-plausible signal** (base rate 0.534 %):

| CWE | Description | CVEs | KEV | Rate | Lift |
|---|---|---:|---:|---:|---:|
| CWE-843 | Type confusion | 483 | 28 | 5.80 % | **10.9×** |
| CWE-288 | Auth bypass via alternate path | 461 | 15 | 3.25 % | 6.1× |
| CWE-502 | Deserialisation of untrusted data | 1,971 | 44 | 2.23 % | 4.2× |
| CWE-306 | Missing authentication | 1,455 | 31 | 2.13 % | 4.0× |
| CWE-94 | Code injection | 2,043 | 39 | 1.91 % | 3.6× |
| CWE-78 | OS command injection | 3,663 | 68 | 1.86 % | 3.5× |
| CWE-416 | Use after free | 4,709 | 67 | 1.42 % | 2.7× |

**And the vulnerability classes that dominate CVE counts are the *least* weaponised** — a genuinely counterintuitive result worth foregrounding:

| Flag | CVEs | KEV | Rate | Lift |
|---|---:|---:|---:|---:|
| Mentions XSS | 27,664 | 17 | 0.06 % | **0.1×** |
| Mentions SQL injection | 12,195 | 18 | 0.15 % | **0.3×** |
| Mentions buffer overflow | 8,001 | 34 | 0.42 % | 0.8× |

XSS and SQL injection — the two categories every security curriculum leads with, and 20 % of all CVEs here — are **negatively associated with real-world exploitation**. Attackers overwhelmingly prefer type confusion, deserialisation and missing-authentication bugs. A model trained on this data will rediscover that, and the finding alone justifies the project.

Finally, a CVSS assumption fails outright: `attack_vector = NETWORK` shows a 0.56 % KEV rate against `LOCAL` at 0.57 % — **no discriminative power whatsoever**, despite remoteness being one of the heaviest weights in the CVSS formula.

### 2.6 Data Quality Issues and Modelling Traps

Six issues were identified by inspecting the actual files. The first three are ordinary cleaning; the last three are traps that would silently invalidate results.

1. **7,063 `Rejected` CVEs (3.5 %)** are withdrawn records that were never real vulnerabilities. Drop them; 194,479 remain.
2. **Missing values:** 8,974 records (4.5 %) have no CVSS score, 7,064 (3.5 %) no EPSS score, 10,069 (5.0 %) no CWE. Mostly recent CVEs still awaiting NVD analysis — missingness correlates with publication date and is therefore **not** missing-at-random.
3. **Four parallel CVSS versions** mean naive column selection loses most of the data. Use `best_cvss_*`, and retain `best_cvss_version` as a feature since scoring-standard changes are themselves informative.

4. **⚠ The `mentions_*` flags leak the target.** `mentions_rce` is `True` for 1,036 of 1,039 KEV rows (99.7 %) but only 19.7 % of all rows. Testing the flag against the NVD description text shows why: **693 of 1,039 KEV rows have `mentions_rce = True` despite `description_en` containing no RCE language at all**, versus 1,776 of 193,440 non-KEV rows — a 72× discrepancy. The flags were evidently computed over text including `kev_shortdescription`, which exists only for KEV rows. *Verified example:* `CVE-2026-33825` is described by NVD as a local privilege-escalation issue in Microsoft Defender with no code-execution language, yet carries `mentions_rce = True`; its KEV short description is the only text mentioning escalation. **All five `mentions_*` flags and every `kev_*` narrative column must be dropped and recomputed from `description_en` alone.** Left in, they produce a model reporting near-perfect AUC that has learned nothing except which rows have a KEV description attached.

5. **⚠ EPSS is an outcome, not an input.** EPSS is itself a trained exploitation-prediction model, scored 2026-05-01 — *after* every CVE in the set. Using it as a feature means predicting exploitation from an exploitation prediction. **EPSS is the baseline to beat (§3.6), never a feature.**

6. **⚠ KEV is positive-unlabelled, not binary.** The package README states this explicitly: KEV lists confirmed-exploited CVEs but makes no claim that non-KEV CVEs are unexploited. A "negative" may be genuinely unexploited, exploited but undetected, or exploited but not yet catalogued. Recent CVEs are additionally right-censored — a 2026 CVE has had months to reach KEV where a 2020 CVE has had years, which the yearly counts show (2020: 136 KEV; 2026: 48 and rising). **Consequences:** measured precision is a *lower bound*, splits must be temporal rather than random, and evaluation must be restricted to CVEs with a comparable exposure window.

---

## 3. Problem Statement

### 3.1 The Problem

A mid-sized enterprise tracks tens of thousands of open vulnerabilities across its estate and can realistically patch a few hundred per sprint. Something must decide the order.

The universal default is CVSS severity: patch Critical, then High. **Section 2.5 shows what that policy costs.** It generates 95,488 patch tickets across this dataset, of which 94,580 address vulnerabilities no attacker was ever observed using — a 0.95 % hit rate. The wasted effort is not merely inefficient; it is actively harmful, because remediation capacity spent on a theoretical Critical is capacity not spent on the Medium-rated bug currently being exploited against the company.

CVSS was never designed for this. It measures *how bad a vulnerability would be if exploited* — a property of the vulnerability in isolation. Prioritisation needs *how likely it is to be exploited at all* — a property of attacker behaviour, economics and tooling that no severity formula can capture. The two are close to uncorrelated in this data.

The project therefore asks:

1. **Prediction** — from information available *the day a CVE is published*, can we predict whether attackers will exploit it in the wild?
2. **Calibration** — can we reproduce the CVSS score itself from its components, quantifying how little independent information severity actually adds?
3. **Structure** — do vulnerabilities fall into natural archetypes with systematically different exploitation rates?
4. **Decision** — given a fixed remediation budget of N patches per sprint, which N maximise attacks prevented?

### 3.2 Why Machine Learning Is Required

- **The signal is distributed across many weak features.** No single column separates the classes: the strongest CWE gives 10.9× lift but covers only 483 CVEs, and CVSS attack vector gives none. Real predictive power requires combining CWE, product, description text and CVSS structure — precisely what a learned model does and a hand-written policy cannot.
- **The rules cannot be written by hand.** That XSS is *negatively* associated with exploitation while type confusion is 10.9× positive is not something a human would think to encode. It has to be discovered from data.
- **Attacker preference drifts.** Which weakness classes attract exploitation shifts with tooling and target mix; a model retrains, a static policy ossifies.
- **Scale.** 201,542 CVEs across 1.55M product mappings and 708k references is beyond manual triage but ideal for supervised learning.

### 3.3 Techniques Applied and Their Justification

Three techniques, each answering one question from §3.1. Section 3.4 states what was excluded and why.

#### (i) Linear Regression — reconstructing CVSS to prove its redundancy

- **Task.** Predict the continuous `best_cvss_base_score` (0.0–10.0) from the CVSS sub-metrics, CWE category and TF-IDF description features.
- **Why.** This is a **deliberate demonstration of a negative result.** CVSS base score is a deterministic formula over its own sub-metrics, so regressing it on `exploitability_score` and `impact_score` should give R² near 1.0 — proving the score contains *no information beyond its inputs*. The interesting model is the second one, which **excludes** the sub-scores and predicts severity from description text and CWE alone; the gap between the two R² values measures how much severity is recoverable from a plain-English vulnerability description. This directly motivates §3.3(ii): if CVSS is fully reconstructible yet only 0.95 % precise at triage, the problem is the target, not the model.
- **Method.** OLS baseline, then Ridge and Lasso — Lasso's feature selection over TF-IDF terms identifies which description phrases drive high severity ratings. Diagnostics: residual plots, VIF, Q–Q normality.
- **Metrics.** R², Adjusted R², RMSE, MAE.
- **Expected result.** R² > 0.95 with sub-scores (confirming redundancy); R² ≈ 0.45–0.65 from text and CWE alone. Large residuals identify CVEs whose assigned severity disagrees with their description — candidate mis-scorings worth manual review, a useful by-product.

#### (ii) Decision Tree Classification — interpretable exploitation triage rules

- **Task.** Binary classification of `kev_is_known_exploited`, using only publication-day features.
- **Why.** A security team will not act on a black-box risk score, and a compliance auditor will not accept one. A decision tree yields an **explicit, auditable rule set** — "deserialisation flaw + network-reachable + no privileges required + enterprise-server product ⇒ escalate" — that becomes a written triage policy. Trees also handle the mixed categorical/numeric feature space natively without dummy-encoding CWE's ~900 levels.
- **Method.** CART with Gini impurity; `class_weight='balanced'` for the 1:187 imbalance; `max_depth`, `min_samples_leaf` and `ccp_alpha` tuned by **time-series cross-validation** (train on 2020–2023, validate 2024, test 2025–2026) — a random split would leak future information backwards.
- **Metrics.** **PR-AUC as primary** (ROC-AUC is misleadingly flattering at 0.5 % positives), plus precision, recall, F1 on the positive class and the extracted rule set.
- **Expected result.** PR-AUC ≈ 0.15–0.30 — which sounds poor but is 28–56× the 0.0053 no-skill baseline — and a readable 10–20 leaf rule set.

#### (iii) Random Forest — maximum-accuracy ranking and driver identification

- **Task.** Same target, optimised for ranking quality rather than interpretability, using CVSS metrics, CWE, vendor/product from CPE, reference tags, description TF-IDF and structural counts.
- **Why.** Triage is fundamentally a **ranking** problem — the output that matters is an ordered list, and the operational metric is how many true exploits appear in the top N. Random Forest's averaged probability estimates rank far better than a single tree's piecewise-constant output. Bagging also stabilises variance on the 1,039 positives, where one tree would memorise noise. **Permutation feature importance answers the underlying security question — what actually makes attackers choose a vulnerability** — and `reference_tags` containing `Exploit` is expected to rank highly, since public exploit code is a strong causal driver.
- **Method.** 300–500 estimators; `class_weight='balanced_subsample'`; SMOTE applied **inside CV folds only**; temporal splits throughout. Benchmarked against the decision tree, gradient boosting, and the EPSS baseline.
- **Metrics.** PR-AUC, **precision@k and recall@k for k ∈ {100, 500, 1000, 2751}** — the real deployment metrics, where k is the sprint patch budget — plus permutation importance and calibration curves.
- **Expected result.** PR-AUC ≈ 0.25–0.40. **The headline target is precision@2751 > 19.27 %**, i.e. beating EPSS at equal effort. Top features expected: `Exploit` reference tags, CWE category, vendor/product, `privileges_required`, description terms.

#### (iv) K-Means Clustering — vulnerability archetypes

- **Task.** Cluster CVEs on standardised CVSS vectors + CWE one-hots + description TF-IDF, **labels withheld**, then measure each cluster's KEV rate.
- **Why.** Discovers **vulnerability archetypes** — natural groupings like "network-reachable unauthenticated RCE in enterprise edge appliances" versus "local privilege escalation requiring user interaction." If archetypes show sharply different exploitation rates, this yields an unsupervised triage capability that works on a *brand-new* CVE with no history, and gives the SOC a small interpretable taxonomy in place of 201,542 individual items.
- **Method.** StandardScaler → TruncatedSVD/PCA on the TF-IDF block (~95 % variance) → K-Means with `k` from elbow and silhouette analysis over k = 2…20; MiniBatchKMeans at full scale; DBSCAN compared to test whether exploited CVEs form a genuine dense region.
- **Metrics.** Silhouette, Davies–Bouldin, elbow; then per-cluster KEV rate and lift over the 0.534 % base rate. ARI and NMI against CWE families as an external check.
- **Expected result.** k ≈ 8–12; silhouette ≈ 0.20–0.40 (text data clusters loosely); **at least two clusters with KEV rates above 3 %** — 5–6× base rate — recovered without any label.

### 3.4 Techniques Considered and Deliberately Excluded

| Technique | Why excluded |
|---|---|
| **Association rule mining** | Redundant with the decision tree, which already produces human-readable if–then rules over the same features and learns them discriminatively against the label rather than filtering by co-occurrence. At a 0.53 % base rate, any rule with a KEV consequent falls below usable `min_support`, so the algorithm would surface only benign high-frequency patterns. Retained as an optional extension (§3.7). |
| **Reinforcement learning** | Requires sequential decisions where an action changes the next state. Patching decisions here are independent per CVE against a static labelled snapshot — no dynamics, so the optimal policy degenerates to ranking by predicted probability, exactly what §3.3(iii) produces directly. **The budget-constrained decision that motivates RL is instead handled properly by the precision@k analysis**, which answers "what do I patch with N slots" without inventing a fake environment. |
| **Deep learning / transformers** | Fine-tuning a language model on descriptions would likely add a few points of PR-AUC, but at 1,039 positives the sample size cannot support it, and the interpretability that makes this project *useful* to a security team would be lost. Out of scope; noted as future work. |

### 3.5 Cloud Services Component

| Stage | Service |
|---|---|
| Storage | Object storage (S3 / Azure Blob / GCS), Parquet, partitioned by `published_year` |
| Distributed preprocessing | Spark on Databricks / Glue / Dataproc — joining 1.55M CPE rows and 708k references to the main table, and TF-IDF over 194k descriptions |
| Training | Managed jobs (SageMaker / Azure ML / Vertex AI) with hyperparameter tuning |
| Tracking | MLflow — parameters, metrics, artefacts per run |
| Deployment | Registry + REST endpoint scoring a new CVE's exploitation risk on the day it is published |
| Scheduled refresh | Daily job pulling new NVD entries and the current KEV/EPSS feeds, re-scoring the backlog |
| Monitoring | Drift detection on feature distributions; alert when a newly-KEV'd CVE was ranked low, as a live recall check |

### 3.6 Expected Results and Success Criteria

| # | Deliverable | Success criterion |
|---|---|---|
| 1 | Cleaned dataset with leakage removed | `Rejected` dropped; all `mentions_*` and `kev_*` narrative columns removed and recomputed from `description_en`; EPSS held out as baseline; documented temporal split |
| 2 | CVSS reconstruction regression | R² > 0.95 with sub-scores; text-and-CWE-only model reported separately; residual outliers surfaced as candidate mis-scorings |
| 3 | Decision tree triage rules | PR-AUC ≥ 10× the no-skill baseline; ≤ 20 leaves; rule set written out as a deployable triage policy |
| 4 | Random Forest ranking model | **precision@2751 > 19.27 %, beating the EPSS `very_high` baseline at equal patch effort** |
| 5 | CVSS baseline comparison | Explicit table versus "patch all HIGH+CRITICAL" (0.95 % precision) and the four EPSS strategies from §2.5 |
| 6 | Feature importance analysis | Ranked drivers of real-world exploitation, with security interpretation of the top 20 |
| 7 | Vulnerability archetypes | ≥ 2 clusters at > 3 % KEV rate, characterised in plain language |
| 8 | Deployed endpoint | Live REST endpoint scoring a CVE in < 100 ms; MLflow history |
| 9 | Positive-unlabelled analysis | Explicit treatment of KEV censoring; precision reported as a lower bound with the reasoning stated |

### 3.7 Expected Outcome

A **cloud-deployed vulnerability triage service** that ranks newly published CVEs by predicted real-world exploitation risk, together with an evidence-based critique of the severity-first prioritisation every security team currently uses. The project is expected to show that:

- **CVSS severity is a poor triage signal** — 0.95 % precision at 95,488 patches, measured, not asserted;
- **exploitation is predictable well above chance from publication-day features**, though absolute precision stays modest because attacker behaviour is only partly determined by vulnerability properties;
- **the weakness classes security education emphasises are not the ones attackers use** — XSS at 0.1× lift and SQL injection at 0.3× versus type confusion at 10.9×;
- **the honest framing is positive-unlabelled learning**, and reporting precision as a lower bound is more defensible than treating absent KEV entries as confirmed negatives.

The deliverable is a reproducible cloud ML pipeline plus a written analysis. Its practical claim is concrete: **a security team following its ranking would address the same number of genuinely exploited vulnerabilities as the standard policy while issuing roughly 35× fewer patch tickets.**

**Optional extensions.** Association rule mining over discretised features for a signature-style rule catalogue; survival analysis on `kev_dateadded − published_date` to model *time* to exploitation rather than its occurrence; a separate model for `kev_knownransomwarecampaignuse` (201 positives) targeting ransomware-associated vulnerabilities specifically.

---

## 4. References

1. Kaggle. *NVD CVE CVSS KEV EPSS Vulnerabilities 2020–2026.* https://www.kaggle.com/datasets/afr1ste/nvd-cve-cvss-kev-vulnerabilities-2020-2026
2. NIST. *National Vulnerability Database CVE JSON 2.0 Data Feeds.* https://nvd.nist.gov/vuln/data-feeds
3. CISA. *Known Exploited Vulnerabilities Catalog.* https://www.cisa.gov/known-exploited-vulnerabilities-catalog
4. FIRST. *Exploit Prediction Scoring System (EPSS).* https://www.first.org/epss/
5. FIRST. *Common Vulnerability Scoring System v3.1: Specification Document.* https://www.first.org/cvss/v3.1/specification-document
6. CISA. *Binding Operational Directive 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities.* https://www.cisa.gov/news-events/directives/bod-22-01
7. MITRE. *Common Weakness Enumeration (CWE).* https://cwe.mitre.org/
