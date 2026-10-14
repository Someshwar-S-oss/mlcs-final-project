# Data Dictionary — NVD CVE CVSS KEV EPSS Vulnerabilities (2020–2026)

**File used:** `nvd_cve_records.csv` / `nvd_cve_records.parquet` (main table, from `archive (1).zip`)

## Shape of the Data

| | |
|---|---|
| **No. of Rows** | 201,542 |
| **No. of Columns** | 106 |

## Total Storage Size

| File | Size |
|---|---|
| `nvd_cve_records.csv` (main table) | 173.2 MB |
| `nvd_cve_records.parquet` (same table, compressed columnar) | 39.9 MB |
| Full package, all 17 files uncompressed (main table + 5 child tables + 6 summary tables + docs) | 582.4 MB (0.57 GB) |
| Downloaded zip archive (compressed) | 118.5 MB (124,209,139 bytes) |

*Note: the package also ships 6 child/reference tables joined on `cve_id` — `nvd_cve_cpe_matches.csv` (1,550,739 rows), `nvd_cve_weaknesses.csv` (260,862 rows), `nvd_cve_references.csv` (708,018 rows), `cisa_kev_catalog.csv` (1,585 rows) and `first_epss_current.csv` (329,934 rows). The dictionary below covers the 106-column main table only, which is the table this project models.*

## Features (Variable)

| # | Feature (Variable) | Type Variable | Description |
|---:|---|---|---|
| 1 | `cve_id` | Identifier | CVE identifier (primary key), e.g. CVE-2024-3400. |
| 2 | `source_identifier` | Categorical (Nominal) | CVE Numbering Authority (CNA) that published the record. |
| 3 | `published` | Categorical (Nominal) | NVD published timestamp (raw string). |
| 4 | `last_modified` | Categorical (Nominal) | NVD last-modified timestamp (raw string). |
| 5 | `vuln_status` | Categorical (Nominal) | NVD analysis workflow status (Modified, Analyzed, Deferred, Rejected, etc.). |
| 6 | `description_en` | Text (free-form) | English-language CVE description text (primary NLP feature source). |
| 7 | `description_length` | Numerical (Discrete) | Character count of `description_en`. |
| 8 | `cve_tag_count` | Numerical (Discrete) | Count of NVD-assigned tags on the record. |
| 9 | `reference_count` | Numerical (Discrete) | Number of external reference URLs attached to the CVE. |
| 10 | `weakness_count` | Numerical (Discrete) | Number of CWE weakness mappings attached to the CVE. |
| 11 | `cpe_match_count` | Numerical (Discrete) | Number of affected-product (CPE) match rows attached to the CVE. |
| 12 | `cvss_v40_source` | Categorical (Nominal) | CVSS v4.0 — scoring organisation for this version. |
| 13 | `cvss_v40_type` | Categorical (Nominal) | CVSS v4.0 — whether this score is Primary or Secondary. |
| 14 | `cvss_v40_vector` | Categorical (Structured string) | CVSS v4.0 — full vector string, e.g. `CVSS:4.0/AV:N/AC:L/...`. |
| 15 | `cvss_v40_base_score` | Numerical (Continuous) | CVSS v4.0 — numeric severity score, 0.0–10.0. |
| 16 | `cvss_v40_base_severity` | Categorical (Nominal) | CVSS v4.0 — severity label: NONE/LOW/MEDIUM/HIGH/CRITICAL. |
| 17 | `cvss_v40_attack_vector` | Categorical (Nominal) | CVSS v4.0 — how remote the attacker can be: NETWORK/ADJACENT_NETWORK/LOCAL/PHYSICAL. |
| 18 | `cvss_v40_attack_complexity` | Categorical (Nominal) | CVSS v4.0 — conditions beyond attacker control: LOW/HIGH. |
| 19 | `cvss_v40_privileges_required` | Categorical (Nominal) | CVSS v4.0 — access level needed before attacking: NONE/LOW/HIGH. |
| 20 | `cvss_v40_user_interaction` | Categorical (Nominal) | CVSS v4.0 — whether a victim must take an action: NONE/REQUIRED. |
| 21 | `cvss_v40_scope` | Categorical (Nominal) | CVSS v4.0 — whether impact can cross a security boundary: UNCHANGED/CHANGED. |
| 22 | `cvss_v40_confidentiality_impact` | Categorical (Nominal) | CVSS v4.0 — impact on confidentiality: NONE/LOW/HIGH. |
| 23 | `cvss_v40_integrity_impact` | Categorical (Nominal) | CVSS v4.0 — impact on integrity: NONE/LOW/HIGH. |
| 24 | `cvss_v40_availability_impact` | Categorical (Nominal) | CVSS v4.0 — impact on availability: NONE/LOW/HIGH. |
| 25 | `cvss_v40_exploitability_score` | Numerical (Continuous) | CVSS v4.0 — exploitability sub-score (ease of attack). |
| 26 | `cvss_v40_impact_score` | Numerical (Continuous) | CVSS v4.0 — impact sub-score (severity of consequences). |
| 27 | `cvss_v40_attack_requirements` | Categorical (Nominal) | CVSS v4.0 only — prerequisite conditions for the attack to succeed. |
| 28 | `cvss_v40_sub_confidentiality_impact` | Categorical (Nominal) | CVSS v4.0 only — confidentiality impact to the subsequent system. |
| 29 | `cvss_v40_sub_integrity_impact` | Categorical (Nominal) | CVSS v4.0 only — integrity impact to the subsequent system. |
| 30 | `cvss_v40_sub_availability_impact` | Categorical (Nominal) | CVSS v4.0 only — availability impact to the subsequent system. |
| 31 | `cvss_v40_exploit_maturity` | Categorical (Nominal) | CVSS v4.0 only — maturity of known exploit code (temporal-style metric). |
| 32 | `cvss_v31_source` | Categorical (Nominal) | CVSS v3.1 — scoring organisation for this version. |
| 33 | `cvss_v31_type` | Categorical (Nominal) | CVSS v3.1 — whether this score is Primary or Secondary. |
| 34 | `cvss_v31_vector` | Categorical (Structured string) | CVSS v3.1 — full vector string, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. |
| 35 | `cvss_v31_base_score` | Numerical (Continuous) | CVSS v3.1 — numeric severity score, 0.0–10.0. |
| 36 | `cvss_v31_base_severity` | Categorical (Nominal) | CVSS v3.1 — severity label: NONE/LOW/MEDIUM/HIGH/CRITICAL. |
| 37 | `cvss_v31_attack_vector` | Categorical (Nominal) | CVSS v3.1 — how remote the attacker can be: NETWORK/ADJACENT_NETWORK/LOCAL/PHYSICAL. |
| 38 | `cvss_v31_attack_complexity` | Categorical (Nominal) | CVSS v3.1 — conditions beyond attacker control: LOW/HIGH. |
| 39 | `cvss_v31_privileges_required` | Categorical (Nominal) | CVSS v3.1 — access level needed before attacking: NONE/LOW/HIGH. |
| 40 | `cvss_v31_user_interaction` | Categorical (Nominal) | CVSS v3.1 — whether a victim must take an action: NONE/REQUIRED. |
| 41 | `cvss_v31_scope` | Categorical (Nominal) | CVSS v3.1 — whether impact can cross a security boundary: UNCHANGED/CHANGED. |
| 42 | `cvss_v31_confidentiality_impact` | Categorical (Nominal) | CVSS v3.1 — impact on confidentiality: NONE/LOW/HIGH. |
| 43 | `cvss_v31_integrity_impact` | Categorical (Nominal) | CVSS v3.1 — impact on integrity: NONE/LOW/HIGH. |
| 44 | `cvss_v31_availability_impact` | Categorical (Nominal) | CVSS v3.1 — impact on availability: NONE/LOW/HIGH. |
| 45 | `cvss_v31_exploitability_score` | Numerical (Continuous) | CVSS v3.1 — exploitability sub-score (ease of attack). |
| 46 | `cvss_v31_impact_score` | Numerical (Continuous) | CVSS v3.1 — impact sub-score (severity of consequences). |
| 47 | `cvss_v30_source` | Categorical (Nominal) | CVSS v3.0 — scoring organisation for this version. |
| 48 | `cvss_v30_type` | Categorical (Nominal) | CVSS v3.0 — whether this score is Primary or Secondary. |
| 49 | `cvss_v30_vector` | Categorical (Structured string) | CVSS v3.0 — full vector string. |
| 50 | `cvss_v30_base_score` | Numerical (Continuous) | CVSS v3.0 — numeric severity score, 0.0–10.0. |
| 51 | `cvss_v30_base_severity` | Categorical (Nominal) | CVSS v3.0 — severity label: NONE/LOW/MEDIUM/HIGH/CRITICAL. |
| 52 | `cvss_v30_attack_vector` | Categorical (Nominal) | CVSS v3.0 — how remote the attacker can be: NETWORK/ADJACENT_NETWORK/LOCAL/PHYSICAL. |
| 53 | `cvss_v30_attack_complexity` | Categorical (Nominal) | CVSS v3.0 — conditions beyond attacker control: LOW/HIGH. |
| 54 | `cvss_v30_privileges_required` | Categorical (Nominal) | CVSS v3.0 — access level needed before attacking: NONE/LOW/HIGH. |
| 55 | `cvss_v30_user_interaction` | Categorical (Nominal) | CVSS v3.0 — whether a victim must take an action: NONE/REQUIRED. |
| 56 | `cvss_v30_scope` | Categorical (Nominal) | CVSS v3.0 — whether impact can cross a security boundary: UNCHANGED/CHANGED. |
| 57 | `cvss_v30_confidentiality_impact` | Categorical (Nominal) | CVSS v3.0 — impact on confidentiality: NONE/LOW/HIGH. |
| 58 | `cvss_v30_integrity_impact` | Categorical (Nominal) | CVSS v3.0 — impact on integrity: NONE/LOW/HIGH. |
| 59 | `cvss_v30_availability_impact` | Categorical (Nominal) | CVSS v3.0 — impact on availability: NONE/LOW/HIGH. |
| 60 | `cvss_v30_exploitability_score` | Numerical (Continuous) | CVSS v3.0 — exploitability sub-score (ease of attack). |
| 61 | `cvss_v30_impact_score` | Numerical (Continuous) | CVSS v3.0 — impact sub-score (severity of consequences). |
| 62 | `cvss_v2_source` | Categorical (Nominal) | CVSS v2.0 — scoring organisation for this version. |
| 63 | `cvss_v2_type` | Categorical (Nominal) | CVSS v2.0 — whether this score is Primary or Secondary. |
| 64 | `cvss_v2_vector` | Categorical (Structured string) | CVSS v2.0 — full vector string. |
| 65 | `cvss_v2_base_score` | Numerical (Continuous) | CVSS v2.0 — numeric severity score, 0.0–10.0. |
| 66 | `cvss_v2_base_severity` | Categorical (Nominal) | CVSS v2.0 — severity label: NONE/LOW/MEDIUM/HIGH/CRITICAL. |
| 67 | `cvss_v2_attack_vector` | Categorical (Nominal) | CVSS v2.0 — how remote the attacker can be: NETWORK/ADJACENT_NETWORK/LOCAL/PHYSICAL. |
| 68 | `cvss_v2_attack_complexity` | Categorical (Nominal) | CVSS v2.0 — conditions beyond attacker control: LOW/HIGH. |
| 69 | `cvss_v2_privileges_required` | Categorical (Nominal) | CVSS v2.0 — access level needed before attacking: NONE/LOW/HIGH. |
| 70 | `cvss_v2_user_interaction` | Categorical (Nominal) | CVSS v2.0 — whether a victim must take an action: NONE/REQUIRED. |
| 71 | `cvss_v2_scope` | Categorical (Nominal) | CVSS v2.0 — whether impact can cross a security boundary: UNCHANGED/CHANGED. |
| 72 | `cvss_v2_confidentiality_impact` | Categorical (Nominal) | CVSS v2.0 — impact on confidentiality: NONE/LOW/HIGH. |
| 73 | `cvss_v2_integrity_impact` | Categorical (Nominal) | CVSS v2.0 — impact on integrity: NONE/LOW/HIGH. |
| 74 | `cvss_v2_availability_impact` | Categorical (Nominal) | CVSS v2.0 — impact on availability: NONE/LOW/HIGH. |
| 75 | `cvss_v2_exploitability_score` | Numerical (Continuous) | CVSS v2.0 — exploitability sub-score (ease of attack). |
| 76 | `cvss_v2_impact_score` | Numerical (Continuous) | CVSS v2.0 — impact sub-score (severity of consequences). |
| 77 | `best_cvss_version` | Categorical (Nominal) | Which CVSS version supplied the preferred score (4.0, else 3.1, else 3.0, else 2.0). |
| 78 | `best_cvss_base_score` | Numerical (Continuous) | Preferred CVSS base score, 0.0–10.0 (harmonised across versions). |
| 79 | `best_cvss_base_severity` | Categorical (Nominal) | Severity label for the preferred score: NONE/LOW/MEDIUM/HIGH/CRITICAL. |
| 80 | `primary_cwe_id` | Categorical (Nominal) | First CWE (weakness type) ID reported by NVD, e.g. CWE-79. |
| 81 | `mentions_rce` | Categorical (Boolean) | Description-derived flag: mentions remote code execution. ⚠ Leaks the target — drop before modelling (see §2.6 of the project report). |
| 82 | `mentions_sql_injection` | Categorical (Boolean) | Description-derived flag: mentions SQL injection. |
| 83 | `mentions_xss` | Categorical (Boolean) | Description-derived flag: mentions cross-site scripting. |
| 84 | `mentions_exploit_public` | Categorical (Boolean) | Description-derived flag: mentions a public exploit. |
| 85 | `mentions_buffer_overflow` | Categorical (Boolean) | Description-derived flag: mentions a buffer overflow. |
| 86 | `kev_is_known_exploited` | Categorical (Boolean) | **TARGET VARIABLE.** True if CISA confirmed real-world exploitation. |
| 87 | `epss_score` | Numerical (Continuous) | FIRST EPSS probability (0–1) of exploitation in the next 30 days. Baseline to beat — not a feature. |
| 88 | `epss_percentile` | Numerical (Continuous) | FIRST EPSS percentile rank among all scored CVEs. |
| 89 | `epss_score_date` | Categorical (Nominal) | EPSS snapshot publication timestamp. |
| 90 | `epss_model_version` | Categorical (Nominal) | FIRST EPSS model version used to score. |
| 91 | `epss_risk_bucket` | Categorical (Nominal) | Coarse EPSS bucket: low / medium / high / very_high. |
| 92 | `epss_top_1_percent` | Categorical (Boolean) | True if EPSS percentile ≥ 0.99. |
| 93 | `epss_top_5_percent` | Categorical (Boolean) | True if EPSS percentile ≥ 0.95. |
| 94 | `kev_vendorproject` | Categorical (Nominal) | KEV catalogue vendor/project name (populated for KEV rows only). |
| 95 | `kev_product` | Categorical (Nominal) | KEV catalogue product name (populated for KEV rows only). |
| 96 | `kev_vulnerabilityname` | Categorical (Nominal) | KEV catalogue short vulnerability name (KEV rows only). |
| 97 | `kev_dateadded` | Categorical (Nominal) | Date CISA added the CVE to the KEV catalogue. |
| 98 | `kev_shortdescription` | Categorical (Nominal) | KEV catalogue narrative description (KEV rows only). Never use as a feature. |
| 99 | `kev_requiredaction` | Categorical (Nominal) | KEV catalogue required remediation action (KEV rows only). |
| 100 | `kev_duedate` | Categorical (Nominal) | Federal remediation deadline under CISA BOD 22-01 (KEV rows only). |
| 101 | `kev_knownransomwarecampaignuse` | Categorical (Nominal) | Known / Unknown — ransomware-campaign association (KEV rows only). |
| 102 | `kev_notes` | Categorical (Nominal) | KEV catalogue free-text notes (KEV rows only). |
| 103 | `kev_cwes` | Categorical (Nominal) | CWE IDs as recorded in the KEV catalogue entry (KEV rows only). |
| 104 | `published_date` | DateTime | Parsed datetime version of `published`. |
| 105 | `published_year` | Numerical (Discrete) | Publication year, extracted from `published_date`. |
| 106 | `last_modified_date` | DateTime | Parsed datetime version of `last_modified`. |

### Summary by Type

| Type Variable | Count |
|---|---:|
| Categorical (Nominal) | 65 |
| Numerical (Continuous) | 15 |
| Categorical (Structured string) | 8 |
| Categorical (Boolean) | 8 |
| Numerical (Discrete) | 6 |
| DateTime | 2 |
| Identifier | 1 |
| Text (free-form) | 1 |
| **Total** | **106** |
