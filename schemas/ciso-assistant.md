# CISO Assistant Community ingest

Auth: `Authorization: Token <PAT>`
API default: `http://localhost:8000/api`

CISO Assistant is Reid-side SoR. Prefer clica or UI CSV import. Do not invent FindingsAssessment UUIDs.

`push_ciso.sh` defaults to dry-run. REST may POST `/api/assets/` and `/api/evidences/` only when `CISO_PUSH=1` and `DRY_RUN!=1`. Never POST `/api/risks`.

Files land in `out/ciso-assistant/`.

## assets.csv

```
ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets
```

`type` is `PR` (hosts/clusters/cloud) or `SP` (identities/SaaS).

## applied_controls.csv

```
ref_id,name,description,domain,status,category,priority,csf_function
```

- status: `to_do|in_progress|on_hold|active|deprecated`
- category: `policy|process|technical|physical|procedure`
- priority: `1-4`
- csf_function: `govern|identify|protect|detect|respond|recover`

## evidences.csv

```
name,description
```

## findings.csv

```
ref_id,name,description,severity,status,filtering_labels
```

severity: `low|medium|high|critical` (canonical `info` maps to `low`).

## vulnerabilities.csv

```
ref_id,name,description,status,severity,assets,applied_controls
```

severity: `Information|Low|Medium|High|Critical`
status default: `Exploitable`
Mapped when category is `vulnerability|secrets|sast` or `ref_id` starts with `CVE`.

## risk_scenarios.csv

Semicolon-delimited:

```
ref_id;assets;threats;name;description;existing_controls;current_impact;current_proba;current_risk;additional_controls;residual_impact;residual_proba;residual_risk;treatment
```

treatment: `mitigate`
Severity → `Low|Moderate|High|Very High`

## OCSF

`out/ocsf/compliance_findings.json` — array of Compliance Finding objects, `class_uid` 2003.
