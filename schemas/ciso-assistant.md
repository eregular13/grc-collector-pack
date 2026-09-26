# CISO Assistant Community ingest

Auth: `Authorization: Token <PAT>`
API default: `http://localhost:8000/api`

CISO Assistant is Reid-side SoR. Operator source of record is `out/ciso-assistant/*.csv` from `python3 -m dropbox ciso`. Prefer [clica](https://github.com/intuitem/ciso-assistant-community) or UI CSV import. Do not invent FindingsAssessment UUIDs.

`push_ciso.sh` defaults to dry-run. REST may POST `/api/assets/` and `/api/evidences/` only when `CISO_PUSH=1` and `DRY_RUN!=1`. Never POST `/api/risks`.

Conductor `export_ciso_poam` reads `out/ciso-assistant/` + `out/poam/` (+ SimpleRisk leave-behind under `out/simplerisk/`). `posted` is **false** unless `CISO_PUSH=1` and `DRY_RUN!=1`. Conductor `http` is always **false** — `RISKREADY_PUSH=1` does not enable HTTP.

Files land in `out/ciso-assistant/`.

## Desktop (no make / no gh)

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
python3 -m keep lab                  # SAMPLE keep-samples → keep/work/out/ciso-assistant/*.csv (primary)
# then: clica   or   CISO UI import of those CSVs (see IMPORT.md)
python3 -m dropbox ciso              # landed KEEP-minimum or sensor-dir files → out/ciso-assistant/*.csv
# then: clica   or   bash push_ciso.sh
python3 -m dropbox mcp export_ciso_poam
python3 scripts/prove_ciso.py        # SAMPLE/DEMO fixture prove → prove/work/out/ciso-assistant (≠ paying-day PASS)
```

`posted` stays false unless `CISO_PUSH=1`. This agent never runs `push_ciso.sh`. Desktop has no `make` / `gh`.

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
Farm leave-behind pack_drop is observation/exposure — `vulnerabilities.csv` may be header-only. The risk register is `findings.csv` + `risk_scenarios.csv`. Do not invent CVE-class rows from open-port observations.

## risk_scenarios.csv

Semicolon-delimited:

```
ref_id;assets;threats;name;description;existing_controls;current_impact;current_proba;current_risk;additional_controls;residual_impact;residual_proba;residual_risk;treatment
```

treatment: `mitigate`
Severity → `Low|Moderate|High|Very High`
One row per canonical finding. `findings.csv` rows > 0 requires `risk_scenarios.csv` rows > 0.

## POA&M (operator draft — not a CISO import)

`out/poam/poam.csv` and `out/poam/poam.md`. Hand to the client with the CISO CSVs.

```
weakness,asset,severity,framework_refs,recommended_fix,owner,due,status,estate,poam_id,finding_ref_id,controls,weakness_description,detector_source,weakness_source_id,original_detection_date,scheduled_completion_date,status_date,milestones,original_risk_rating,point_of_contact,cve
```

FedRAMP POA&M R3.0-style fields (appended; the first nine columns are unchanged):

- `poam_id` = `POAM-<ref_id>`; `finding_ref_id` links to `findings.csv` `ref_id`.
- `controls` = SP 800-53 Rev. 5 ids from `control_map` (blank when unmapped, never invented).
- `weakness_description` = finding description; `detector_source` = collector + tool (e.g. `inventory-nmap (nmap NSE ftp-anon)`); `weakness_source_id` = check/plugin/rule id or blank.
- `original_detection_date` = artifact scan timestamp calendar day (Nessus HOST_START/HOST_END, nmap starttime, SARIF startTimeUtc, Trivy CreatedAt, pack_drop meta generated_at, file-level scan time). Literal `not recorded` when the artifact has none — never the pack run date. Dates keep the recorded timezone (UTC when the artifact is Zulu); poam.md labels the zone. The poam.csv column name is unchanged.
- `scheduled_completion_date` = DEFAULT detection + 30 days (Critical/High), 90 (Moderate), 180 (Low) when a real detection date exists; `pending due date` when detection is `not recorded`. `due` stays blank until a human commits a date.
- `status_date` = run date; `milestones` = three dated defaults (validate, apply fix, rescan to verify).
- `original_risk_rating` = Low/Moderate/High/Critical (`severity` keeps the legacy low/medium/high/critical vocabulary for existing readers).
- `point_of_contact` is blank, like `owner`. `cve` = explicit CVE ids or known aliases (Heartbleed -> CVE-2014-0160), else blank.

- `estate` is the run watermark: `LAB`, `SAMPLE`, `DEMO`, or `UNLABELED` (never client).
  `poam.md` opens with an `ESTATE: ...` banner. CISO import CSVs keep their headers;
  `findings.csv` / `assets.csv` carry an `estate_<label>` token in `filtering_labels`
  and `ciso-assistant/ESTATE.txt` states the label.

- High/critical findings and key medium exposures (SMB 445, RDP 3389) are included.
- `framework_refs` are wizard-safe `cpg_*` / `csf_*` stamps (no colons).
- `owner`, `point_of_contact`, and `due` stay blank. Status is `open`. Scheduled completion and milestone dates are labeled defaults, not commitments.
- Recommended fix is a control narrative (e.g. restrict TCP/445, confirm SMBv1 disabled). Port-open is not a CVE.

## OCSF

`out/ocsf/compliance_findings.json` — array of Compliance Finding objects, `class_uid` 2003.

## Other sinks (same CSVs)

`python3 -m exporters` reads these files and writes OpenGRC / Probo drops.
CISO headers stay the contract. See [opengrc.md](opengrc.md) and [probo.md](probo.md).
