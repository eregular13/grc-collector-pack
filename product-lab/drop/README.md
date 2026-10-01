# Drop package

**Copied:** 2026-09-04T14:12:58Z from this Linux VM `out/` after host lab (`scripts/lab.sh`).  
**Estate:** demo (`in/` empty → fixtures). SAMPLE/DEMO. Not a client. Not a LAB dest_in prove.

See `MANIFEST` for CISO CSV + POA&M + OpenGRC + Probo row counts and SHA256.

Hand `poam/poam.csv` with the CISO CSVs. Owner and due are blank.

OpenGRC and Probo files are **file-true leave-behind, posted=false, not live import**. Do not POST `/api/risks`.

## `ciso/`

CISO Assistant Community import CSVs. Headers are the contract. `risk_scenarios.csv` is **semicolon**-separated. Finding severity `low|medium|high|critical`. Vuln severity `Information|Low|Medium|High|Critical`. Asset type `PR` or `SP`. `filtering_labels` include wizard-safe `cpg_2_W` / `csf_*` (no colons).

Preferred import: clica or CISO Assistant UI. Do not invent FindingsAssessment UUIDs.

| File | Rows |
|---|---|
| `assets.csv` | 62 |
| `findings.csv` | 62 |
| `vulnerabilities.csv` | 15 |
| `evidences.csv` | 24 |
| `applied_controls.csv` | 77 |
| `risk_scenarios.csv` | 77 |

## `poam/`

Operator draft. Not a CISO import. Owner and due stay blank.

| File | Rows |
|---|---|
| `poam.csv` | 61 |
| `poam.md` | same draft, markdown |

Example: open TCP/445 on `filesrv.corp.local` → restrict SMB / confirm SMBv1 disabled (`cpg_2_W`, `csf_PR`). Port finding, not a CVE.

## `opengrc/`

OpenGRC Data Manager CSVs (Risks / Assets / Implementations). File-true leave-behind. posted=false. Not live import. Do not POST `/api/risks`.

| File | Rows |
|---|---|
| `risks.csv` | 82 |
| `assets.csv` | 62 |
| `implementations.csv` | 77 |

Operator path: Data Manager → Import Data → map headers. Status is **Not Assessed**. No taxonomy FKs invented.

## `import_preview/` + `probo/`

Probo drafts (`addFinding` / `addRisk`). File-true, posted=false, documentation-only. Not live GraphQL. `organization_id` stays null.

| File | Rows |
|---|---|
| `import_preview/probo.json` | 77 addFinding drafts |

Do not POST `/api/risks`.
