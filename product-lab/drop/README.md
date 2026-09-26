# Drop package

**Copied:** 2026-09-26T06:47:46Z from this Linux VM `out/` after host lab (`scripts/lab.sh`).  
**Estate:** demo (`in/` empty → fixtures). SAMPLE/DEMO. Not a client. Not a LAB dest_in prove.

See `MANIFEST` for CISO CSV + POA&M + OpenGRC + Probo row counts and SHA256.

Hand `poam/poam.csv` with the CISO CSVs. Owner and due are blank.

OpenGRC and Probo files are **file-true leave-behind, posted=false, not live import**. Do not POST `/api/risks`.

## `ciso/`

CISO Assistant Community import CSVs. Headers are the contract. `risk_scenarios.csv` is **semicolon**-separated. Finding severity `low|medium|high|critical`. Vuln severity `Information|Low|Medium|High|Critical`. Asset type `PR` or `SP`. `filtering_labels` include wizard-safe `cpg_2_W` / `csf_*` (no colons).

`filtering_labels` include `estate_demo`. `ciso/ESTATE.txt` is the estate banner sidecar (import CSVs stay header-first). Preferred import: clica or CISO Assistant UI. Do not invent FindingsAssessment UUIDs.

| File | Rows |
|---|---|
| `assets.csv` | 84 |
| `findings.csv` | 103 |
| `vulnerabilities.csv` | 22 |
| `evidences.csv` | 33 |
| `applied_controls.csv` | 125 |
| `risk_scenarios.csv` | 125 |

## `poam/`

Operator draft. Not a CISO import. Owner and due stay blank. `poam.csv` has an `estate` column (DEMO/SAMPLE/LAB, never client KEEP). Banner lives in `poam/ESTATE.txt` plus `EXECUTIVE_SUMMARY.md` / `SCOPE_AND_TRUST.md`.

| File | Rows |
|---|---|
| `poam.csv` | 125 |
| `poam.md` | same draft, markdown |

Example: open TCP/445 on `filesrv.corp.local` → restrict SMB / confirm SMBv1 disabled (`cpg_2_W`, `csf_PR`). Port finding, not a CVE.

## `opengrc/`

OpenGRC Data Manager CSVs (Risks / Assets / Implementations). File-true leave-behind. posted=false. Not live import. Do not POST `/api/risks`.

| File | Rows |
|---|---|
| `risks.csv` | 143 |
| `assets.csv` | 84 |
| `implementations.csv` | 125 |

Operator path: Data Manager → Import Data → map headers. Status is **Not Assessed**. No taxonomy FKs invented.

## `import_preview/` + `probo/`

Probo drafts (`addFinding` / `addRisk`). File-true, posted=false, documentation-only. Not live GraphQL. `organization_id` stays null.

| File | Rows |
|---|---|
| `import_preview/probo.json` | 125 addFinding drafts |

Do not POST `/api/risks`.
