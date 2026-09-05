# Drop package

**Copied:** 2026-09-04T14:12:58Z from this Linux VM `out/` after host lab (`scripts/lab.sh`).  
**Estate:** demo (`in/` empty → fixtures). Not a client.

See `MANIFEST` for CISO CSV + POA&M row counts and SHA256.

**Pentera finds it; Evergreen maps it.** Hand `poam/poam.csv` with the CISO CSVs. Owner and due are blank.

## `ciso/`

CISO Assistant Community import CSVs. Headers are the contract. `risk_scenarios.csv` is **semicolon**-separated. Finding severity `low|medium|high|critical`. Vuln severity `Information|Low|Medium|High|Critical`. Asset type `PR` or `SP`. `filtering_labels` include wizard-safe `cpg_2_W` / `csf_*` (no colons).

Preferred import: clica or CISO Assistant UI. Do not invent FindingsAssessment UUIDs.

| File | Rows |
|---|---|
| `assets.csv` | 62 |
| `findings.csv` | 59 |
| `vulnerabilities.csv` | 15 |
| `evidences.csv` | 24 (sensor runs + high/critical attestations + loader) |
| `applied_controls.csv` | 74 |
| `risk_scenarios.csv` | 74 |

## `poam/`

Operator draft. Not a CISO import. Owner and due stay blank.

| File | Rows |
|---|---|
| `poam.csv` | 58 |
| `poam.md` | same draft, markdown |

Example: open TCP/445 on `filesrv.corp.local` → restrict SMB / confirm SMBv1 disabled (`cpg_2_W`, `csf_PR`). Port finding, not a CVE.

## `riskready/`

LICENSE-LOCK stay-out. Review on disk. Never wrap, login, or POST.

| File | Role |
|---|---|
| `assets.json` | inventory |
| `incidents.json` | explicit + high/critical findings |
| `evidence.json` | TECHNICAL / SENSOR / DRAFT |
| `risks_proposed.json` | human review only — never POST `/api/risks` |
