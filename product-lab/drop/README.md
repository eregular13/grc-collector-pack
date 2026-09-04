# Drop package

**Copied:** 2026-09-04T05:08:28Z from this Linux VM `out/` after host lab (`scripts/lab.sh`).  
**Estate:** demo (`in/` empty → fixtures). Not a client.

See `MANIFEST` for CISO CSV row counts and SHA256.

## `ciso/`

CISO Assistant Community import CSVs. Headers are the contract. `risk_scenarios.csv` is **semicolon**-separated. Finding severity `low|medium|high|critical`. Vuln severity `Information|Low|Medium|High|Critical`. Asset type `PR` or `SP`. `filtering_labels` include wizard-safe `cpg_2_W`.

Preferred import: clica or CISO Assistant UI. Do not invent FindingsAssessment UUIDs.

| File | Rows |
|---|---|
| `assets.csv` | 62 |
| `findings.csv` | 59 |
| `vulnerabilities.csv` | 15 |
| `evidences.csv` | 10 (nine sensors + loader) |
| `applied_controls.csv` | 74 |
| `risk_scenarios.csv` | 74 |

## `riskready/`

LICENSE-LOCK stay-out. Review on disk. Never wrap, login, or POST.

| File | Role |
|---|---|
| `assets.json` | inventory |
| `incidents.json` | explicit + high/critical findings |
| `evidence.json` | TECHNICAL / SENSOR / DRAFT |
| `risks_proposed.json` | human review only — never POST `/api/risks` |
