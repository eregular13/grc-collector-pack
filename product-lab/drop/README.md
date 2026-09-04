# Drop package

**Copied:** 2026-09-03 21:45 America/Los_Angeles from `C:\Users\R\grc-collector-pack\out\` after the product-lab compose + negative suite.  
**Estate:** demo (`in/` empty → fixtures). Not a client.

## `ciso/`

CISO Assistant Community import CSVs. Headers are the contract. `risk_scenarios.csv` is **semicolon**-separated. Finding severity `low|medium|high|critical`. Vuln severity `Information|Low|Medium|High|Critical`. Asset type `PR` or `SP`. `filtering_labels` include wizard-safe `cpg_2_W`.

| File | Role |
|---|---|
| `assets.csv` | 62 rows + header |
| `findings.csv` | 59 |
| `vulnerabilities.csv` | 15 |
| `evidences.csv` | 10 (nine sensors + loader) |
| `applied_controls.csv` | 74 |
| `risk_scenarios.csv` | 74 |

SHA256 `assets.csv`: `4CFAB51E09CFC1D4930609114A08670187ACCF2928C07D4DC783471BE216172B`

## `riskready/`

| File | Role |
|---|---|
| `assets.json` | inventory |
| `incidents.json` | explicit + high/critical findings |
| `evidence.json` | TECHNICAL / SENSOR / DRAFT |
| `assets.json` `evidence.json` `incidents.json` `risks_proposed.json` | **LICENSE-LOCK stay-out — review on disk. Never wrap or POST.** |

SHA256 `risks_proposed.json`: `E10DE14A57A876F5BA18ED00C22769C6AD60AB7158C5757DC60F54DD5FA9C91C`
