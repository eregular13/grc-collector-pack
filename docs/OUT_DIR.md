# Output directories

| Dir | What | After `run_lab.ps1` |
| --- | --- | --- |
| `out/` | Pack loader fixture (Litware demo CSVs, summary 132/155/9, fixture POA&M SMBv1) | **Overwritten** by collectors + loader |
| `dropbox/out/` | Orchestrator dest for the last plan/run | Live-byo POA&M if estate SCOPE ran |
| `out/opengrc/` | OpenGRC Data Manager CSVs (`assets.csv`, `risks.csv`) | `python -m dropbox.import_grc --target opengrc --dry-run` |
| `out/probo/` | Probo `addFinding` plan JSON (no createRisk) | `python -m dropbox.import_grc --target probo --dry-run` |
| `out-estate/` | Copy of **this estate run** (poam/quote/simplerisk) | Written by `python -m dropbox.product_demo` |
| `engagements/<slug>/out/` | Kit copy for the zip | Estate slug uses `out-estate/`, not leftover Litware `out/` |
| `engagements/engagement-<slug>-YYYYMMDD.zip` and `-ready.zip` | Product zip (POA&M inside) | **Not touched** by `run_lab.ps1`. Pack `out/poam` becomes fixture SMBv1; slug zip keeps estate rows. |

Rule: do not treat pack `out/poam/poam.csv` as the Docker estate after a host lab. The product zip for `docker-estate-product` is built from `out-estate/` / `dropbox/out`.

CISO auto-push (assets.csv + evidences.csv) is still the pack loader path. Estate findings/POA&M stay HITL (`out-estate/poam/poam.csv`).
