# KEEP-chain samples — not a client KEEP drop

These four families are **redacted fixtures** for `make keep-lab`. They are
**not** client KEEP files. Pack `in/` on this checkout is empty; keep-lab
lands these samples under `keep/work/in/` (never pack `in/`).

| Family | Sample file | Layer C sensor |
|---|---|---|
| HardeningKitty | `identity/hardeningkitty.csv` | `in/identity/` |
| Maester | `saas/maester.json` | `in/saas/` |
| testssl | `vuln/testssl.json` | `in/vuln/` |
| Prowler \| ScoutSuite | `cloud/prowler.json` (+ optional `scoutsuite.json`) | `in/cloud/` |

Hosts, tenants, and account IDs use `.invalid` / `000000000000`. Actual HK
values are `[REDACTED]`. Each JSON file sets `"sample": true`.

**SAMPLE ≠ client KEEP.** A real engagement drops operator-landed KEEP
exports into pack `in/<sensor>/`. keep-lab prefers those when all four
families are present **and** the files do not carry the sample banner.
Until then the lab stays `sample: true` / `demo: true`.

Eval consumes `keep/work/out/eval/handoff.json` as a file. This pack does
not call Origin Eval over HTTP and does not POST `/api/risks`.
