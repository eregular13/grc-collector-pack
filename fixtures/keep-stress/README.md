# KEEP stress fixtures — fail-closed shapes

These trees are **not** SAMPLE success fixtures and **not** a client KEEP drop.
Brick 3 of the scan→risk register+POA&M depth plan: incomplete and malformed
KEEP packages must fail closed with a stable code on the cold SAMPLE→SoR /
keep-preflight path. They must not write SoR CSVs as if success and must not
silent skip-to-PASS.

See `CATALOG.json` for shape id → expected `KEEP_FIXTURE_*` code.

| id | expected code |
|---|---|
| `truncated-json` | `KEEP_FIXTURE_TRUNCATED_JSON` |
| `garbage-binary` | `KEEP_FIXTURE_GARBAGE_BINARY` |
| `wrong-schema` | `KEEP_FIXTURE_WRONG_SCHEMA` |
| `missing-leaf` | `KEEP_FIXTURE_MISSING_LEAF` |
| `empty-required` | `KEEP_FIXTURE_EMPTY` |
| `claim-mismatch` | `KEEP_FIXTURE_CLAIM_MISMATCH` |
| `corrupt-zip` | `KEEP_FIXTURE_CORRUPT_ZIP` |

`python -m keep lab` / MCP `keep_status` + `keep_ciso` / `require_keep_samples`
must name the code. SAMPLE/DEMO labels stay honest. No new operator entrypoint.
