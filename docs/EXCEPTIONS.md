# Known exceptions / SoR misses

Honest list. These are accepted, not hidden.

| ID | Item | Why |
|---|---|---|
| EX-NMAP-NAME | Two Nmap hosts that share a hostname collide on asset `ref_id` / lowercase name dedupe | Loader dedupes assets by lowercase name. Distinct IPs with the same PTR collapse to one PR asset. |
| EX-LYNIS | No Lynis parser | Start spec named many OSS tools; Lynis reports are not ingested. Duplicate “add Lynis” suggestions should not open a new container. |
| EX-FLEET-NOHOST | Fleet host with no `hostname` / `computer_name` / `display_name` / `id` | Skipped (hostile test). Not invented as `unknown`. |
| EX-EMPTY-SARIF | SARIF file with empty `runs` | Emits no findings; fixture fallback only if the whole collector parsed nothing. |
| EX-PUSH-DRY | `push_ciso.sh` never POST `/api/risks`; `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1` | LICENSE-LOCK stay-out. High/critical stay in `risks_proposed.json`. |
| EX-DONE-STALE | `DONE.md` quoted cycle-1 counts until cycle 5 stamp | Historical. Live counts are `out/summary.json`. |
| EX-PYTEST-WIN | pytest atexit `PermissionError` on `pytest-of-R` | Windows temp symlink cleanup. Tests still pass. |
