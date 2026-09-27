# H5 REPORT — three-scan ledger stability (REPORT ONLY)

Pack base: `ce67328` (`hermes/testbed-base-2026-09-26`)  
Branch: `hermes/h5-three-scan-ledger-2026-09-26`  
Lab: evergreen-lab **48/48** containers restored after run 3 (labnet 172.28.10.0/24 + labnet2 172.28.11.0/24). LAB != SAMPLE != client. No `/api/risks`. No live GRC write. RiskReady stay-out. **No product code changes.**

| Run | Stamp | Role |
|---|---|---|
| 1 | `20260926-212350` (nmap UTC `2026-09-27 04:23Z`) | baseline (LEDGER_LOST; first mint) |
| 2 | `20260926-233806` (nmap UTC `2026-09-27 06:38Z`) | identical rescan ~2h later; carried run1 ledgers |
| 3 | `20260927-015301` (nmap UTC `2026-09-27 08:53Z`) | delta: redis `requirepass` on `evergreen-lab-redis-1`, `docker stop` ftp, nginx autoindex `172.28.10.90`; then revert to 48/48 |

Nuclei **skipped** (H1 blocker; do not loop).

## Run 3 commands (exit codes)

H1 pipeline via `lab-estate/scripts/h5_three_scan_ledger.py run3` with `H5_STAMP=20260927-015301`. Delta via `h5_run3_delta.py apply|revert`.

| Step | Command (abbrev) | rc |
|---|---|---|
| docker pre | `docker ps` evergreen-lab | **48 Up** |
| delta apply | redis `CONFIG SET requirepass`; `docker stop evergreen-lab-ftp-1`; `docker run` nginx autoindex `172.28.10.90` (no host publish) | **0** |
| nmap labnet | `instrumentisto/nmap:latest -sT -sV` + #124 NSE, `--network evergreen-lab_labnet` | **0** |
| nmap labnet2 | same, `evergreen-lab_labnet2` | **0** |
| nikto 30 web URLs | `ghcr.io/sullo/nikto:latest -h http://IP:PORT/ -maxtime 30s` (includes `.90`) | 0 (30/30) |
| testssl nginx:80 | `drwetter/testssl.sh` `172.28.10.10:80` (no TLS on web) | non-zero / not TLS (JSON written) |
| nuclei | skipped — H1 templates-missing then hung empty jsonl | n/a |
| trivy image ×11 | `aquasec/trivy image --format json` unique compose images | **0 all 11** |
| carry | run2 `out/poam/poam-ledger.json` + `out/assets/asset-ledger.json` → run3 `in/` | copied |
| prove | `C:/Python314/python.exe scripts/prove_ciso.py --work …/h5-run3-20260927-015301 --use-existing-in` then `--verify-only` | **0** |
| revert | `docker rm -f h5-delta-nginx-autoindex`; `docker start ftp`; `docker restart redis` | **0**; redis unauth `PONG`; **48/48** |

Networks: **only** 172.28.10.0/24 and 172.28.11.0/24. No overlay. No `/api/risks`.

## Scanner counts

| | run 1 | run 2 | run 3 (delta) |
|---|---|---|---|
| nmap hosts up | 48 | 48 | **48** (ftp down + nginx `.90` in) |
| open ports | 51 | 51 | **51** (port 21 gone, port 80 **29** vs 28) |
| redis-info NSE | 8 | 8 | **7** (`172.28.10.63` requirepass; INFO refused) |
| ftp-anon NSE | 0 | 0 | **0** (ftp container stopped; no tcp/21) |
| http-title | 29 | 29 | **30** (autoindex host) |

Run 3 ports: 80×29, 6379×8, 2222×2, 27017×2, 3306×2, 139×2, 445×2, 5432×2, 1025×1, 8025×1. **No 21.**

## prove_ciso --use-existing-in

| counter | run 1 | run 2 | run 3 |
|---|---|---|---|
| assets.csv | 58 | 58 | **58** (Extra Import did not add the delta host) |
| findings.csv (Extra Import) | 63 | 63 | 63 |
| poam.csv | 754 | 754 | **756** |
| poam_fedramp.csv (open) | 754 | 754 | **756** |
| poam_fedramp_closed.csv | 0 | 0 | **0** |
| ledger items | 768 | 768 | **770** |
| EGA uids (asset-ledger) | 58 | 58 | **59** (`EGA-F4067CE3BD`) |
| vulnerabilities.csv | 3356 | 3356 | 3356 |
| risk_scenarios | 3419 | 3419 | 3419 |
| ledger warnings | **LEDGER_LOST** | **[]** | **[]** |
| posted / lab / sample / client | false / true / false / false | same | same |
| paying_day | FAIL | FAIL | FAIL |

poam.csv **756 =** poam_fedramp.csv **756**. Ghosts between those two files: **0** all runs.

## CR7 section C

| Metric | run 1 (baseline) | run 1→2 | run 2→3 (delta) |
|---|---|---|---|
| IDs kept | n/a (first mint) | **754** | **754** |
| IDs new | **754** EGP- minted | **0** | **2** `EGP-C3A3194C96`, `EGP-5AD2119A2A` |
| IDs gone from open | n/a | **0** | **0** |
| Closed (`poam_fedramp_closed.csv`) | **0** | **0** new | **0** new |
| Ghost rows (fedramp Δ poam.csv) | **0** | **0** | **0** |
| Ledger warnings | **LEDGER_LOST** | **cleared** | **cleared** |
| Original Detection Date | **706** = `2026-09-27`; **48** = `not recorded` | **0 changed** | **0 changed** (707 / 49) |
| Asset EGA | **58** uids | **58 kept / 0 new / 0 lost** | **58 kept / 1 new / 0 lost** |
| Blank carried (POC / Resources / Scheduled Completion) | **754 / 754 / 754** | **754 / 754 / 754** | **756 / 756 / 756** (#190) |

Blank POC + Resources Required + Scheduled Completion Date on every Open row is cited for **#190** (carried blanks). Remediation Plan was filled on the 754 carried rows; the **2 new** rows also have plans in fedramp (snapshot `Overall Remediation Plan` blank count **2** is the new open-port + listing pair vs carried 0).

Compare JSON: `compare-run1-run2.json`, `compare-run2-run3.json`.

## Delta vs ledger (the point of run 3)

Applied (verified): redis-1 `PING` → `NOAUTH Authentication required.`; ftp container stopped; wget on `.90` returned `<h1>Index of /</h1>`.

| Intent | Scanner | POA&M / ledger |
|---|---|---|
| redis requirepass on **one** host | redis-info **8→7**; tcp/6379 still open | **`Redis accessible without authentication` `EGP-AE21306146` stayed open** (not closed). New **`Open port 6379/redis` `EGP-5AD2119A2A`** appeared on the same asset (`detected` = `not recorded`). |
| stop **one** ftp | tcp/21 absent | **`FTP exposed` `EGP-F94CC7EBF6` stayed open** (ids_gone=0, closed=0). Trivy image CVEs for `stilliard/pure-ftpd:latest` also stayed (image scan, not runtime). |
| add nginx autoindex | http-title 29→30; nikto `.90` | **New** `HTTP directory listing enabled` **`EGP-C3A3194C96`** on `h5-delta-nginx-autoindex.evergreen-lab_labnet (80/TCP)`. New EGA **`EGA-F4067CE3BD`**. Extra Import `assets.csv` stayed 58. |

Report only: no product fixes. Runtime disappear (ftp down, redis AUTH) did **not** close POA&M rows. New listing **did** mint. That close-gap plus blank POC/Resources/Scheduled Completion is evidence for **#190**.

## Revert

`h5_run3_delta.py revert`: extra nginx removed, ftp started, redis restarted (compose has no requirepass) → unauth `PONG`. `docker-post-revert.json`: evergreen-lab **48**, extra_delta **[]**, ftp_up **true**.

## Evidence paths

- `lab-evidence/desktop/h5-three-scan-ledger/LAB.txt`
- `lab-evidence/desktop/h5-three-scan-ledger/run1/` (baseline)
- `lab-evidence/desktop/h5-three-scan-ledger/run2/`
- `lab-evidence/desktop/h5-three-scan-ledger/run3/` (LAB.txt, raw nmap/nikto/trivy/testssl, prove-ciso.json, snapshot.json, nmap-counts.json, docker-baseline.json, docker-post-revert.json, delta-state.json, prove/poam_fedramp.csv + ledgers)
- Operator dest_in (not in git): `lab-estate/prove-work/h5-run3-20260927-015301`

## Honesty

LAB Docker estate. Not SAMPLE. Not client KEEP. Did not flip client_facing_ready. posted=false. No live GRC. No product parser fixes. Nuclei not retried. File-true leave-behind is export, not tenant import. Baseline 48/48 restored.
