# H5 REPORT — three-scan ledger stability (REPORT ONLY)

Pack base: `ce67328` (`hermes/testbed-base-2026-09-26`)  
Branch: `hermes/h5-three-scan-ledger-2026-09-26`  
Lab: evergreen-lab **48/48** containers (labnet 172.28.10.0/24 + labnet2 172.28.11.0/24). LAB != SAMPLE != client. No `/api/risks`. No live GRC write. RiskReady stay-out. **No product code changes.**

| Run | Stamp | Role |
|---|---|---|
| 1 | `20260926-212350` (nmap UTC `2026-09-27 04:23Z`) | baseline (LEDGER_LOST; first mint) |
| 2 | `20260926-233806` (nmap UTC `2026-09-27 06:38Z`) | identical rescan ~2h later; carried `in/poam/poam-ledger.json` + `in/assets/asset-ledger.json` |
| 3 | *pending next slice* | redis `requirepass` on one host, stop ftp, add nginx autoindex; then revert to 48/48 |

Nuclei **skipped** (H1 blocker; do not loop).

## Run 2 commands (exit codes)

H1 pipeline via `lab-estate/scripts/h5_three_scan_ledger.py run2` with `H5_STAMP=20260926-233806`.

| Step | Command (abbrev) | rc |
|---|---|---|
| docker baseline | `docker ps` evergreen-lab | **48 Up** (pre and post) |
| nmap labnet | `instrumentisto/nmap:latest -sT -sV` + #124 NSE, `--network evergreen-lab_labnet` | **0** |
| nmap labnet2 | same, `evergreen-lab_labnet2` | **0** |
| nikto 29 web URLs | `ghcr.io/sullo/nikto:latest -h http://IP:PORT/ -maxtime 30s` | 0 (29/29) |
| testssl nginx:80 | `drwetter/testssl.sh` `172.28.10.10:80` (no TLS on web) | non-zero / not TLS (JSON written) |
| nuclei | skipped — H1 templates-missing then hung empty jsonl | n/a |
| trivy image ×11 | `aquasec/trivy image --format json` unique compose images | **0 all 11** |
| carry | run1 `out/poam/poam-ledger.json` + `out/assets/asset-ledger.json` → run2 `in/` | copied |
| prove | `C:/Python314/python.exe scripts/prove_ciso.py --work …/h5-run2-20260926-233806 --use-existing-in` then `--verify-only` | **0** |

Networks: **only** 172.28.10.0/24 and 172.28.11.0/24. No overlay. Did not start/stop containers this slice.

## Scanner counts (run 1 vs run 2)

nmap both runs: **48 hosts up**, **51 open ports**. Ports: 80×28, 6379×8, 2222×2, 27017×2, 3306×2, 139×2, 445×2, 5432×2, 21×1, 1025×1, 8025×1.  
NSE both: http-title 29, redis-info **8**, http-enum 10, smb2-security-mode 2, ssl-enum-ciphers/ssl-cert 2 (MySQL 3306), ftp-anon **0**, mysql-empty-password **0**.

## prove_ciso --use-existing-in

| counter | run 1 | run 2 |
|---|---|---|
| assets.csv | 58 | 58 |
| findings.csv (Extra Import) | 63 | 63 |
| poam.csv | 754 | 754 |
| poam_fedramp.csv (open) | 754 | 754 |
| poam_fedramp_closed.csv | 0 | 0 |
| ledger items | 768 | 768 |
| EGA uids (asset-ledger) | 58 | 58 |
| vulnerabilities.csv | 3356 | 3356 |
| risk_scenarios | 3419 | 3419 |
| ledger warnings | **LEDGER_LOST** | **[]** (carry held) |
| posted / lab / sample / client | false / true / false / false | same |
| paying_day | FAIL | FAIL |

poam.csv **754 =** poam_fedramp.csv **754**. Ghosts between those two files: **0** both runs.

## CR7 section C

| Metric | run 1 (baseline) | run 1→2 | run 2→3 |
|---|---|---|---|
| IDs kept | n/a (first mint) | **754** | *pending run 3* |
| IDs new | **754** EGP- minted | **0** | |
| IDs gone from open | n/a | **0** | |
| Closed (`poam_fedramp_closed.csv`) | **0** | **0** new | |
| Ghost rows (fedramp Δ poam.csv) | **0** | **0** | |
| Ledger warnings | **LEDGER_LOST** (no prior `in/poam/poam-ledger.json`) | **cleared** | |
| Original Detection Date | **706** = `2026-09-27`; **48** = `not recorded` | **0 changed** (still 706 / 48) | |
| Asset EGA | **58** uids | **58 kept / 0 new / 0 lost** | |
| Blank carried (POC / Resources / Scheduled Completion) | **754 / 754 / 754** | **754 / 754 / 754** (unchanged) | |

Blank POC + Resources Required + Scheduled Completion Date on every Open row is cited for **#190** (carried blanks). Remediation Plan is filled (0 blank). First-seen dates held across the UTC-day rescan.

Compare JSON: `lab-evidence/desktop/h5-three-scan-ledger/compare-run1-run2.json`.

## Evidence paths

- `lab-evidence/desktop/h5-three-scan-ledger/LAB.txt`
- `lab-evidence/desktop/h5-three-scan-ledger/run1/` (baseline)
- `lab-evidence/desktop/h5-three-scan-ledger/run2/` (LAB.txt, raw nmap/nikto/trivy/testssl, prove-ciso.json, snapshot.json, nmap-counts.json, prove/poam_fedramp.csv + poam-ledger.json + asset-ledger.json)
- Operator dest_in (not in git): `lab-estate/prove-work/h5-run2-20260926-233806`
- State for run 3 carry: `lab-estate/scans/H5_STATE.json`

## Next slice

1. Run 3 lab delta: enable redis `requirepass` on **one** host, stop **one** ftp, add **one** new nginx with autoindex.  
2. Identical H1 pipeline → run 3. Carry run 2 ledgers.  
3. CR7-C table run 2→3 (IDs kept/new/closed/ghosts/dates/EGA).  
4. **Revert** the delta. Confirm docker **48/48**. Do not leave extra containers.

## Honesty

LAB Docker estate. Not SAMPLE. Not client KEEP. Did not flip client_facing_ready. posted=false. No live GRC. No product parser fixes. Nuclei not retried. File-true leave-behind is export, not tenant import.
