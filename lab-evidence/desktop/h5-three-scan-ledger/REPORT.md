# H5 REPORT — three-scan ledger stability (REPORT ONLY)

Stamp run 1: `20260926-212350` (PT start ~21:23; nmap UTC `2026-09-27 04:23Z`)  
Pack base: `ce67328` (`hermes/testbed-base-2026-09-26`)  
Branch: `hermes/h5-three-scan-ledger-2026-09-26`  
Lab: evergreen-lab **48/48** containers (labnet 172.28.10.0/24 + labnet2 172.28.11.0/24). LAB != SAMPLE != client. No `/api/risks`. No live GRC write. RiskReady stay-out. **No product code changes.**

This slice is **run 1 baseline only**. Run 2 is the identical rescan ~1h later (next cron tick) carrying `in/poam/poam-ledger.json` + `in/assets/asset-ledger.json`. Run 3 is the deliberate delta (redis `requirepass` on one host, stop ftp, add nginx autoindex) then revert. CR7-C 1→2 and 2→3 tables land after those scans.

## Run 1 commands (exit codes)

H1 pipeline via `lab-estate/scripts/h5_three_scan_ledger.py` (ops tree). Nuclei **skipped** (H1 blocker; do not loop).

| Step | Command (abbrev) | rc |
|---|---|---|
| docker baseline | `docker ps` evergreen-lab | 48 Up |
| nmap labnet | `instrumentisto/nmap:latest -sT -sV` + #124 NSE, `--network evergreen-lab_labnet` | **0** |
| nmap labnet2 | same, `evergreen-lab_labnet2` | **0** |
| nikto 29 web URLs | `ghcr.io/sullo/nikto:latest -h http://IP:PORT/ -maxtime 30s` | 0 (29/29) |
| testssl nginx:80 | `drwetter/testssl.sh` `172.28.10.10:80` (no TLS on web) | non-zero / not TLS (JSON written) |
| nuclei | skipped — H1 templates-missing then hung empty jsonl | n/a |
| trivy image ×11 | `aquasec/trivy image --format json` unique compose images | **0 all 11** |
| prove | `C:/Python314/python.exe scripts/prove_ciso.py --work …/h5-run1-20260926-212350 --use-existing-in` then `--verify-only` | **0** |

Networks: **only** 172.28.10.0/24 and 172.28.11.0/24. No overlay. Did not start/stop containers this slice.

## Run 1 scanner counts

nmap: **48 hosts up**, **51 open ports**. Ports: 80×28, 6379×8, 2222×2, 27017×2, 3306×2, 139×2, 445×2, 5432×2, 21×1, 1025×1, 8025×1.  
NSE: http-title 29, redis-info **8**, http-enum 10, smb2-security-mode 2, ssl-enum-ciphers/ssl-cert 2 (MySQL 3306), ftp-anon **0**, mysql-empty-password **0**.

## Run 1 prove_ciso --use-existing-in

`prove-ciso.json`: lab=true sample=false client=false seeded=false posted=false paying_day=FAIL. sensors nmap+vuln.

| counter | n |
|---|---|
| assets.csv | 58 |
| findings.csv (Extra Import) | 63 |
| poam.csv | 754 |
| poam_fedramp.csv (open) | 754 |
| poam_fedramp_closed.csv | 0 |
| ledger items | 768 |
| EGA uids (asset-ledger) | 58 |
| vulnerabilities.csv | 3356 |
| risk_scenarios | 3419 |

poam.csv **754 =** poam_fedramp.csv **754**. Ghosts between those two files: **0**.

Vs H1 same-day earlier prove (`20260926-115811`): poam 747 → 754 (+7). Trivy DB re-download this run (version jitter expected on CVE rows).

## CR7 section C — run 1 (no prior ledger)

| Metric | run 1 (baseline) | run 1→2 | run 2→3 |
|---|---|---|---|
| IDs kept | n/a (first mint) | *pending run 2* | *pending run 3* |
| IDs new | **754** EGP- minted | | |
| Closed (`poam_fedramp_closed.csv`) | **0** | | |
| Ghost rows (fedramp Δ poam.csv) | **0** | | |
| Ledger warnings | **LEDGER_LOST** (no `in/poam/poam-ledger.json`) | expect clear if carry works | |
| Original Detection Date | **706** = `2026-09-27` (nmap Zulu day); **48** = `not recorded` | | |
| Asset EGA | **58** uids | | |
| Blank carried (POC / Resources / Scheduled Completion) | **754 / 754 / 754** | | |

Blank POC + Resources Required + Scheduled Completion Date on every Open row is cited for **#190** (carried blanks). Remediation Plan is filled (0 blank).

Detection calendar is UTC from the nmap artifact (`2026-09-27`), not PT civil `2026-09-26`. Run 2 ~2h later the same UTC day should keep `2026-09-27` if first-seen holds.

## Evidence paths

- `lab-evidence/desktop/h5-three-scan-ledger/LAB.txt`
- `lab-evidence/desktop/h5-three-scan-ledger/run1/` (LAB.txt, raw nmap/nikto/trivy/testssl, prove-ciso.json, snapshot.json, prove/poam_fedramp.csv + poam-ledger.json + asset-ledger.json)
- Operator dest_in (not in git): `lab-estate/prove-work/h5-run1-20260926-212350`
- State for run 2 carry: `lab-estate/scans/H5_STATE.json`

## Next slice

1. Wait ~1h from run 1 (`20260926-212350`).  
2. Identical H1 pipeline rescan → run 2. Carry ledgers into dest_in.  
3. CR7-C table run 1→2 (IDs kept/new/closed/ghosts/dates/EGA).  
4. Later: run 3 lab delta + revert + baseline confirm. Restore docker 48/48.

## Honesty

LAB Docker estate. Not SAMPLE. Not client KEEP. Did not flip client_facing_ready. posted=false. No live GRC. No product parser fixes. Nuclei not retried.
