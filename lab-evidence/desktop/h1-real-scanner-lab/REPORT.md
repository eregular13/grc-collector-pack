# H1 REPORT — real-scanner LAB run + ground-truth grading

Stamp: `20260926-115811`  
Pack base: `ce67328` (`hermes/testbed-base-2026-09-26`)  
Branch: `hermes/h1-real-scanner-lab-2026-09-26`  
Lab: evergreen-lab 48 containers (labnet 172.28.10.0/24 + labnet2 172.28.11.0/24). LAB != SAMPLE != client. No `/api/risks`. No live GRC write. RiskReady stay-out.

## Commands (exit codes)

| Step | Command (abbrev) | rc |
|---|---|---|
| nmap labnet | `docker run --rm --network evergreen-lab_labnet -v …:/out instrumentisto/nmap:latest -sT -sV -T4 --open --max-retries 1 --host-timeout 60s --script-timeout 20s -p 21,22,25,80,110,139,143,443,445,1025,1433,2222,3306,5432,6379,8025,8080,27017 --script ftp-anon,redis-info,mysql-empty-password,smb2-security-mode,ssl-enum-ciphers,ssl-cert,http-enum,http-title -iL /out/targets-labnet.txt -oX /out/lab-nmap-labnet-20260926-115811.xml` | 0 |
| nmap labnet2 | same image/scripts, `--network evergreen-lab_labnet2`, targets-labnet2.txt | 0 |
| trivy image ×11 unique compose images | `docker run --rm -v …:/out -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --format json --output /out/trivy-….json <image>` | 0 all 11 |
| testssl nginx:80 | `docker run --rm --network evergreen-lab_labnet -v …:/out drwetter/testssl.sh:latest --fast --jsonfile /out/testssl-172.28.10.10-80.json 172.28.10.10:80` | 245 (not TLS; JSON WARN written) |
| nikto 29 web URLs | `docker run --rm --network <labnet\|labnet2> ghcr.io/sullo/nikto:latest -h http://IP:PORT/ -nointeractive -maxtime 30s -output /out/nikto-….txt` | 0 all 29 |
| nuclei | see blocker below | blocked |
| prove | `C:/Python314/python.exe scripts/prove_ciso.py --work C:\Users\R\Desktop\EvergreenOps\lab-estate\prove-work\h1-20260926-115811 --use-existing-in` then `--verify-only` | 0 |

Runner: `lab-estate/scripts/h1_real_scanner_lab.py` (ops tree, not product).

## Scanner counts

nmap: **48 hosts up**, **51 open ports**. Ports: 80×28, 6379×8, 2222×2, 27017×2, 3306×2, 139×2, 445×2, 5432×2, 21×1, 1025×1, 8025×1.  
NSE script elements: http-title 29, redis-info 8, http-enum 10, smb2-security-mode 2, ssl-enum-ciphers/ssl-cert 2 (MySQL 3306, not web TLS), ftp-anon **0**, mysql-empty-password **0**.

trivy: 11/11 images JSON written (queue said 12; compose unique images are 11).

nikto: 29/29. nginx/httpd files ~1 KB (header missing). whoami (10.80-85, 11.80-83) ~256 KB / 2478 items each (200-for-all false positives).

testssl: no TLS listeners on web hosts. Probe of 172.28.10.10:80 → `doesn't seem to be a TLS/SSL enabled server` + `Scan interrupted`.

## Nuclei blocker (did not loop)

1. `-duc`: `[ERR] Could not find template '/root/nuclei-templates'` / `[FTL] Could not run nuclei: no templates provided for scan`.
2. Without `-duc`: installed v10.4.9, **6437 templates**, 29 targets; hung ~22m at ~0.5% CPU, jsonl 0 bytes. Killed (`docker rm keen_swartz`).
3. `-timeout 5 -retries 0 -mhe 15` + `-v h1-nuclei-home:/root`: stuck on `nuclei-templates are not installed, installing...` >4.5m. Killed.

Exact argv in `raw/nuclei-BLOCKED.txt`. jsonl left 0 bytes. Did not retry further.

## prove_ciso --use-existing-in

`prove-ciso.json`: lab=true sample=false client=false seeded=false posted=false paying_day=FAIL. sensors nmap+vuln.

| counter | n |
|---|---|
| assets.csv | 58 |
| findings.csv (Extra Import) | 63 |
| poam.csv | 747 |
| poam_fedramp.csv (open) | 747 |
| poam_fedramp_closed.csv | 0 |
| vulnerabilities.csv | 3347 |
| risk_scenarios | 3410 |

**(d) count diff:** poam.csv **747 =** poam_fedramp.csv **747**. Extra Import findings.csv **63** is nmap-only (HTTP/redis/SMB/FTP/open-port). Trivy CVEs go to vulnerabilities.csv (3347) and dominate POA&M (estate `MIXED: REVIEW BEFORE USE`, assets like `usr/local/bin/gosu`). FedRAMP open tracks POA&M 1:1; Extra Import findings do not.

## Ground-truth table (compose vs detected vs POA&M)

Queue said redis x7; **compose has 8** redis (10.63–67 + 11.63–65).

| Ground truth | Compose fact | Detected? | On POA&M? | 800-53 | Fix specific or generic |
|---|---|---|---|---|---|
| redis no-auth | 8 containers, no requirepass | **yes 8/8** redis-info Version= | **yes 8** `Redis accessible without authentication` | IA-2, AC-3, CM-6, CM-7, SC-7 | **specific** (requirepass / ACL / protected-mode / bind) |
| mysql labpass | 10.33 + 11.33 root=labpass (not empty) | port 3306×2; mysql-empty-password **absent (correct)** | open-port MySQL rows, not empty-password | port mapping CM-7 class | generic open-port; empty-password correctly not claimed |
| postgres labpass | 10.54 + 11.54 | 5432×2; no postgres NSE in #124 set | open-port postgresql | generic | generic open-port |
| mongo no-auth | 10.27 + 11.27 no auth | 27017×2; no mongo NSE in #124 set | open-port mongodb | generic | generic open-port; **no-auth not proven by NSE** |
| ssh password auth | PASSWORD_ACCESS=true; listens **2222** not 22 | 2222×2 | Open port 2222/ssh | generic | generic; password-auth not in NSE set |
| samba guest/writable | guest=**no**, users=lab | 139/445×2; smb2-security-mode **signing not required** ×2 | SMB 445 exposed + signing-not-required; **guest not claimed (correct)** | signing: SC-8, SC-8(1), SC-23, CM-6 | signing **specific**; guest correctly absent |
| anonymous ftp | Pure-FTPd **named user labftp**, not anonymous | 21 open; ftp-anon element **absent (correct)** | `FTP exposed` only | CM-7, SC-8 | **generic** port-21; anonymous correctly not claimed |
| mailhog SMTP/UI | 10.25 | 1025 + 8025; http-title MailHog | open-port smtp/http | generic | generic |
| published 8080 | host `8080:80` on web-nginx | **8080 count=0 on bridge** (container :80) | no | n/a | n/a — host publish is not a labnet port |

## H1c failing tests (RED on ce67328)

`tests/test_h1_desktop_real_collectors.py` + `tests/fixtures/h1-desktop/` (real drops). pytest: **3 failed**.

1. **inventory-nmap gnmap** invents `Administrative share … (C$/ADMIN$)` on dperson/samba even when the gnmap line says `Samba smbd 4`. XML path does not. Fixtures: `nmap-samba-172.28.10.50.gnmap`.
2. **nikto 2.5.0 text empty:** parser wants `Target Hostname` and URL lines starting `/`; real files are `Target Host:` + `GET /:`. TRACE on httpd never lands. Fixture: `nikto-172.28.10.11-80.txt`.
3. **testssl plaintext HTTP** becomes vulnerabilities `Optimal proto` / `Scan Time` / “Scan interrupted”. Fixture: `testssl-172.28.10.10-80.json`.

No product code changes this slice (H1c tests only).

## Honesty

LAB Docker estate. Not SAMPLE. Not client KEEP. Did not flip client_facing_ready. posted=false. No live GRC.
