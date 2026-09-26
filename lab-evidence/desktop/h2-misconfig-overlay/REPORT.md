# H2 REPORT — Docker-validate misconfig overlay

Stamp: `20260926-144558` (pass-2 after Samba NT1 overlay fix; pass-1 `20260926-144355` was 10/11 missing guest)  
Pack base: `ce67328` (`hermes/testbed-base-2026-09-26`)  
Branch: `hermes/h2-misconfig-overlay-2026-09-26`  
Lab: overlay project `misconfig`, internal `172.31.250.0/24` only. Baseline evergreen-lab **48** running. LAB != SAMPLE != client. No `/api/risks`. No live GRC write. RiskReady stay-out.

## Commands (exit codes)

| Step | Command | rc |
|---|---|---|
| cert | `docker run --rm -v …/nginx/tls:/tls alpine:3.20` openssl rsa:1024 + dhparam 1024 | 0 |
| up | `docker compose -p misconfig -f lab-estate/misconfig/docker-compose.yml up -d --build` | 0 |
| wait | redis-cli PING PONG; mariadb `healthcheck.sh --connect --innodb_initialized` | 0 |
| scan | `docker compose -p misconfig --profile scan run --rm scan` (instrumentisto/nmap:7.95, 172.31.250.10-14, NSE set from compose) | 0 |
| SoR | `C:/Python314/python.exe scripts/prove_ciso.py --work …/h2-20260926-144558 --use-existing-in` then `--verify-only` (lab_drop_to_sor equivalent on ce67328) | 0 / 0 |
| down | `docker compose -p misconfig down` (no `--remove-orphans`) | 0 |

Runner: `lab-estate/scripts/h2_misconfig_overlay.py` then `h2_rescan_smb.py` (ops tree). Scan inside overlay network only.

## Baseline restore

| | count |
|---|---|
| pre-item running | 48 |
| after pass-1 down | 48 extra=[] missing=[] |
| after pass-2 down | 48 extra=[] missing=[] |
| misconfig containers left | **none** |

## 11 of 11 table (Docker vs box-loopback)

Box fixture used 127.0.10.2–7 (HTTP and TLS on **two** loopback IPs). Docker overlay uses 172.31.250.10–14 (HTTP+TLS on **one** IP `.12`). Parser check_ids match PR #124 EXPECTED, remapped to overlay IPs.

| # | Misconfig | Box IP | Docker IP | Detected? | On POA&M? | 800-53 | Fix |
|---|---|---|---|---|---|---|---|
| 1 | Anonymous FTP | 127.0.10.2 | 172.31.250.10 | **yes** ftp-anon 230 | **yes** | AC-3, AC-14, CM-7, IA-2 | **specific** anonymous_enable=NO / SFTP |
| 2 | Redis no auth | 127.0.10.3 | 172.31.250.11 | **yes** redis-info Version= | **yes** | IA-2, AC-3, CM-6, CM-7, SC-7 | **specific** requirepass / protected-mode |
| 3 | Directory listing | 127.0.10.4 | 172.31.250.12:80 | **yes** http-enum `/` + `/files/` | **yes** | CM-7, CM-6, AC-3 | **specific** autoindex off |
| 4 | TLS 1.0/1.1 | 127.0.10.5 | 172.31.250.12:443 | **yes** ssl-enum-ciphers | **yes** | SC-8, SC-8(1), SC-13, CM-6 | **specific** disable TLS 1.0/1.1 |
| 5 | Weak ciphers aNULL grade F | 127.0.10.5 | 172.31.250.12:443 | **yes** least strength F + `_anon_` | **yes** | SC-8, SC-8(1), SC-13, CM-6 | **specific** remove aNULL |
| 6 | Self-signed cert (web) | 127.0.10.5 | 172.31.250.12:443 | **yes** subject=issuer weak-tls.lab.local | **yes** | SC-17, SC-23, SC-8 | **specific** replace CA cert |
| 7 | RSA-1024 weak key | 127.0.10.5 | 172.31.250.12:443 | **yes** Public Key bits 1024 | **yes** | SC-12, SC-13, SC-17 | **specific** reissue ≥2048 |
| 8 | SMB signing not required | 127.0.10.6 | 172.31.250.13 | **yes** smb2-security-mode | **yes** | SC-8, SC-8(1), SC-23, CM-6 | **specific** server signing = mandatory |
| 9 | SMB guest | 127.0.10.6 | 172.31.250.13 | **yes** smb-security-mode account_used: guest | **yes** | AC-3, IA-2 (topic map) | **specific** guest |
| 10 | DB empty root password | 127.0.10.7 | 172.31.250.14 | **yes** mysql-empty-password root | **yes** | IA-5, IA-5(1), IA-2, AC-2, CM-6 | **specific** set password |
| 11 | MariaDB self-signed (true positive) | 127.0.10.7 | 172.31.250.14:3306 | **yes** CN=MariaDB Server | **yes** | SC-17, SC-23, SC-8 | **specific** replace CA cert |

**Docker 11/11.** All 11 NSE rows on `poam.csv`. Extra Import `findings.csv` = 16 (11 NSE + port-level rows). Parser `kind=finding` = 17.

## Diffs vs box-loopback result

1. **Addressing:** one CIDR 172.31.250.0/24 vs six loopbacks. HTTP and TLS share `.12` (box split `.4` / `.5`).
2. **Versions:** vsftpd 3.0.5 same class; Redis **7.4.11** (box 8.0.2); nginx **1.27.5** (box 1.26); Samba **4.19** alpine (box 4.22); MariaDB **11.8.9**.
3. **TLS would have been a miss on stock alpine nginx:** OpenSSL 3 refuses TLS 1.0/1.1 and aNULL unless `OPENSSL_CONF` + `ssl_conf_command MinProtocol TLSv1` + `CipherString ALL:@SECLEVEL=0` + 1024-bit dhparam. Overlay fix applied (see `overlay-src/`). Without it, checks 4–7 fail. Box daemons already offered TLS 1.0/aNULL.
4. **SMB guest miss on pass-1:** `server min protocol = SMB2` made `smb2-security-mode` fire (signing) but **silenced** `smb-security-mode` (guest). Restored `server min protocol = NT1` + `ntlm auth = yes`. Pass-2: both scripts. Box already had NT1-class SMB1.
5. **http-default-accounts:** still **not deployed** (gap 8 / optional Tomcat). Script ran, no vendor-default-creds row. Same as box.
6. **Port-level rows** still sit next to specific rows (FTP exposed + Anonymous FTP, etc.). Unchanged product behavior on ce67328.
7. **poam.csv 11 vs naive poam_fedramp.csv line count 12:** FedRAMP Comments field for the Critical DB row embeds a newline (`Critical` vs template High+30 note). Unique `EGP-*` POAM IDs = **11**. Not an extra weakness.

## prove_ciso / lab_drop_to_sor

`prove-ciso.json`: lab=true sample=false client=false seeded=false posted=false paying_day=FAIL http=false. sensors nmap.

| counter | n |
|---|---|
| assets.csv | 5 |
| findings.csv (Extra Import) | 16 |
| poam.csv | 11 |
| poam_fedramp unique POAM IDs | 11 |
| risk_scenarios | 16 |
| vulnerabilities.csv | 0 |

Honesty verify: `LAB_DROP_HONESTY=ok`. Did not reseed fixtures/pack_drop. File-true OpenGRC/Probo leave-behind posted=false (export, not tenant import).

## Overlay fixes (same item; ops tree + copied to overlay-src/)

- `nginx/openssl.cnf` + compose `OPENSSL_CONF` + nginx `ssl_conf_command` / aNULL ciphers / dhparam so alpine nginx actually offers TLS 1.0/1.1 + anonymous DH.
- RSA-1024 self-signed cert generated in-container (not present on disk before this item).
- Samba `server min protocol = NT1` + `ntlm auth = yes` so nmap `smb-security-mode` records `account_used: guest`.
- `nginx/www/LAB.txt` so autoindex is non-empty.

TLS private keys stay out of git (`nginx/tls/*.pem` not copied).

## Optional Tomcat / http-default-accounts

Not run. Gap 8 remains. No extra ~250 MB Tomcat service this slice.

## Honesty

LAB Docker overlay != box-loopback fixture != SAMPLE != client. Did not flip client_facing_ready. No `/api/risks`. No live CISO/OpenGRC/Probo/RiskReady write. Did not scan 172.28.10/11 this item. Did not start/stop evergreen-lab containers.
