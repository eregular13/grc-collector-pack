# lab-estate/misconfig — DELIBERATELY MISCONFIGURED LAB SERVICES

LAB/DEMO — not a client estate. Never expose these services outside the internal
`misconfig_lab` network (`internal: true`, no host ports published). Each service
is broken on purpose so the scan→risk-register→POA&M product has something real to find.

| service | IP | misconfig | NSE script that proves it |
|---|---|---|---|
| mc-ftp | 172.31.250.10 | vsftpd anonymous login | ftp-anon |
| mc-redis | 172.31.250.11 | Redis, no requirepass, protected-mode off | redis-info |
| mc-web | 172.31.250.12 | nginx autoindex on / and /files/ (port 80) | http-enum, http-title |
| mc-web | 172.31.250.12 | TLS 1.0/1.1 + aNULL ciphers + self-signed RSA-1024 (port 443) | ssl-enum-ciphers, ssl-cert |
| mc-smb | 172.31.250.13 | Samba signing disabled, guest share | smb2-security-mode, smb-security-mode |
| mc-db | 172.31.250.14 | MariaDB root with EMPTY password (default creds) | mysql-empty-password |

Resource budget: ~450 MB RAM total (mem_limit per service).

```powershell
cd C:\Users\R\Desktop\EvergreenOps\lab-estate\misconfig
.\gen-weak-cert.ps1            # once: RSA-1024 self-signed cert (LAB only)
docker compose -p misconfig up -d --build
docker compose -p misconfig run --rm scan   # nmap runs INSIDE misconfig_lab; writes .\out\misconfig-nse.xml
# drop into pack LAB dest_in:  <work>\in\LAB.txt + <work>\in\nmap\misconfig-nse.xml
# then: scripts\lab_drop_to_sor.ps1 -Work <work>   (or the lab-estate scan-and-sor one-shot)
docker compose -p misconfig down -v
```
