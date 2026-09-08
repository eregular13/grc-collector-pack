# Isolated Docker estate

Compose file: `docker-compose.estate.yml` (project `grc-estate`).

```powershell
docker compose -f docker-compose.estate.yml up -d
# reuse if already up on 127.0.0.1:18081
```

| Service | Address |
| --- | --- |
| estate-web (nginx) | `127.0.0.1:18081` → `172.28.90.10` |
| estate-api (whoami) | `127.0.0.1:18082` → `172.28.90.11` |
| estate-tls (nginx self-signed) | `127.0.0.1:18443` → `172.28.90.12` |
| network | `grc-estate` `172.28.90.0/24` |

Publish binds **loopback only**. SCOPE: `dropbox/SCOPE.docker-estate.yaml` (Evergreen Docker Estate LLC). Tools: curl HEAD + allowlisted same-origin GET `/.git/HEAD` and `/listing/` (dummy lab Git metadata + autoindex on estate-web) + optional sidecar nmap `-sn` on that CIDR (`--profile scan`). Pack image does not apt-install nmap.

Do **not** scan the host LAN (`192.168.10.0/24`), pve, or public internet. This estate is lab-sim, not a customer.
