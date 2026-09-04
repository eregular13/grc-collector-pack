# 01 — Containers this compose project owns

**Written:** 2026-09-03 21:29 America/Los_Angeles  
**Repo:** `C:\Users\R\grc-collector-pack`  
**Command:** `docker inspect` + `docker logs --tail 80` on the ten `grc-collector-pack-*` names  
**Exit:** 0  
**Duration:** ~2 s  
**Pass/fail:** PASS  
**Artifacts:** `product-lab/raw/compose-inspect.json`, `product-lab/raw/logs-grc-collector-pack-*.txt`, `product-lab/raw/docker-ps.txt`, `product-lab/raw/compose-ps.txt`

`docker compose ps` at 21:28 PT listed **no running services**. The table below is the last completed run (started 2026-09-03T05:00:05Z). Host `out/` from that compose run is the 05:00:07Z summary; a later host lab overwrote `out/summary.json` at 05:02:06Z.

All ten use image `grc-collector-pack:local`, no published ports, mounts `C:\Users\R\grc-collector-pack\{in,out,fixtures}` → `/in` ro, `/out` rw, `/fixtures` ro.

Safety env (redacted: none present; no TOKEN/PASSWORD/API_KEY on these containers):

`DRY_RUN=1` `CISO_PUSH=0` `RISKREADY_PUSH=0` `GRC_LIVE_SCAN=0` `OUT_DIR=/out` `IN_DIR=/in` `FIXTURES_DIR=/fixtures/demo` `PYTHONPATH=/app` `GRC_DOMAIN=Global` `GRC_PERIMETER=IT Environment`

| Name | Command | Status | Exit | Started (UTC) | Finished (UTC) | Last log (≤80 lines) |
|---|---|---|---|---|---|---|
| `grc-collector-pack-cloud-prowler-1` | `python collectors/cloud_prowler.py` | exited | 0 | 05:00:05.864Z | 05:00:06.255Z | empty stdout |
| `grc-collector-pack-inventory-nmap-1` | `python collectors/inventory_nmap.py` | exited | 0 | 05:00:05.855Z | 05:00:06.309Z | empty stdout |
| `grc-collector-pack-vuln-scan-1` | `python collectors/vuln_scan.py` | exited | 0 | 05:00:05.869Z | 05:00:06.284Z | empty stdout |
| `grc-collector-pack-host-wazuh-1` | `python collectors/host_wazuh.py` | exited | 0 | 05:00:05.884Z | 05:00:06.234Z | empty stdout |
| `grc-collector-pack-identity-ad-1` | `python collectors/identity_ad.py` | exited | 0 | 05:00:05.861Z | 05:00:06.323Z | empty stdout |
| `grc-collector-pack-easm-1` | `python collectors/easm.py` | exited | 0 | 05:00:05.914Z | 05:00:06.375Z | empty stdout |
| `grc-collector-pack-k8s-kubescape-1` | `python collectors/k8s_kubescape.py` | exited | 0 | 05:00:05.903Z | 05:00:06.354Z | empty stdout |
| `grc-collector-pack-code-secrets-1` | `python collectors/code_secrets.py` | exited | 0 | 05:00:05.874Z | 05:00:06.329Z | empty stdout |
| `grc-collector-pack-saas-idp-1` | `python collectors/saas_idp.py` | exited | 0 | 05:00:05.896Z | 05:00:06.331Z | empty stdout |
| `grc-collector-pack-grc-loader-1` | `python collectors/grc_loader.py` | exited | 0 | 05:00:07.094Z | 05:00:07.379Z | JSON summary 62/58/15/10 (cycle 6 compose) |

Service count remains **10**. No eleventh container.

## Not this project (do not inspect as ours)

`grc-collector-mock_sink-1` (`0.0.0.0:18080`) and the rest of `grc-collector-*` belong to `C:\GRC Collector`. `grc-facet-*` is another tree. See `00-inventory.md`.

## Did host `out/` change during this inspect?

No. Inspect and logs are read-only. `out/summary.json` stayed at the 05:02:06Z host-lab file until the product-lab host run below.

## Ship meaning

The last compose batch on this project was a one-shot batch: collectors finish in ~400 ms, loader finishes after `depends_on: service_completed_successfully`, all exit 0, no sockets published. That is the ship shape. Empty collector logs are acceptable (writers go to `/out`, not stdout). The next compose lab must prove the same ten-service list and a current loader summary after cycle 7.
