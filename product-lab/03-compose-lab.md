# 03 — Compose product lab

**Written:** 2026-09-03 21:45 America/Los_Angeles  
**Repo:** `C:\Users\R\grc-collector-pack`  
**Command:** `docker compose up --build --exit-code-from grc-loader`  
**Pass/fail:** PASS (twice)

`run_docker_lab.ps1` and `run_facet_docker.ps1` **do not exist** in this repo. Not copied from `C:\GRC Collector`. Facet compose is another tree (`grc-facet-*` containers, exited ~29h). This lab only drove this file’s `docker-compose.yml`.

## Run 1

| Field | Value |
|---|---|
| Stamp | `product-lab/TEST_RUNS/20260903-214007-compose1` |
| Exit | **0** |
| Duration | 00:00:08.063 |
| Services | **10** (`cloud-prowler` `inventory-nmap` `vuln-scan` `host-wazuh` `identity-ad` `easm` `k8s-kubescape` `code-secrets` `saas-idp` `grc-loader`) |
| Loader | `grc-loader-1 exited with code 0` |
| Host `out/` | changed 04:39:51Z → 04:40:14Z |
| Artifact | `…/compose1/stdout.log`, `stderr.log`, `summary.json`, `PASSFAIL.md` |

Loader stdout:

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "applied_controls": 74, "risk_scenarios": 74, "incidents": 58, "risks_proposed": 57, "ocsf": 59, "canonical": 137, "demo": true, "generated_at": "2026-09-04T04:40:14Z"}
```

Compose v5 printed `Aborting on container exit` while waiting on collectors, then started `grc-loader` after all nine `service_completed_successfully` conditions. Loader still wrote a full cycle-7 summary. That is noisy, not a torn write.

## Run 2

| Field | Value |
|---|---|
| Stamp | `product-lab/TEST_RUNS/20260903-214026-compose2` |
| Exit | **0** |
| Duration | 00:00:07.078 |
| Loader | exited 0 |
| Host `out/` | changed 04:40:14Z → 04:40:33Z |
| Summary | same 62 / 59 / 15 / 10 |

## Service count

`docker compose config --services` = 10. No eleventh container. No published ports. Image `grc-collector-pack:local`.

## Ship meaning

The same ten-job batch a customer would run on Windows + Docker Desktop completes in ~8 seconds after cache, overwrites `out/` with CISO CSVs + RiskReady JSON + OCSF, and exits 0 twice in a row. Counts match the host lab. This compose instance is the shippable unit. It is still a **demo estate** (`in/` is `.gitkeep` only).
