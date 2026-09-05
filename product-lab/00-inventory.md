# 00 — Docker and repo inventory

**Written:** 2026-09-03 21:28 America/Los_Angeles  
**Repo:** `C:\Users\R\grc-collector-pack`  
**Stamp:** `product-lab/TEST_RUNS/20260903-212845`  
**Pass/fail:** PASS (daemon up; this compose project identified; other trees not claimed)

## Commands

| Command | Exit | Duration | Artifact |
|---|---|---|---|
| `docker version` | 0 | 165 ms | `product-lab/raw/docker-version.txt` |
| `docker compose version` | 0 | 208 ms | `product-lab/raw/compose-version.txt` |
| `docker ps -a` | 0 | 264 ms | `product-lab/raw/docker-ps.txt` |
| `docker compose ps` | 0 | 225 ms | `product-lab/raw/compose-ps.txt` |
| `docker inspect` of ten `grc-collector-pack-*` names | 0 | ~2 s | `product-lab/raw/compose-inspect.json` |

Working directory for all of the above: `C:\Users\R\grc-collector-pack`.

## What this machine has

Docker Desktop **4.89.0** (238018). Engine **29.7.2**, API 1.55, context `desktop-linux`. Compose **v5.5.0**. The daemon is up. This sprint can run compose; skipping it would be a P1.

`docker compose ps` from this repo is empty right now. The ten `grc-collector-pack-*` services last ran **2026-09-03T05:00:05Z**, all **exit 0**, image `grc-collector-pack:local`. They published **no ports**. Mounts are this tree only: `in` ro, `out` rw, `fixtures` ro. Safety env on every service: `DRY_RUN=1` `CISO_PUSH=0` `RISKREADY_PUSH=0` `GRC_LIVE_SCAN=0`.

`docker compose config --services` lists exactly ten: `cloud-prowler`, `inventory-nmap`, `vuln-scan`, `host-wazuh`, `identity-ad`, `easm`, `k8s-kubescape`, `code-secrets`, `saas-idp`, `grc-loader`. No eleventh service.

## Scripts that exist here

| Path | Present |
|---|---|
| `scripts/lab.ps1` | yes — host lab |
| `Makefile` target `compose` | yes — `docker compose up --build --exit-code-from grc-loader` |
| `push_ciso.sh` | yes — dry unless `CISO_PUSH=1`; never `/api/risks` |
| `push_riskready.sh` | yes — review-only forever, even if `RISKREADY_PUSH=1`; no login/POST |
| `run_docker_lab.ps1` | **no** |
| `run_facet_docker.ps1` | **no** |
| `tests/mock_grc*` / mock sink compose service | **no** |

Do not copy those scripts from `C:\GRC Collector`. They do not belong to this checkout.

## What is on the host but is not this product

`docker ps -a` also shows other compose projects. They are inventory only. This lab does not drive them and does not treat their ports as ours.

| Names | Image prefix | Notes |
|---|---|---|
| `grc-collector-*` including `grc-collector-mock_sink-1` | `grc-collector-*` | **Other repo** (`C:\GRC Collector`). `mock_sink` is **Up** on `0.0.0.0:18080->8080`. Created seconds before this inventory. **Not this compose project.** Do not contract-test it. |
| `grc-collector-lab-1` and nine `grc-collector-*` collectors | `grc-collector-*` | Same other tree; lab exited 0 ~7s before inventory. |
| `grc-facet-*` | `grc-facet-*` | Exited ~29h ago. Not this repo. |
| `localgrokloop-*`, `aegis-*`, juice-shop, ollama, etc. | various | Unrelated. Stopped. |

`.cursor/hooks.json` is present (`loop_limit` 24, `.cursor/hooks/keep_going.cmd`).

## Inputs and last host outputs

`in/` has no scanner drops (`.gitkeep` only). Labs use `fixtures/demo/` and write `demo: true`. That is a demo estate, not a client estate.

Last host `out/summary.json` before this product lab (generated 2026-09-03T05:02:06Z):

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "canonical": 137, "demo": true}
```

Last compose loader log (`grc-collector-pack-grc-loader-1`, 2026-09-03T05:00:07Z) wrote 62 / 58 / 15 / 10 (cycle 6 compose, before cycle 7 host lab added one finding).

## Ship meaning

The daemon is healthy. This pack’s last compose run completed all ten jobs with exit 0 and no published ports. There is **no mock sink on this repo**. A process from another tree is currently bound to `:18080`; hitting it would be a P1 (guessing another repo’s sink). Product lab continues with host lab + this project’s compose only.
