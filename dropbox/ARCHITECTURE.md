# Evergreen drop-box — three layers

Short and sharp. Orchestrator is brakes. Collectors stay parse-only.

## Layer A — BYO tool zoo (the drop box)

On a **consented** box, Reid (or the operator) may already have host tools. SCOPE names them. This repo does **not** embed or apt-install Nmap, Nessus, Nuclei, OpenVAS/GVM, or the rest of LICENSE-LOCK.

Private operator layout: **`farm/`** (README + OPERATOR + `SLOTS.yaml` 95+ slots + `SLOTS.md` counts + adapter stubs + compose skeleton). Tools arrive via host PATH, bind-mount (`FARM_TOOL_BIN`), or **private image tags Reid builds**. Not a public Hub soup. Binaries are not vendored.

- Consent + window + named CIDRs/hosts first (`SCOPE.yaml`).
- Allowlisted PATH binaries only (`ss` / `ip` / `curl` / `lynis`; optional BYO `nmap` / `nessus` / `testssl`).
- Missing binary → plan-only. Never download. Never ship plugins.

## Layer B — intelligent orchestrator = BRAKES

Quiet → loud. Integrity over coverage ego.

1. **Discover (quiet):** shard `internal.cidrs` to `/24` (or `discover_prefix`). Inventory only (`nmap -sn` + host timeout) if BYO nmap is on PATH **and** allowlisted.
2. **Deepen (loud, gated):** only if `orchestrator.stages.deepen: true`. Hosts from **discover-live** or explicit `deepen_hosts`. Batches 2–5. Concurrent workers ≤ `max_workers`. Never a `/16` in one worker. Never `0.0.0.0/0`.
3. **Destroy workers** after each stage.
4. **External (plan-only):** list named SCOPE hosts and farm slots with `will_run=false`. Operator lands files in `in/easm|…`. No live curl/testssl from orchestrate.
5. **Ingest:** copy/normalize discover/deepen artifacts into pack `in/<sensor>/` and inventory dropped external files. Does not probe.

`python3 -m dropbox status` prints the stage graph (`plan → shard → discover → destroy → deepen → destroy → external (plan-only) → ingest → grc_export`), last integrity stop, shard/batch counters, and `allow_tools ∩ PATH ∩ SLOTS` (present/missing). See `farm/OPERATOR.md`.

## Layer C — existing 10 containers (parse-only)

Nine collectors + `grc-loader`. They read **files already in `in/`** (or `fixtures/demo/` when empty) and emit CISO CSVs, POA&M (`owner`/`due` blank), RiskReady review JSON, SimpleRisk leave-behind docs.

They do **not** live-scan. They do **not** POST `/api/risks`.

## The feed rule

**Layer B feeds Layer C via `in/`.** The orchestrator does **not** turn Layer C into live scanners. Collectors never import `dropbox`. Compose still ships parsers, not a scanner suite.

## “100 tools”

That number is **tool-family file inputs the parsers accept** (Nmap XML/gnmap, Nessus-shaped reports you dropped, Prowler, Nuclei/Trivy, httpx, …). It is **not** 100 embedded binaries in compose.

```
consent SCOPE
    │
    ▼
Layer A  BYO on PATH / farm/ bind-mount / private tag
    │
    ▼
Layer B  discover → deepen → destroy → external (plan-only) → ingest
    │                    artifacts
    ▼
   in/<sensor>/
    │
    ▼
Layer C  9 collectors + loader  →  CISO / POA&M / SimpleRisk leave-behind
```
