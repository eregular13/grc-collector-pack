# H3 REPORT — Prove or refute GRC_LIVE_SCAN=1 scan_to_sor on DESKTOP

Stamp: `20260926-165419`  
Pack base: `ce67328` (`hermes/testbed-base-2026-09-26`)  
Branch: `hermes/h3-live-scan-2026-09-26`  
Lab: evergreen-lab **48** containers up (labnet `172.28.10.0/24` + labnet2 `172.28.11.0/24`). Did **not** start/stop any container. LAB != SAMPLE != client. No `/api/risks`. No live GRC write. RiskReady stay-out.

**Verdict: REFUTED.** `GRC_LIVE_SCAN=1` / `python -m dropbox run --profile all --live` does **not** reach any `172.28.x` host from DESKTOP. Windows has no nmap, no `ss`, no lynis; host TCP to `172.28.10.10:80` and `172.28.11.10:80` times out while the containers are Up. When the SCOPE gate is forced open, live collectors write a **synthetic** gnmap (`# dropbox local inventory (ss/ip). Not Nmap.`) that plants `22/ssh` + `80/http` on `172.28.10.10` and labels it `DESKTOP-222GHQV` — then `scan_to_sor` reports `scanned=true`. That is not a live estate observation.

Proposed fix (separate branch): `hermes/h3-live-docker-runner-2026-09-26`.

## Host facts

| Check | Result |
|---|---|
| nmap on PATH | **missing** (`which nmap` empty; no Program Files\Nmap) |
| ss / lynis on PATH | **missing** |
| docker | `C:\Program Files\Docker\Docker\resources\bin\docker.EXE` |
| evergreen-lab running | **48** (`docker ps --filter name=evergreen-lab-`) |
| `172.28.10.10` (web-nginx, labnet) | container Up; host TCP `:80` **TimeoutError** |
| `172.28.11.10` (n2web0, labnet2) | container Up; host TCP `:80` **TimeoutError** |

TCP probes: `raw/tcp-probe.json`. docker ps: `raw/docker-ps.txt`.

## Documented command (mcp_stub.py:661)

Windows twin:

```
$env:GRC_LIVE_SCAN=1; python -m dropbox run --profile all --live; .\scripts\lab_drop_to_sor.ps1 -Work DIR
```

### A. Default DEMO SCOPE — not executed

`dropbox/SCOPE.yaml` external includes `vpn.example.com`, `staging.example.com`, `example.com`, `192.0.2.10`. `--profile all --live` would `curl -I` those hosts (`runners.write_tls_headers`). Queue forbids internet targets. **Did not run** `--profile all --live` against DEMO SCOPE. Copy: `raw/default-SCOPE.yaml`.

### B. Lab-estate-only SCOPE (no dummy external) — documented `--profile all --live`

Exact argv:

`C:\Python314\python.exe -m dropbox run --profile all --live --scope C:\Users\R\Desktop\EvergreenOps\lab-estate\prove-work\h3-20260926-165419\scope\SCOPE.yaml`

Env: `GRC_LIVE_SCAN=1` `CISO_PUSH=0` `RISKREADY_PUSH=0` `DRY_RUN=1` `IN_DIR=<work>\in` (not pack `in/`).

| | |
|---|---|
| rc | **2** |
| stdout | empty |
| stderr | `SCOPE gate: external hosts/domains/IPs required` |
| dest_in files | **none** |
| 172.28.x reached | **no** |

Then documented SoR half:

`powershell.exe -NoProfile -ExecutionPolicy Bypass -File …\scripts\lab_drop_to_sor.ps1 -Work …\h3-20260926-165419`

| | |
|---|---|
| rc | **1** |
| stderr | `EXISTING_IN_FAIL dest_in is empty or missing; --use-existing-in / --no-seed will not seed fixtures/pack_drop.` |

A SCOPE that only names `172.28.10.0/24` + `172.28.11.0/24` cannot load. The documented `--profile all --live` path therefore cannot be aimed at the estate allowlist without also naming an external target that live TLS/curl would contact.

### C. MCP `scan_to_sor` + `GRC_LIVE_SCAN=1`

| Mode | SCOPE / target | rc | result |
|---|---|---|---|
| refuse-loopback | default DEMO + `127.0.0.1` | 0 (dispatch) | `ok=false` `refused=true` `fail_code=LIVE_LAB_NET` `scanned=false` `posted=false` — `requested target(s) outside lab-estate networks: 127.0.0.1` |
| live-lab (empty external) | lab CIDRs + `172.28.10.10` | 0 | `ok=false` `refused=true` `fail_code=SCOPE_REFUSED` `scanned=false` — `external hosts/domains/IPs required` |

JSON: `raw/scan-to-sor-refuse-loopback.json`, `raw/scan-to-sor-live-lab.json`.

## Follow-up (gate open, still no packets to 172.28.x)

Dummy external **`192.0.2.10`** (RFC 5737 TEST-NET-1) so `load_scope` succeeds. **`--profile all` not used** (would curl). `--profile internal --live` and `scan_to_sor` `run_live_collectors` only.

### D. `dropbox run --profile internal --live`

Exact argv:

`C:\Python314\python.exe -m dropbox run --profile internal --live --scope …\followup\scope\SCOPE.yaml`

| | |
|---|---|
| rc | **0** |
| wrote | `nmap/dropbox-inventory.gnmap`, `wazuh/dropbox-lynis-host.json` |
| nmap spawned | **no** |

gnmap (`raw/dropbox-inventory-internal.gnmap`):

```
# dropbox local inventory (ss/ip). Not Nmap.
Host: 172.28.10.10 (DESKTOP-222GHQV)	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
```

`ss` is not on PATH. This line is the DEMO fallback in `dropbox/runners.py` `write_inventory` (`demo or not hosts` → default ports 22/80, hostname = `socket.gethostname()` because the token looks like an IP). **Not a probe of labnet.** web-nginx is `:80` only; estate SSH is `:2222` on other containers. Planted `22/ssh` is false.

### E. `scan_to_sor` live after dummy external

`GRC_LIVE_SCAN=1` dispatch `scan_to_sor` target `172.28.10.10` estate=lab.

| | |
|---|---|
| ok / live / scanned | true / true / **true** (claim) |
| posted / http | false / false |
| dest_in gnmap | same synthetic Not-Nmap line |
| prove_ciso | status=pass, lab=true sample=false client=false posted=false paying_day=FAIL |
| counts | assets=1 findings=2 poam=2 risk_scenarios=3 vulnerabilities=0 |

`scanned=true` means “collectors wrote dest_in + prove ran”, **not** “a 172.28.x socket opened”. prove: `raw/prove-ciso-mcp-live.json`.

## Was any 172.28.x host reached?

**No.** Evidence:

1. Host TCP connect to the live container IPs timed out.
2. No nmap/ss binary on the Windows PATH.
3. Documented `--profile all --live` never got past SCOPE load on a lab-only document.
4. Internal live / `run_live_collectors` header says `Not Nmap` and uses default 22/80 + the Windows hostname.

In-container nmap on `evergreen-lab_labnet` (H1) is a different path and was not this item.

## H3 test (this branch)

`tests/test_h3_desktop_live_scan.py` — `xfail(strict=True)` that `run_live_collectors` spawns nmap against `172.28.10.10`. Expected XFAIL on ce67328.

## Honesty

LAB Docker estate != SAMPLE != client. Did not flip `client_facing_ready`. No `/api/risks`. File-true SoR from synthetic gnmap is not clause-1 observation and not clause-2 tenant import. No new crons. No Covey. No overlay start. Next: H4 Windows pytest (after the proposed-fix branch is pushed).
