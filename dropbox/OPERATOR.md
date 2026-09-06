# Operator commands

Tree: `C:\GRC Collector\grc-collector-pack` (Windows). Fixtures ≠ client estate.

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
```

1. Copy `dropbox\SCOPE.example.yaml` and fill it from the **signed** authorization sheet. `consent_attested: true` only after HITL (`yes`/`True` do **not** attest). `$env:EVERGREEN_ORCH_LIVE` must be `1` (not `true`).
2. Plan (no binaries required):

```powershell
python -m dropbox.orchestrator plan --scope dropbox\SCOPE.example.yaml
```

`SCOPE.example.yaml` may be **window_closed** (historic demo end 2026-09-05 09:00 PT). That is fail-closed live, not a scanner bug. Pytest uses `SCOPE.lab.yaml` (relative window, still `allow_live_exec: false`). See `docs/LAB_WINDOW.md`.

If `dropbox\out\discover.json` is another client, archive it before this SCOPE's quiet pass (do not silently clobber):

```powershell
python -m dropbox.archive_out --client "Litware Lab LLC"
```

3. Quiet discover (fixture path without BYO nmap). Live host nmap (`-sn` only) runs **only** when all of: signed SCOPE, `integrity.allow_live_exec: true`, `$env:EVERGREEN_ORCH_LIVE=1`, nmap on PATH, shard ≤256 hosts (never a `/16` in one argv). Lynis / ss / HardeningKitty on the **drop-box endpoint** are the same gate; they are **record_seen only** (no invented POA&M rows). Prowler/Maester need **named** cloud/Entra, same live gate, record_seen, **same-day revoke**; tenant/account is never interpolated into a shell. Binary missing → plan-only. Pack never downloads Nmap. Lab `SCOPE.example.yaml` keeps `allow_live_exec: false`.

```powershell
python -m dropbox.orchestrator run --scope dropbox\SCOPE.example.yaml --stage discover
```

4. Review `dropbox\out\discover.json`. Tighten SCOPE if needed. Deepen refuses leftover discover from another `client_legal_name` (`discover_client_mismatch`), leftover discover with no `client` stamp (`discover_client_missing`), leftover **plan-only**/refused discover (`discover_refused`), and leftover **live-byo** discover when the current SCOPE has `allow_live_exec: false` (`live_exec_not_allowed`). Those leftover refuses are top-level (CLI/MCP **exit 2**), not nested-only. Only deepens hosts in the current SCOPE.
5. Louder deepen, small batches (2–5). `max_concurrent_deepen` is capped at **2** (discover concurrent ≤4, shard ≤256) even if SCOPE asks for 99. Live nessuscli / testssl / curl run **only** when all of: signed SCOPE, `allow_live_exec`, `$env:EVERGREEN_ORCH_LIVE=1`, binary on PATH, batch ≤5. Nessus: hosts only (CIDRs refused). testssl/curl: named hostnames/URLs only (never CIDRs, never the whole internet). curl is HEAD-only (`-I`, no redirects). Binary missing → plan-only fixture. Pack never downloads scanners.

```powershell
python -m dropbox.orchestrator run --scope dropbox\SCOPE.example.yaml --stage deepen
```

6. Ingest → POA&M + control map. Label follows deepen: `fixture` (lab) or `live-byo` (BYO exec). Live-byo does **not** merge pack demo canonical rows and does **not** stamp `product-lab\drop\`. Unsigned/empty/window refuse **ignores leftover live-byo** `deepen.json` (other-client leftovers too). Fixture-lab SCOPE (`allow_live_exec: false`) also ignores leftover live-byo ingest (`live_exec_not_allowed`). Leftover plan-only/refused deepen is ignored (`deepen_refused`); leftover deepen with no `client` stamp is `deepen_client_missing`; leftover **fixture** deepen from another client is `client_mismatch` (not only live-byo). Ingest also drops leftover hosts that are not in the current SCOPE (external-only does not ingest internal SMBv1; internal-only does not merge vpn/TLS pack demo). Normalized findings land in `dropbox\out\in-preview\` and `in\_dropbox_preview\` (labeled, **not** mixed into `in\nmap` / `in\vuln`). Evidence trail: `dropbox\out\EVIDENCE.md`.

```powershell
python -m dropbox.orchestrator run --scope dropbox\SCOPE.example.yaml --stage ingest
# or end-to-end:
python -m dropbox.orchestrator run --scope dropbox\SCOPE.example.yaml --stage all
```

7. Pack lab (parse-only collectors → CISO CSVs):

```powershell
powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
```

CISO import (HITL):
- Dry-run: `$env:CISO_PUSH=0`; `.\push_ciso.ps1` lists files, no HTTP.
- Auto-push when you mean it: `$env:CISO_PUSH=1` + `CISO_TOKEN` uploads **assets.csv** and **evidences.csv** only to `/api/importer/`.
- Findings, vulnerabilities, risk_scenarios, applied_controls, and `out\poam\poam.csv` stay **HITL**: CISO Assistant UI Extra → Import, or `clica` if you have it. Do not auto-push findings.

SimpleRisk Core: leave-behind CSV `out\simplerisk\risks_import.csv` (also `product-lab\drop\simplerisk\`). Import by hand in SimpleRisk extras. No API wrap.

RiskReady: `out\riskready\` review-only. `push_riskready.ps1` is WRAP_DEAD (no POST even if `RISKREADY_PUSH=1`).

Unsigned SCOPE (`dropbox\SCOPE.unsigned.yaml`) refuses discover/deepen (exit 2) and does **not** stamp `product-lab\drop\` (CISO/POA&M/quote leave-behind). `integrity.refuse_if_unsigned: false` and `refuse_if_empty_targets: false` **cannot bypass** those laws. Fixture ingest may still write `dropbox\out\` labeled fixture. Plan-only still prints shards (`python -m dropbox.orchestrator plan`). Blank `named_contact` is unsigned (schema required) even if `consent_attested: true`. Empty targets (`dropbox\SCOPE.empty.yaml`) refuse live and also skip the CISO drop. Empty `allow_tools` refuses live (`empty_allow_tools`) even if consent is attested and `EVERGREEN_ORCH_LIVE=1`. Tool not in `allow_tools` does not exec (nmap is not implied by nessus). Missing `window_start`/`window_end` refuses live (`window_missing`). Closed/not-open/unparseable window refuses live. A `/16`-class prefix (more than 8192 addresses) refuses live (`prefix_too_large`) even if `timeouts_seconds: 1`. Deepen without `discover.json` or with unparseable JSON is a BRAKE (exit 2). Leftover discover refuse (`live_exec_not_allowed` / `discover_client_mismatch` / `discover_client_missing` / `discover_refused`) is also CLI/MCP **exit 2** (top-level `refused`, console `integrity_stop`). Unparseable leftover `deepen.json` is ignored (`deepen_unparseable`); ingest stays fixture. Deepen only uses hosts discover marked live/in-scope; an empty live set does not dump fixture SMBv1. Deepen workers are torn down after the stage (`dropbox\out\destroy_deepen.json`; no `workers\*.alive`). External-only (`dropbox\SCOPE.external.yaml`) never shards internal CIDRs even if they are listed. CIDR-only does not unlock testssl; Entra-only does not unlock Lynis. Cloud/Entra tools (Prowler, Maester) stay gated until named in SCOPE; same-day revoke after the window. HardeningKitty is endpoint-sample plan-only (record_seen, no invented findings). Scripts never download scanner installers.

POA&M lands at `dropbox\out\poam.csv`, `out\poam\poam.csv` + `MANIFEST.json`, and `C:\GRC Collector\product-lab\drop\poam\` (CISO drop companion, fixture-labeled).

Remediation quote stub: `out\quote\quote.csv` (hours/rate/total **blank** — never invent a price). HITL fills numbers.

Client-facing send stays false unless **all** of: signed live-eligible SCOPE with `integrity.allow_live_exec: true`, evidence label `live-byo` (not fixture) whose `client` matches SCOPE, ingest and deepen labels agreeing (stale live-byo ingest vs current fixture/plan-only deepen is `evidence_label_mismatch`), and `dropbox\out\HITL.json` with `"attested": true` **and** `"client"` matching `client_legal_name`. Discover-only inventory is not client-facing evidence. Fixture lab (`allow_live_exec: false`) cannot be client-facing even with leftover live-byo (`live_exec_not_allowed`) and is the only path that stamps `product-lab\drop\`. Live-eligible SCOPE does **not** stamp the CISO drop with leftover fixture ingest. Leftover live-byo from another client is `evidence_client_mismatch`. Leftover HITL does **not** override unsigned/empty/window refuse or a different client. Crash leftover `workers\*.alive` are torn down at the start of discover/deepen. Example:

```json
{"attested": true, "reviewer": "Reid Schram", "client": "Litware Lab LLC"}
```

Missing HITL.json, missing `client`, or fixture evidence → `client_facing_ready: false`.

## Localhost console

```powershell
python -m dropbox.orchestrator console
# http://127.0.0.1:18765/      HTML brakes view (localhost only)
# http://127.0.0.1:18765/status  JSON
```

Not a public attack socket. GET-only (`POST`/`PUT`/`PATCH`/`DELETE`/`OPTIONS` → 405). Future operator MCP should wrap this CLI, not expose scanners.

```powershell
python -m dropbox.orchestrator mcp --action plan --scope dropbox\SCOPE.example.yaml
python -m dropbox.orchestrator mcp --action status
# exploit / spray / scan_internet → exit 2 (not an attack API)
# mcp --action run --stage exploit|nuclei → exit 2 (stage is not a payload library)
```
