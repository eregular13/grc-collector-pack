# Drop box — orchestrator as brakes

Written consent → Reid-owned drop box → **quiet discover** → gated **louder deepen** → ingest → CISO + POA&M.

This is **not** a Pentera payload library. The wedge is: find SMBv1 → map CPG/CSF → POA&M row → CISO SoR → remediation quote.

## Three layers (do not mix)

1. **Tool zoo (BYO)** — Reid installs allowlisted scanners on the drop box. This repo does not embed Nmap, Nessus, Nuclei, OpenVAS.
2. **Orchestrator = brakes** — SCOPE gate, shard size, deepen batches 2–5, concurrency caps, worker tear-down, unsigned refuse.
3. **Ingest pack** — existing collectors parse files only. `GRC_LIVE_SCAN=1` is ignored.

Stage graph: `plan → shard → discover → destroy_discover_workers → deepen(small_batches) → destroy_deepen_workers → ingest → grc_export`

## Laws

- Client environment integrity over coverage ego.
- Quiet discovery exists to *earn* louder findings, not replace them.
- BYO nmap is called on the drop box only when allowlisted, on PATH, `allow_live_exec`, and `EVERGREEN_ORCH_LIVE=1`. CIDR shards are IP slices (≤256/worker). Missing binary → plan-only fixture. Pack does not embed Nmap.
- BYO nessuscli deepen is the same gate plus batch ≤5 hosts (CIDRs refused). Missing binary → fixture deepen. Pack does not embed Nessus.
- BYO testssl/curl deepen is named external hosts/URLs only (never CIDRs). curl is HEAD-only. Missing binary → plan-only.
- BYO Lynis / ss / HardeningKitty audit the drop-box endpoint only (`record_seen`; no invented findings). Same live gates. Missing binary → plan-only.
- BYO Prowler/Maester need named cloud/Entra, record_seen, same-day revoke. Tenant is not interpolated into `-Command`. Missing binary or unnamed cloud → plan-only.
- Missing/unsigned SCOPE, blank `named_contact`, missing consent window, or empty targets → plan-only. No live stages. `consent_attested` / `allow_live_exec` must be lowercase `true` (`yes`/`True` do not attest or enable live). `EVERGREEN_ORCH_LIVE` must be `1`. `integrity.refuse_if_unsigned` / `refuse_if_empty_targets` cannot be turned off. Tool not in `allow_tools` → that adapter does not exec. Deepen only hosts discover marked live/in-scope (empty live set is not a hail-mary fixture dump).
- External profile never uses internal CIDRs; internal never sprays public internet.
- Tool-kind gate: CIDR-only does not unlock testssl; Entra-only does not unlock Lynis.
- Discover/deepen workers run in waves of `max_concurrent_*`, then tear down. SCOPE cannot hail-mary concurrency: discover ≤4, deepen ≤2, shard ≤256, deepen batch ≤5. Prefixes larger than 8192 addresses (`/16`-class) refuse live (`prefix_too_large`); `timeouts_seconds: 1` cannot make them look cheap. Waves × max(30s, timeout) over `max_runtime` → `runtime_over_budget`.
- CISO auto-push is assets+evidences only. Findings/POA&M are HITL (clica/UI). SimpleRisk is a leave-behind CSV, not an API.
- RiskReady wrap is stay-out. SimpleRisk is a leave-behind import, not an API wrap.
- Empty `in/` is demo fixtures, not a client estate. Orchestrator ingest writes `in/_dropbox_preview/` only (labeled `fixture` or `live-byo`). Live-byo does not merge pack demo canonical rows and does not stamp `product-lab/drop/`. Single-profile fixture ingest does not merge the other profile's pack demo (external-only: no internal SMBv1; internal-only: no vpn/TLS). Live-eligible SCOPE (`allow_live_exec: true`) also does not stamp the CISO drop with leftover fixture ingest. Unsigned/empty/window refuse ignores leftover live-byo `deepen.json`. Fixture-lab SCOPE (`allow_live_exec: false`) also ignores leftover live-byo ingest. Leftover plan-only/refused or unstamped deepen is ignored (`deepen_refused` / `deepen_client_missing`); leftover fixture deepen from another client is `client_mismatch`. Ingest filters leftover hosts to current SCOPE (external-only does not ingest internal SMBv1). Deepen refuses leftover `discover.json` from another client, leftover discover with no `client` stamp, leftover plan-only/refused discover, and leftover live-byo discover when `allow_live_exec` is false; those refuses are top-level (CLI/MCP exit 2). It filters hosts to current SCOPE. HITL cannot make fixture evidence client-facing; leftover live-byo ingest cannot outrank a current fixture/plan-only deepen (`evidence_label_mismatch`); discover-only is not client-facing evidence. Current SCOPE must have `allow_live_exec`; HITL `client` and live-byo artifact `client` must match SCOPE (leftover other-client live-byo is not ready). Crash leftover workers are torn down at stage start. It does not clobber sensor folders.

Operator MCP is a later hook: `python -m dropbox.orchestrator mcp --action plan` wraps the CLI. It is **not** a public attack API (exploit/spray denied).

See `OPERATOR.md`. Northstar: `C:\GRC Collector\grok-build-desktop-orchestrator-mega-prompt.md`.
