# CYCLE log

## cycle 35 — cloud file-drop harden (2026-09-04)

`cloud-prowler` accepts Prowler JSON/ASFF (`ProductFields`, string or dict Severity) and ScoutSuite `services.*.findings` under `in/cloud/`. Finding `ref_id` is check+resource so two buckets stay two rows. High FAIL maps to CISO/POA&M when obvious (public S3 / AllUsers, IAM AdministratorAccess, root MFA, SG `0.0.0.0/0`, public RDS, unencrypted S3/EBS). Demo ASFF adds `demo-asff-open`. Empty `in/` still loads fixtures including `prowler-asff.json` + `scoutsuite.json`. ScoutSuite stays file_drop; Prowler invoke stays BYO. Catalog **not inflated**. No cloud API calls. pytest **187**. Labs green. Compose ABSENT.

```json
{"pytest": 187, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 64, "findings": 63, "vulns": 16, "poam": 63}, "farm_lab": {"assets": 64, "findings": 63, "poam": 63, "demo": true}, "farm_toolbin_e2e": {"assets": 64, "findings": 64, "poam": 63, "demo": true}, "dropbox_lab": {"assets": 69, "findings": 72, "poam": 66, "demo": true}, "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 34 — SARIF file-drop parsers (2026-09-04)

`vuln-scan` and `code-secrets` accept `in/vuln/*.sarif` / `in/code/*.sarif`. Shared `shared/sarif.py`. Demo fixture `fixtures/demo/vuln/demo.sarif` (command-injection, high). High SARIF rules map to control_map / POA&M. Empty `in/` still falls back to existing fixtures plus the new SARIF. Catalog **not inflated**. farm/SLOTS.md + OPERATOR document file_drop → these parsers. Docs/e2e stand. pytest **184**. Labs green. Compose ABSENT.

```json
{"pytest": 184, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "host_lab": {"assets": 63, "findings": 62, "vulns": 16, "poam": 62}, "farm_toolbin_e2e": {"assets": 63, "findings": 63, "poam": 62, "demo": true}, "farm_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 33 — operator UX + honesty docs (2026-09-04)

`farm/QUICKSTART.md` (27 lines): consent → SCOPE → tool-bin DEMO vs real → `make farm-toolbin-e2e` → CISO zip → `--live` only on drop box. Root README “Private drop-box farm” links QUICKSTART + ARCHITECTURE. STATUS + product-lab/EXECUTIVE stamp **111 / 32 / 30**, pytest **180** (179 + QUICKSTART doc test), e2e 63/63 poam 61. DEMO ≠ client estate. Catalog **not inflated**. Cycles 31–32 stand. Labs green. Compose ABSENT.

```json
{"pytest": 180, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": {"assets": 63, "findings": 63, "poam": 61, "demo": true}, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 32 — conductor farm_toolbin_status + MCP snippets (2026-09-04)

Conductor adds `farm_toolbin_status` (FARM_TOOL_BIN resolve: present/missing/demo_stub for wired invoke). `tools/call` `orchestrator_plan` returns per-stage `will_run`. OPERATOR.md + operator_mcp_interface.md have Cursor `.cursor/mcp.json` and Claude Desktop snippets; `scripts/mcp_stdio.sh` starts from repo root. Catalog **not inflated**. Cycle 31 e2e stands. No live internet. No fake compose. pytest **179**. Labs green. Compose ABSENT.

```json
{"pytest": 179, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": "pass", "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 31 — farm-toolbin-e2e quiet→loud DEMO (2026-09-04)

`make farm-toolbin-e2e` / `scripts/farm_toolbin_e2e.py`: isolated `farm/work/e2e` with `FARM_TOOL_BIN=farm/tool-bin/lab`. Plan → discover (DEMO nmap stub) → deepen small batch (DEMO nessus/nessuscli) → external **plan-only** → ingest → Layer C. Artifacts in `in/nmap|vuln`; CISO/POA&M exist; pack `in/` untouched; `demo` true. LICENSE-LOCK still refuses nuclei/openvas. Catalog **not inflated**. No live internet. No fake compose pass. pytest **178**. Labs green. Compose ABSENT.

```json
{"pytest": 178, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_toolbin_e2e": {"assets": 63, "findings": 63, "poam": 61, "demo": true}, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 30 — deepen FARM_TOOL_BIN DEMO stubs (2026-09-04)

Lab stubs add nessus / nessuscli / testssl / testssl.sh / lynis (fixture stdout, DEMO banner, no network). Deepen + external-adjacent plan `will_run` true; `external_stage` still forces false. Dry `run_slot` writes work out. LICENSE-LOCK refuse stands. `make farm-toolbin-lab` asserts nmap+curl. Catalog **not inflated**. pytest **176**. Labs green. Compose ABSENT.

```json
{"pytest": 176, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 29 — FARM_TOOL_BIN DEMO lab stubs (2026-09-04)

`farm/tool-bin/lab/{nmap,curl}` are DEMO shell stubs (fixture gnmap / HTTP headers, no network). `farm_which` checks `FARM_TOOL_BIN` then `FARM_TOOL_BIN/lab` then PATH. Plan `will_run` true when env points at stubs; dry invoke writes work out. External stage still `will_run=false`. Catalog **not inflated**. pytest **172**. Labs green. Compose ABSENT.

```json
{"pytest": 172, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 28 — compose scanner-free skeletons (2026-09-04)

Farm + dropbox compose bind SCOPE / work/in / work/out / tool-bin. Statics catch apt/apk/yum/dnf, pip, wget, FROM/image soup, COPY `.deb`, `git clone`, and wrap `curl … /api/risks`. `make farm-compose` added. Docker absent → **ABSENT** after static PASS (not a fake runtime pass). Catalog **not inflated** (111 / 32 / 30 / 81). pytest **168**. Labs green.

```json
{"pytest": 168, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 27 — ingest dropped external files (2026-09-04)

`ingest_stage` inventories operator-landed files in `in/easm|…` (`dropped_external`). Skips `.gitkeep` / `plan.json`. Still `will_run=false` / `live=false` / `probed=false`. No curl/testssl from orchestrate. Catalog **not inflated** (111 / 32 / 30 / 81). pytest **163**. Labs green.

```json
{"pytest": 163, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 26 — external stage plan-only (2026-09-04)

Stage graph: discover → deepen → **external (plan-only)** → ingest. SCOPE external refuses CIDR, wildcards, `0.0.0.0/0`; named hosts and `https://` URLs allowed. External SLOTS all `will_run=false` (`file_drop or plan-only — operator lands artifacts in in/easm|…`). `make dropbox-external` stays DEMO fixture writer — no live probe from orchestrate/CI. Catalog **not inflated** (111 / 32 / 30 / 81). pytest **160**. Labs green.

```json
{"pytest": 160, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 25 — farm ↔ orchestrator slot selection (2026-09-04)

Plan JSON lists SLOTS per stage from `allow_tools ∩ wired invoke ∩` discover / deepen / external. `--live` discover runs only discover-stage invoke adapters on PATH; missing gets an explicit skip_reason. Deepen batches use deepen invoke slots on discover-live hosts or `deepen_hosts`. nuclei / openvas / file_drop-only never subprocess. Catalog **not inflated** (111 / 32 / 30 / 81). pytest **158**. farm-lab 62/62/24 poam 61. compose absent.

```json
{"pytest": 158, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 24 — farm_slots.brakes matches INTEGRITY.md (2026-09-04)

Conductor `farm_slots` returns structured `brakes` (SCOPE, deepen fail-closed, max_workers=2, batch 2–5, timeout 30s, wrap review-only). Catalog unchanged: **111 / 32 / 30 / 81**. pytest **153**. farm-lab 62/62/24 poam 61.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "farm_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 23 — Layer C ingest map on SLOTS.md (2026-09-04)

`farm/SLOTS.md` now includes an **Ingest map (Layer C)** table: every slot lands in `in/cloud|nmap|vuln|wazuh|identity|easm|k8s|code|saas`. `ingest_map()` sums to 111. FILE_DROP_ONLY names listed. No theater parsers. Catalog unchanged: **111 / 32 / 30 / 81**.

pytest **153 passed, 1 skipped**. `make farm-lab` 62/62/24 poam 61. compose_lab absent.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "ingest_audit": [], "farm_lab": "pass", "host_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 22 — hostname PATH stub hits 30 invoke (2026-09-04)

Sixth real OS PATH stub (`hostname -f`, discover-adjacent, `in/nmap/`). Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Cycle 20’s 105 named slots stand. No fake padding. Labs unchanged.

pytest **153 passed, 1 skipped**. `make lab` / `make farm-lab` 62/62/15/24 poam 61. `make dropbox-lab` 68/71. compose_lab absent.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 111, "wired": 32, "invoke": 30, "file_drop": 81, "assets": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 21 — quality: PATH-invoke toward 30, conductor, ingest audit (2026-09-04)

Cycle 20 **105** named slots stand. Added 5 real OS stubs (ping / traceroute / tracepath / host / getent) and rewired existing oss_byo (journalctl, kubectl client, snmpwalk named-host). **110 / 31 wired / 29 invoke / 81 file_drop**. nikto / gobuster / ffuf / amass / subfinder / scoutsuite / checkov stay file_drop. Conductor `tools/list` is stable `OPERATOR_TOOLS` order; `farm_slot_status` accepts `category`. `audit_output_globs()` empty — every glob is `in/<Layer-C-sensor>/`. `farm/INTEGRITY.md` brakes table. Cursor `.cursor/mcp.json` snippet in `farm/OPERATOR.md` has `cwd` + `PYTHONPATH`. Wrap dead. No Hexstrike. No USB. No paying-day PASS.

pytest **153 passed, 1 skipped**. `make lab` / `make farm-lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64. compose_lab absent.

```json
{"pytest": 153, "pytest_skipped": 1, "farm_slots": 110, "wired": 31, "invoke": 29, "file_drop": 81, "assets": 62, "findings": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 20 — 105-slot catalog (95+), SLOTS.md, conductor counts (2026-09-04)

`farm/SLOTS.yaml` is **105** slots across discover/deepen/external/endpoint/identity/cloud/k8s/secrets/wifi/ot. **23 wired / 21 invoke / 84 file_drop**. openssl + nslookup added as PATH stubs. LICENSE-LOCK (nuclei, openvas, gvm, pingcastle, bloodhound, sharphound, …) stay file_drop, never subprocess. `farm/SLOTS.md` is the category table. Conductor `farm_slots` returns `counts` + `by_category`. Layer C untouched. Wrap dead.

pytest **149 passed, 1 skipped**. `make lab` / `make farm-lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64. compose_lab absent.

```json
{"pytest": 149, "pytest_skipped": 1, "farm_slots": 105, "wired": 23, "invoke": 21, "file_drop": 84, "assets": 62, "findings": 62, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "wrap": "review-only"}
```

## cycle 19 — 21 wired adapters, farm-lab DEMO, farm_slot_status (2026-09-04)

Wired SLOTS **21** (19 invoke + kube-bench/gitleaks file-drop stubs). New invoke: rustscan, naabu, httpx, dig, whois, sslscan. LICENSE-LOCK (nuclei/openvas/pingcastle) never subprocess. Conductor `tools/call` returns plan-only JSON for stage_discover/deepen/ingest plus `farm_slot_status` matrix. `make farm-lab` = plan → fixture discover → ingest → Layer C under `farm/work` (DEMO, not pack `in/`). `farm/OPERATOR.md` is one copy-paste runbook to CISO zip. Wrap dead.

pytest **149 passed, 1 skipped**. `make lab` 62/62/15/24 poam 61. `make farm-lab` 62/62/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64. compose_lab absent.

```json
{"pytest": 149, "pytest_skipped": 1, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "farm_lab": "pass", "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "scanner_free": true, "farm_slots": 51, "wired_adapters": 21, "invoke_adapters": 19, "wrap": "review-only"}
```

## cycle 18 — private farm catalog + adapters + conductor (2026-09-04)

`farm/SLOTS.yaml` is a 48-slot tool-zoo catalog (discover/deepen/external/endpoint/identity/cloud/k8s/secrets) with binary, SCOPE key, output glob → `in/<sensor>/`, license_class, default_batch. 13 wired adapter stubs (plan-only if missing; PATH stub tests). `farm/OPERATOR.md` is the install → mount → quiet→loud path. Compose adds short-lived discover/deepen/ingest workers on an internal network. Orchestrator stage graph: plan → shard → discover → destroy → deepen → destroy → ingest → grc_export. Status prints allow_tools ∩ PATH ∩ SLOTS. Conductor lists 8 SCOPE-gated tools and invokes plan/status/farm_slots over JSON-RPC (no FastMCP, no Hexstrike). Layer C untouched. Ingest skips plan.json so pack `in/` stays gitkeep. Wrap dead.

pytest **147 passed, 1 skipped**. `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. `make dropbox-compose` scanner_free true, status absent.

```json
{"pytest": 147, "pytest_skipped": 1, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "compose_lab_reason": "docker CLI not on PATH", "scanner_free": true, "farm_slots": 48, "wired_adapters": 13, "wrap": "review-only"}
```

## cycle 17 — private farm layout (Layer A) (2026-09-04)

`farm/` is a private operator drop-box: README + `SLOTS.yaml` + scanner-free Dockerfile/compose skeleton. Tools arrive via host PATH, `FARM_TOOL_BIN` bind-mount, or image tags Reid builds. Not Hub soup. Binaries not vendored. Same static apt/embed asserts cover `farm/Dockerfile` + `farm/docker-compose.yml`. Layer C 10 collectors untouched/parse-only. Integrity stop: farm is private. Wrap dead.

pytest **140 passed, 1 skipped**. `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. `make dropbox-compose` scanner_free true, status absent.

```json
{"pytest": 140, "pytest_skipped": 1, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "compose_lab_reason": "docker CLI not on PATH", "scanner_free": true, "wrap": "review-only"}
```

## cycle 16 — dropbox compose scanner-free + honest ABSENT (2026-09-04)

`dropbox/scanner_free.py` + `tests/test_compose_scanner_free.py` fail if nmap/nessus/nuclei/openvas/gvm reappear as apt/pip/wget/FROM in `Dockerfile` or compose files. `make dropbox-compose` always runs those statics. This VM: **compose_lab: absent** (`docker CLI not on PATH`) — not a fake pass. Runtime path (internal+external demo/dry + image `command -v` probe) is implemented for when Docker is present. CISO `product-lab/drop/MANIFEST` refreshed to current empty-`in/` hashes (62/62/24 poam 61). Wrap dead.

pytest **136 passed, 1 skipped** (honest compose runtime skip). `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. `make dropbox-compose` scanner_free true, status absent.

```json
{"pytest": 136, "pytest_skipped": 1, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "compose_lab_reason": "docker CLI not on PATH", "scanner_free": true, "wrap": "review-only"}
```

## cycle 15 — MCP serve, worker teardown, external named-only (2026-09-04)

`python3 -m dropbox.mcp_stub serve` lists the seven SCOPE-gated tools (no FastMCP, no Hexstrike). Discover/deepen destroy workers on timeout/failure; status prints timeout, batch overflow, scope miss. External SCOPE refuses wildcards and CIDRs. testssl/curl BYO adapters parallel to nmap. Telnet POA&M golden. Owner/due blank. Wrap dead.

pytest **132**. `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. Plan-only 3 shards / 2 batches / destroyed=3.

```json
{"pytest": 132, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only"}
```

## cycle 14 — three layers + Hexstrike-pattern stub + DEMO E2E (2026-09-04)

Architecture documented (A BYO / B brakes / C parse-only). Hexstrike is UX pattern only — `mcp_stub.py` SCOPE-gated, no vendor submodule, no exploit API. Internal+external DEMO scripts stamp honest DEMO labels through in/ → POA&M → CISO. BYO adapters actually invoke allowlisted PATH stubs. Status CLI prints stage graph, last integrity stop, allow_tools ∩ PATH. POA&M goldens: TLS weak cipher, admin shares, open RDP (owner/due blank). Dropbox-lab `demo: true`.

pytest **126**. `make lab` 62/62/15/24 poam 61 demo true. `make dropbox-lab` 68/71/15/24 poam 64 demo true. Plan-only 3 shards / 2 batches / destroyed=3. Wrap dead. Docker absent.

```json
{"pytest": 126, "assets": 62, "findings": 62, "evidences": 24, "poam": 61, "assets_dropbox_lab": 68, "findings_dropbox_lab": 71, "poam_dropbox_lab": 64, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only", "demo_dropbox_lab": true}
```

## cycle 13 — rebase master + orchestrator harden (2026-09-04)

Rebased onto `b9055eb` (CI, loopback bind, evidence floor). Wrap stayed dead. Added BYO adapters, `dropbox status`, SCOPE `--live` refuse (empty/unsigned/0.0.0.0/0), deepen `--live` exit 2 without `stages.deepen`, deepen worker tear-down tests, TLS + admin-share POA&M maps.

pytest **111**. `make lab` 62/59/15/24 poam 58 demo true. `make dropbox-lab` 68/69/15/24 plan-only 3 shards / 2 batches / destroyed=3. Wrap dead. Docker absent.

```json
{"pytest": 111, "assets": 62, "findings": 59, "evidences": 24, "poam": 58, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only"}
```

## cycle 12 — orchestrator = brakes (2026-09-04)

Quiet → loud governor. Discover defaults quiet (`nmap -sn`, host timeout, no deepen tools). Deepen fail-closed unless `orchestrator.stages.deepen: true`. Hosts from discover or explicit `deepen_hosts`. `max_workers` default 2. Never /16 in one worker. Never 0.0.0.0/0. Tear-down after each stage. SCOPE.example ships deepen false. DEMO sets true for plan-only lab.

pytest **88**. `make lab` 62/59/15/10 poam 58 demo true. `make dropbox-lab` 68/69 plan-only 3 shards / 2 batches / destroyed=3. Wrap dead. Docker absent.

```json
{"pytest": 88, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "orchestrator": "plan-only quiet→loud"}
```

## cycle 11 — Pentera wedge: finding → CPG/CSF + POA&M (2026-09-04)

Discovery is not enough. `shared/control_map.py` stamps high/critical and key medium (SMB/RDP) with wizard-safe `cpg_*` / `csf_*` (no colons). Loader writes `out/poam/poam.csv` (owner/due blank, status open) plus mapped `applied_controls`. Demo TCP/445 → restrict SMB / confirm SMBv1 disabled — not a CVE. Console `/api/poam` + drop zip. Docs: “Pentera finds it; Evergreen maps it.”

pytest **80**. `make lab` 62/59/15/10, poam **58**, demo true. `make dropbox-lab` 68/69 + orchestrator plan-only 3 shards / 2 batches / destroyed=3. Wrap still dead. Docker absent.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "applied_controls": 74, "poam": 58, "risk_scenarios": 74, "pytest": 80, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent"}
```

## cycle 10 — orchestrator shards (2026-09-04)

Intelligent chaining, not one scanner on a /16. `dropbox/orchestrator/`: discover shards CIDRs to /24, deepen batches 2–5 hosts, ingest copies artifacts. Plan-only without Nmap/Nessus. BYO if on PATH and in SCOPE.allow_tools. Workers destroyed after discover. Never download Nessus plugins. Never apt-embed.

pytest **75**. `make lab` 62/59 demo true. `make dropbox-lab` 68/69 (extra SCOPE hosts in demo inventory) + orchestrator 3 shards / 2 batches / destroyed=3. Wrap still dead.

## cycle 9 — LICENSE-LOCK + drop-box (2026-09-04)

Reid: pull/harden pack; same PR add evergreen drop-box.

Wrap: `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1`. No login, no curl, no POST. Tests fail if wrap endpoints reappear. Console binds 127.0.0.1 only. CISO prefers clica; no FindingsAssessment UUIDs.

Drop-box: `dropbox/` SCOPE gate (client, consent path+sha256, window, named internal/external). Internal/external profiles. Demo runners write gnmap + httpx JSONL + osquery-shaped host JSON into existing collector formats. No forbidden scanners in the image. `make dropbox-lab` seeds `dropbox/work/in` (not pack `in/`).

Labs this VM (Docker **absent**):

- pytest **61 passed**
- `make lab` empty pack `in/` → fixtures: 62 / 59 / 15 / 10, `demo: true`
- `make dropbox-lab`: 65 / 63 / 15 / 10, `demo: false` (files in IN_DIR) — still not a client
- Wrap `RISKREADY_PUSH=1 DRY_RUN=0` → LICENSE-LOCK, no HTTP
- Console http://127.0.0.1:18765/ ready; `/api/risks` 403

Not stamped: paying-day PASS. USB evergreen-assessment not copied.

```json
{"pytest": 61, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "sink": "absent"}
```


## cycle 1 — BUILD / LAB / GREEN

Pack shipped. Two consecutive green labs. critic 9/10. DONE.md GREEN.

## cycle 2 — parsers + tests (2026-09-01 evening PT)

Overnight 30m loop armed until 07:00 PT (PID 14860).

Improvements:
- Prowler ASFF Findings parser + `fixtures/demo/cloud/prowler-asff.json`
- PingCastle XML parser + `fixtures/demo/identity/pingcastle.xml`
- Amass JSONL `name` field + `fixtures/demo/easm/amass.jsonl`
- Greenbone results fixture
- osquery host coverage in host-wazuh
- `tests/test_schema.py` `tests/test_redact.py` `tests/test_parsers.py`
- `scripts/lab.ps1` `LOOP.md`

Lab: 23 pytest passed; lab_outputs PASS; docker compose loader exit 0. P2 closed. Makefile compose now `--exit-code-from grc-loader`.

```json
{"assets": 50, "findings": 44, "vulnerabilities": 11, "evidences": 10, "applied_controls": 55, "risk_scenarios": 55, "incidents": 41, "risks_proposed": 40, "ocsf": 44, "canonical": 106, "demo": true}
```

## cycle 3 — TruffleHog + Falco (allow-all)

User: allow all requests. Added TruffleHog JSONL (redacted) and Falco runtime events. pytest 25 passed. lab_outputs PASS.

```json
{"assets": 52, "findings": 46, "vulnerabilities": 13, "evidences": 10, "applied_controls": 59, "risk_scenarios": 59, "incidents": 44, "risks_proposed": 43, "ocsf": 46, "canonical": 112, "demo": true}
```

## cycle 4 — 10:36 PM PT tick

Cloud Custodian policies, Steampipe control rows, Nmap greppable (`-oG`). pytest 28 passed. lab_outputs PASS.

```json
{"assets": 55, "findings": 50, "vulnerabilities": 13, "evidences": 10, "applied_controls": 63, "risk_scenarios": 63, "incidents": 47, "risks_proposed": 46, "ocsf": 50, "canonical": 119, "demo": true}
```

## overnight loop ended — 2026-09-02 07:00 PT

PID 14860 exited 0 after the 07:00 America/Los_Angeles cutoff (~9 hours). Not re-armed.

Completed ticks that produced labs: cycle 2–4. Cycle 5 parsers (BloodHound edges, Fleet, SARIF) were written during the 23:07 PT tick; the lab command was interrupted, so those counts were never recorded.

## cycle 5 — C5-LAB + C5-STAMP (2026-09-02 21:58 PT)

`scripts\lab.ps1`: pytest 31 passed, lab_outputs PASS.

Proved in canonical: BloodHound GenericAll/DCSync/AdminTo, Fleet `fleet-laptop-07` coverage, SARIF `python.lang.security.audit.sql-injection`.

```json
{"assets": 60, "findings": 54, "vulnerabilities": 14, "evidences": 10, "applied_controls": 68, "risk_scenarios": 68, "incidents": 52, "risks_proposed": 51, "ocsf": 54, "canonical": 129, "demo": true}
```

DONE_CYCLE5.md GREEN.

## cycle 6 — KEEP queue

KEEP-HK HardeningKitty CSV (identity, no new service). KEEP-MAESTER. KEEP-TESTSSL. KEEP-ASFF2 ScoutSuite. HOSTILE+ Fleet missing hostname. docs/EXCEPTIONS.md. filtering_labels strip blanks. Double lab.ps1 62=62 unique. Evidence names all nine sensors. Compose loader 62/58.

pytest 36. DONE_IMPROVE.md GREEN.

```json
{"assets": 62, "findings": 58, "vulnerabilities": 15, "evidences": 10, "applied_controls": 73, "risk_scenarios": 73, "incidents": 57, "risks_proposed": 56, "ocsf": 58, "canonical": 136, "demo": true}
```

## cycle 7 — README-weak formats

CONTINUE queue 1–12 already GREEN. Added Microsoft Graph directoryRoles (README Scuba/Graph/Okta), kube-bench + httpx unit tests, wizard-safe `cpg_2_W` on CISO filtering_labels.

pytest 39. lab 62 assets / 59 findings.

## cycle 8 — product lab (Docker + evidence)

No new parsers. Inventory + host lab ×2 + compose ×2 + sink truth + negatives. Reports under `product-lab/`. `DONE_PRODUCT_LAB.md` GREEN. Critic 9/10 (P2 typo `OUT_DIR` mkdir empty). Sink absent on this repo; host `:18080` is the other tree and was not contacted.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 10, "pytest": 39, "host_lab": "pass", "compose_lab": "pass", "sink": "absent"}
```

## cycle 10 — public-repo hardening

CI workflow, SECURITY.md, loopback bind lock, evidence floor 24, import previews, VERSION 0.3.0. Two host labs + compose. `DONE_GITHUB.md` GREEN.

```json
{"assets": 62, "findings": 59, "vulnerabilities": 15, "evidences": 24, "pytest": 55, "host_lab": "pass", "compose_lab": "pass"}
```





