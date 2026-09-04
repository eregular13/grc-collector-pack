# Private farm operator path

**Written SCOPE required.** Drop-box only under written SCOPE. Not a public Hub image. Layer C parses `in/<sensor>/` only.

See `dropbox/ARCHITECTURE.md` Layer A / B / C.

## Copy-paste runbook (bare Linux → CISO zip)

```bash
# 0) repo root, no scanner install from this tree
cd /path/to/grc-collector-pack
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0

# 1) written SCOPE (copy example, fill client/consent/window/CIDRs)
# cp dropbox/SCOPE.example.yaml dropbox/SCOPE.yaml
python3 -m dropbox gate
python3 -m dropbox status

# 2) optional: tools YOU install (never this Dockerfile)
# export PATH="$PATH:/opt/farm/bin"
# export FARM_TOOL_BIN=/opt/farm/bin
#    copy real allowlisted binaries into farm/tool-bin/ on the drop box
#    OR rely on host PATH. farm/tool-bin/lab/ is DEMO stubs only (nmap/curl).

# 3) DEMO path (fixtures, not a client) — plan → fixture discover → ingest → Layer C
make farm-lab

# 4) real engagement: drop artifacts into in/<sensor>/ (or farm/work/in), then:
python3 -m dropbox orchestrate          # plan-only unless --live + allowlisted PATH
# IN_DIR=$PWD/in OUT_DIR=$PWD/out python3 collectors/grc_loader.py

# 5) CISO zip from localhost console (after lab outputs exist)
# bash scripts/start-product.sh
# open http://127.0.0.1:18765/  → download drop zip (CISO CSVs + poam.csv)
# owner/due stay blank. Do not POST /api/risks. RiskReady is review-only.
```

`make farm-lab` writes under `farm/work/` (not pack `in/`). Stamp is DEMO.

## tool-bin mount (PATH vs copy)

On the drop box, tools come from **host PATH** or a **bind-mount / copy** into
`farm/tool-bin/` (`FARM_TOOL_BIN`). This repo does not apt-install scanners.

**DEMO stubs vs real binaries:** `farm/tool-bin/lab/` ships shell stubs
(`nmap`, `curl`, `nessus`, `nessuscli`, `testssl`, `testssl.sh`, `lynis`).
Each prints a DEMO banner and fixture-shaped stdout. They are not scanners
and make no network calls. `make farm-toolbin-lab` points `FARM_TOOL_BIN` at
that directory and asserts nmap+curl `will_run`. On a consented box, copy
**your** allowlisted binaries into `farm/tool-bin/` (parent) or rely on host
PATH. Do not commit ELF/deb scanner packages. Unset `FARM_TOOL_BIN` for
`make farm-lab` so that lab stays plan-only fixtures.

```bash
# DEMO quiet→loud (stubs only, no internet, not pack in/):
make farm-toolbin-lab          # will_run nmap+curl
make farm-toolbin-e2e          # discover→deepen stubs → external plan-only → Layer C

# real binaries on a consented box (you install; this repo does not):
# export FARM_TOOL_BIN=/usr/local/bin
# # or: cp "$(command -v nmap)" farm/tool-bin/nmap && export FARM_TOOL_BIN="$PWD/farm/tool-bin"
# python3 -m dropbox orchestrate --live
```

Unset `FARM_TOOL_BIN` for `make farm-lab` — that lab stays plan-only fixtures.

## Compose skeleton (statics vs runtime)

`farm/docker-compose.yml` is an **operator skeleton**: bind-mounts for
written `SCOPE.yaml`, `work/in`, `work/out`, `FARM_TOOL_BIN` → `/opt/farm/bin`,
and orch scratch. The Dockerfile is `python:3.12-slim` + COPY. No `RUN apt`.
No Hub soup image.

```bash
make dropbox-compose    # pack + farm + dropbox statics; runtime only if Docker is up
make farm-compose       # farm skeleton statics; never fakes a runtime pass
```

**What statics prove:** no apt/pip/wget/FROM embed of nmap/nessus/nuclei/openvas/gvm/zeek
(and the rest of LICENSE-LOCK). Wrap POST of risks is refused in image/compose files.
SCOPE/work/tool-bin binds present, `DROPBOX_LIVE=0` / `RISKREADY_PUSH=0`.

**What remains unexercised:** compose **runtime** (workers actually starting) when
Docker CLI is missing. This VM stamps **ABSENT** after static PASS — not a compose
pass. An operator with Docker may start profiles locally under written SCOPE.
Do not treat ABSENT as paying-day evidence.

## License classes (`SLOTS.yaml`)

| Class | Meaning |
|---|---|
| `use_dont_ship` | LICENSE-LOCK / do not embed. File-drop or BYO nmap/nessus only. |
| `commercial_byo` | Vendor CLI you licensed. We do not ship it. |
| `oss_byo` | OSS you installed. Missing → plan-only. |

Catalog is **95+** slots (`SLOTS.md`). LICENSE-LOCK names (nuclei, openvas, gvm, pingcastle, bloodhound, …) stay **file_drop**. Adapters never subprocess them.

Nmap **gnmap/XML/JSON** is file-drop ingest under `in/nmap/`. Layer C parses
hosts and exposure findings only — the collector never runs `nmap`. Discover
may land DEMO stub gnmap from `farm/tool-bin/lab/nmap`. Open 445 / 3389 / 23
map to existing SMB / RDP / Telnet POA&M rows.

kube-bench / kubescape / gitleaks are **file_drop** (never subprocess). Drop
Kubescape or kube-bench JSON into `in/k8s/` — Failed/FAIL only. Layer C does
not run `kubectl` or talk to a cluster. High rows map to CISO/POA&M when
obvious (privileged, anonymous-auth, privilege escalation, hostNetwork).

Nuclei **JSON/JSONL** is file-drop ingest under `in/vuln/`. Layer C parses
JSONL, a single object, an array, or a `{results|matches|findings}` wrapper.
INFO rows stay silent. Empty results invent nothing. High Log4Shell / RCE
rows map to existing CISO/POA&M. The collector never runs `nuclei`.

Nuclei / Semgrep / Trivy **SARIF** is file_drop: land `in/vuln/*.sarif` or
`in/code/*.sarif`. Layer C parsers emit findings; high rules become CISO/POA&M
rows. This repo does not invoke those tools.

testssl JSON and **Maester** / Entra Graph *exports* are file-drop ingest:
land testssl JSON under `in/vuln/` or `in/easm/`; Maester or `directoryRoles`
JSON under `in/saas/`. Layer C parses HIGH testssl rows and Failed Maester
rows only — no live TLS probe, no Graph API call. OK/Passed stay silent.
testssl / Maester *invoke* is separate BYO (`allow_tools`) if already on PATH.
Orchestrate external stays plan-only.

BloodHound CE / SharpHound JSON is file-drop ingest under `in/identity/`.
Layer C parses `data.nodes` / `data.edges`, graph `nodes`/`edges`, or
SharpHound `data` arrays (`Properties` / `ObjectIdentifier` / mapped `Aces`).
Empty `data` and empty `Members` invent nothing. No LDAP / BloodHound API /
SharpHound run. High rows map to existing CISO/POA&M (DCSync, GenericAll,
roastable SPN, AS-REP, unconstrained delegation, Backup Operators).
bloodhound / azurehound stay file_drop.

Fleet host/policy JSON is file-drop ingest under `in/wazuh/`. Layer C parses
`hosts` / `data.hosts` / a single `host`, plus failing `policies` only.
Offline hosts are coverage gaps. Disk encryption off and MDM enrollment Off
map to existing CISO/POA&M. Empty hosts/policies invent nothing. No Fleet
API / fleetctl / osqueryi.

CIS-CAT / XCCDF JSON or XML is file-drop ingest under `in/wazuh/` or
`in/identity/`. Failed rows only. Empty results invent nothing. High rows
map to existing CISO/POA&M (SSH PermitRootLogin, host firewall, disk
encryption). osquery **check** JSON (`queries` with status=fail) lands under
`in/wazuh/`. The collector never runs `cis-cat` or `osqueryi`.

HardeningKitty **Audit CSV** and **Lynis** reports are file-drop ingest:
land HK CSV under `in/identity/`, Lynis report/`report.dat` under `in/wazuh/`.
Layer C parses Failed HK rows and Lynis warnings only — no WinRM/AD API, no
live Lynis from the collector. High rows map to CISO/POA&M when obvious.
Passed HK rows (including Guest) stay silent. Lynis *invoke* is separate BYO
(`allow_tools`) only if the binary is already on PATH.

Prowler / ScoutSuite **cloud** is file-drop ingest under `in/cloud/`: land
Prowler JSON, Prowler ASFF, or ScoutSuite `services.*.findings` JSON (Custodian
and Steampipe also parse). Layer C does not call AWS/GCP/Azure APIs. High FAIL
rows map to CISO/POA&M when the check is obvious. Prowler *invoke* is separate
BYO (`allow_tools`) only if the binary is already on PATH. ScoutSuite stays
`file_drop` even if `scout` is on PATH.

## Orchestrator + conductor

Stage graph (quiet→loud): `plan → shard → discover → destroy → deepen (2–5) → destroy → external (plan-only) → ingest → grc_export`

Plan JSON lists `slots` per stage: `allow_tools ∩ wired invoke ∩` discover / deepen / external.
`--live` discover runs only those discover invoke slots that are on PATH; missing → `skip_reason`.
Deepen uses deepen invoke slots on discover-live hosts or `deepen_hosts`.
**External is plan-only** in this pack: slots list with `will_run=false` and
`file_drop or plan-only — operator lands artifacts in in/easm|…`.
Ingest inventories those dropped files (`dropped_external` on the ingest
marker). It does not probe. `make dropbox-external` writes DEMO fixtures
into `in/easm/`. httpx / Amass / Subfinder JSON or JSONL is file-drop
ingest: native arrays and `{results|hosts}` wrappers parse. Failed httpx
rows and empty exports invent nothing. High perimeter / admin-UI / TLS
rows map to existing CISO/POA&M. Layer C never runs amass, httpx, or
subfinder and does not probe DNS/HTTP. Live BYO curl/testssl is
operator-local under written SCOPE — not orchestrate.
LICENSE-LOCK / file_drop names never subprocess.

```bash
python3 -m dropbox orchestrate
python3 -m dropbox orchestrate --live   # BYO PATH only; still SCOPE-gated
python3 -m dropbox.mcp_stub serve
python3 -m dropbox mcp farm_slot_status
python3 -m dropbox mcp farm_toolbin_status
python3 -m dropbox mcp stage_discover    # plan-only
```

The conductor is **`dropbox.mcp_stub`** JSON-RPC on stdin/stdout — **not**
hosted FastMCP. It must start from the **repo root**. Replace
`/absolute/path/to/grc-collector-pack` with this checkout. Prefer
`scripts/mcp_stdio.sh` (finds the root itself) when the client ignores `cwd`.

**Cursor** — project file `.cursor/mcp.json` (or user `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "grc-dropbox": {
      "command": "python3",
      "args": ["-m", "dropbox.mcp_stub", "serve", "--stdio"],
      "cwd": "/absolute/path/to/grc-collector-pack",
      "env": {
        "PYTHONPATH": "/absolute/path/to/grc-collector-pack",
        "DROPBOX_LIVE": "0",
        "GRC_LIVE_SCAN": "0",
        "CISO_PUSH": "0",
        "RISKREADY_PUSH": "0"
      }
    }
  }
}
```

**Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `~/.config/Claude/claude_desktop_config.json` (Linux). Many
builds ignore `cwd`; point `command` at the wrapper:

```json
{
  "mcpServers": {
    "grc-dropbox": {
      "command": "/absolute/path/to/grc-collector-pack/scripts/mcp_stdio.sh"
    }
  }
}
```

`tools/list` returns the ten operator tools in **fixed** `OPERATOR_TOOLS`
order (`scope_status`, `orchestrator_plan`, `orchestrator_status`,
`stage_discover`, `stage_deepen`, `stage_ingest`, `farm_slots`,
`farm_slot_status`, `farm_toolbin_status`, `export_ciso_poam`).
`farm_slot_status` accepts an optional `{ "category": "discover" }`
argument. `farm_toolbin_status` lists wired invoke resolve as
`present` / `missing` / `demo_stub`. `orchestrator_plan` returns the
per-stage `will_run` map already in plan JSON.

Live deepen stays fail-closed (`DROPBOX_LIVE=0`) unless the operator
explicitly allowlists tools. Do not point this at public Layer C.

## Do not

- Publish `farm/` images to public Hub
- Apt-install scanners in `farm/Dockerfile`
- Copy USB evergreen-assessment
- Stamp paying-day PASS
- Submodule hexstrike-ai / add Metasploit
