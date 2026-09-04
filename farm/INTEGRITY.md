# Farm integrity (private, never a public Layer C scanner)

The farm is a **private** drop-box tool catalog + adapters. It is **not** a
public Layer C collector and **not** a paying-day assessment. Wrap is
review-only. Hexstrike is not vendored. USB evergreen-assessment is not copied.

Conductor `farm_slots` returns these defaults as structured `brakes` JSON.

## Brakes defaults

| Brake | Default | Fail-closed behavior |
|---|---|---|
| `dropbox/SCOPE.yaml` | Required written SCOPE | Orchestrator / farm refuse to start without client, attestation hash, window, named targets |
| Deepen | `orchestrator.stages.deepen` default **false** | Live deepen refused unless the flag is true **and** `allow_tools` is non-empty |
| `max_workers` | **2** (`DROPBOX_MAX_WORKERS` / SCOPE) | Extra live workers refused; no unbounded fan-out |
| `deepen_batch` | **3** (must be 2–5) | `GateError` if outside 2–5 |
| Host timeout | `host_timeout_sec` default **30** | Adapter raises `TimeoutError`; worker is destroyed |
| Wildcard / CIDR spray | External named hosts only | `0.0.0.0/0`, `*`, `/0`, and `/8`–`/16` spray never passed to adapters |
| BYO PATH | `allow_tools` ∩ PATH only | Binary missing or not allowlisted → plan-only; never apt/embed |
| LICENSE-LOCK embed | Never ship scanner packages | Nmap/Nessus BYO PATH+allowlist only; nuclei / OpenVAS / Zeek / Wazuh / osquery / PingCastle / Purple Knight / BloodHound / CIS-CAT stay file_drop, never subprocess |
| Exploit / vendor | Absent | No Metasploit, no Hexstrike submodule, no USB copy |
| Wrap | Review-only | `push_riskready.sh` prints LICENSE-LOCK and never POSTs, even if `RISKREADY_PUSH=1` |
| External stage | Plan-only | Named hosts/URLs only; no live curl/testssl from orchestrate; operator lands `in/easm/` |
| External ingest | File-drop inventory | `ingest_stage` lists dropped `in/easm|…` files; never probes; skips `.gitkeep` / `plan.json` |
| Layer C | Parse-only ingest | `in/<sensor>/` only; collectors never call farm adapters |
| Compose | Scanner-free | Farm Dockerfile has no `RUN apt`; compose runtime ABSENT here (no Docker CLI) |

## Adapter policy (quality, not catalog inflation)

PATH-invoke adapters are **safe BYO only**. Common OS binaries may be wired
when they exist on PATH (`ss`, `ip`, `ping`, `traceroute`, `tracepath`,
`host`, `getent`, `hostname`, `journalctl`, `kubectl` client, `snmpwalk` named-host).

These catalog names stay **file_drop** even if a binary is on PATH:

- `nikto`, `gobuster`, `ffuf`, `amass`, `subfinder`, `scoutsuite`, `checkov`

Helpers that are not collectors (`jq`, `yq`) are **not** catalog slots.
`python3` / `bash` already exist on PATH as interpreters — do **not** add
them as farm slots.

## Ingest mapping

Every `output_glob` must land under an existing Layer C sensor directory:

`in/cloud/` `in/nmap/` `in/vuln/` `in/wazuh/` `in/identity/` `in/easm/` `in/k8s/` `in/code/` `in/saas/`

`audit_output_globs()` fails the catalog if a glob uses any other prefix.
New sensor directories need a Layer C parser first — do not invent theater
parsers. Document a TODO instead.

Cycle 21: every SLOTS `output_glob` already lands in one of the nine Layer C
dirs above. No new sensor stub. No theater parser.

## Cycle 20 catalog stands

Cycle 20 shipped **105** named slots. This window adds a **small** set of
real OS PATH stubs (ping / traceroute / tracepath / host / getent / hostname)
and rewires existing oss_byo entries (journalctl, kubectl client, snmpwalk).
Do **not** inflate fake slots to hit a round number.
