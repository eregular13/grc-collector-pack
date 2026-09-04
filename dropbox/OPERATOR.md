# Drop-box operator — consent → VM → SCOPE → ingest → CISO

**Written:** 2026-09-04  
**Delivery:** with **written client consent**, Reid drops a box/VM into their environment, runs a one-two combo (internal + external), then dumps files into this pack for CISO Assistant.

This directory is the **gated runner**. The public pack stays parse-only. Do not turn the collectors into a scanner suite.

## Three layers (see `ARCHITECTURE.md`)

- **Layer A — BYO tool zoo.** Consent SCOPE names host tools already on the drop box. This repo does not embed Nmap/Nessus/Nuclei/OpenVAS.
- **Layer B — orchestrator = brakes.** Quiet discover → gated deepen → destroy workers → ingest into `in/` → grc_export. `python3 -m dropbox status` prints the stage graph, last integrity stop, shard/batch counters, and `allow_tools ∩ PATH ∩ SLOTS` (present/missing). Private farm install path: `farm/OPERATOR.md`.
- **Layer C — 10 containers (9 collectors + loader).** Parse-only files in `in/` → CISO / POA&M / SimpleRisk leave-behind.

Layer B **feeds** Layer C via `in/`. It does **not** turn Layer C into live scanners. “100 tools” means parser file-family inputs, not 100 binaries in compose.

Operator MCP stub (`mcp_stub.py`, `HEXSTRIKE.md`): Hexstrike-style stage/status UX only. No exploit-chain, no Metasploit, no hexstrike-ai submodule.

## Consent first (fail-closed)

1. Get **written** client consent (PDF or signed memo).
2. Store it next to the box, e.g. `dropbox/consent/SIGNED-CONSENT.md`.
3. `sha256sum` that file.
4. Copy `dropbox/SCOPE.example.yaml` → `dropbox/SCOPE.yaml`.
5. Fill:
   - `client.name`
   - `consent.attestation_path` + `consent.attestation_sha256`
   - `engagement.start` / `engagement.end` (today must fall inside)
   - **named** `internal.cidrs` and/or `internal.hosts`
   - **named** `external.hosts` / `domains` / `ips`
   - `allow_tools` (`lynis`, `ss`, `ip`, `curl`; optional BYO `nmap` / `nessus` if **you** installed them)
   - Orchestrator brakes (see below): `stages.deepen` (default **false**), `max_workers`, `deepen_batch` (2–5), `host_timeout_sec`, `deepen_hosts`, `max_live_shards`

No `SCOPE.yaml` → runners do not start. Missing or hash-mismatched attestation → exit 2.

```bash
python3 -m dropbox gate
```

## Drop the VM

Place this repo on the box. This repo does **not** apt-install or Docker-embed Nmap, Nuclei, OpenVAS/GVM, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, or any RiskReady wrap.

If the client consented and **you** install Nmap and/or Nessus on the drop box yourself, list them in `SCOPE.allow_tools`. Evergreen only shards and stages. It will not download those tools or Nessus plugins.

## Run internal (this host only)

```bash
python3 -m dropbox run --profile internal
# live ss/lynis only if already on PATH and listed in allow_tools:
python3 -m dropbox run --profile internal --live
```

What internal **does**

- Local listen inventory via `ss`/`ip` (or demo gnmap from named SCOPE hosts) → `in/nmap/dropbox-inventory.gnmap`
- Lynis **only** if `lynis` is on PATH and in `allow_tools` → host JSON in `in/wazuh/` (full Lynis controls are **not** parsed; no Lynis collector)
- BYO: if a binary is already on PATH **and** named in `SCOPE.allow_tools` / `byo`, run SCOPE args and capture stdout → `in/<sensor>/`. Never downloads. Forbidden names are rejected even if listed.

What internal **does not**

- No unsarded Nmap of a /16. CIDR spray is the orchestrator’s job, one /24 (or configured prefix) at a time, and only if `nmap` is already on PATH.
- No Wazuh/osquery/BloodHound/PingCastle execution.

## Orchestrator = brakes (quiet → loud)

Client **environment integrity is paramount**. The farm still has to find vulns and misconfigs, but it is a governor, not a coverage contest. Defaults prefer integrity over coverage ego.

```bash
python3 -m dropbox status               # SCOPE brakes + last run (stage, shards, batches, stops)
python3 -m dropbox orchestrate          # plan-only if nmap/nessus are absent
python3 -m dropbox orchestrate --live   # BYO binaries only; still SCOPE-gated
```

`status` prints the quiet→loud governor, shard/batch brakes, and integrity stops (unsigned SCOPE never gets this far — the gate exits 2). Last-run lines come from `dropbox/out/summary.json` after an orchestrate. DEMO fixtures are labeled **not a client estate**.

### Product contract

1. **Discover is QUIET.** Wide shard inventory only (`internal.cidrs` → `/24` jobs, or `orchestrator.discover_prefix`). Low impact (`nmap -sn` + `--host-timeout`). **No deepen tools** in this stage. Plan lists farm slots: `allow_tools ∩ wired invoke ∩ discover`. `--live` uses only those discover invoke adapters on PATH; missing → `skip_reason`. LICENSE-LOCK / file_drop never subprocess.
2. **Brakes (always on).** SCOPE required. `max_workers` (default **2**). `deepen_batch` 2–5 (default **3**). `host_timeout_sec` (default **30**). Tear-down after every stage. **No targets outside SCOPE.** No `0.0.0.0/0` and no prefix shorter than `/8`.
3. **Deepen is LOUDER and gated.** Runs only when `orchestrator.stages.deepen: true`. Missing or false → **fail closed** (no deepen workers, `--live` exits 2). Hosts come from **discover live results** or an explicit `orchestrator.deepen_hosts` list — never “the whole estate” and never a /16 in one worker. Small batches only. Tools only from deepen-stage farm invoke slots ∩ `allow_tools` on PATH (Nessus CLI if you installed it).
4. **Never open-internet spray.** Never one worker across a /16. External named hosts are the `run --profile external` path, not deepen.
5. **Outputs stay the pack path:** discover/deepen artifacts → `in/` → control map → `out/poam/poam.csv` → CISO CSVs. Pentera (or Nmap/Nessus) finds it; Evergreen maps it.

`SCOPE.example.yaml` ships `stages.deepen: false`. Set it true only when the client consented to louder tools on a named host list. The committed DEMO `SCOPE.yaml` sets `deepen: true` so `make dropbox-lab` still exercises the plan (no binaries).

`make dropbox-lab` is **plan-only** without Nmap/Nessus. Lab stays green without those binaries. Workers are destroyed after discover and after deepen.

## Run external (named SCOPE targets only)

Orchestrator stage **`external` is plan-only**. It lists farm slots and named
SCOPE hosts; it does **not** curl or testssl the internet. Operator lands
artifacts in `in/easm/` (or other Layer C dirs). Live BYO header-grab is
**operator-local** under written SCOPE — not this PR’s CI/agent path.

```bash
python3 -m dropbox orchestrate          # includes external (plan-only)
make dropbox-external                   # DEMO fixture writer → in/easm/
python3 -m dropbox run --profile external
```

`make dropbox-external` / `scripts/dropbox-external.sh` stay DEMO fixture
writers (DROPBOX_DEMO=1). They do not add a new live probe. Wildcards, CIDRs,
and `0.0.0.0/0` are refused in `external:` at the SCOPE gate. Named hosts and
`https://` URLs are allowed.

Operator MCP: `python3 -m dropbox.mcp_stub serve` lists the seven SCOPE-gated tools and exits (no Hexstrike server, no FastMCP).

`make dropbox-compose` always runs scanner-free assertions on `Dockerfile` + `docker-compose.dropbox.yml`. If Docker is up it runs internal+external **demo/dry** profiles and checks the image has no scanner binaries. If Docker is absent it stamps **ABSENT** (not a pass).

Private farm layout (`farm/`, Layer A): allowlisted slots only. Binaries come from host PATH / bind-mount / Reid’s private tags. Not a public Hub image. Same scanner-free asserts cover `farm/Dockerfile` + `farm/docker-compose.yml`.

Output: `in/easm/dropbox-tls.jsonl` (existing easm collector).

## Ingest → CISO

```bash
bash scripts/lab.sh
# or: make lab
python3 -m product          # http://127.0.0.1:18765/
```

Collectors parse `in/<sensor>/`. Empty sensors still fall back to `fixtures/demo/` and label `demo`. Zip `out/` (or the console drop zip) for CISO Assistant. Prefer **clica / UI** CSV import. Hand `out/poam/poam.csv` as the POA&M draft — a human fills owner and due. Do not invent FindingsAssessment UUIDs.

RiskReady JSON is LICENSE-LOCK stay-out — review on disk. `push_riskready.sh` never logs in or POSTs.

SimpleRisk: see `dropbox/SIMPLERISK.md` (leave-behind docs only). No SimpleRisk push.

## Honest: BYO vs shipped

| Shipped in this repo | Not shipped |
|---|---|
| SCOPE gate, demo runners, parse-only collectors, localhost console | Nmap, Nuclei, OpenVAS, Nessus, Zeek, Wazuh agent, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, RiskReady wrap |
| Optional: `ss`/`ip`/`curl`/`lynis` **if already on the box** | Any download of those tools |
| Orchestrator shard/batch plans | Nmap/Nessus binaries and Nessus plugins (install yourself under consent) |

`make dropbox-lab` is **fixtures + demo overlays**, not a client estate. The committed `dropbox/SCOPE.yaml` is the DEMO consent fixture.

## Do not

- Live-scan CIDRs or the open internet
- POST `/api/risks`
- Restore RiskReady wrap
- Stamp paying-day PASS
- Copy USB evergreen-assessment
