# CISO Assistant export prove (SAMPLE/DEMO)

**Farm leave-behind (Covey pack_drop → CISO):** `./scripts/farm_drop_to_sor.sh`
or `make farm-drop-to-sor` (DESKTOP: `.\scripts\farm_drop_to_sor.ps1`).
That is the operator twin of `sample_to_sor` — it runs
`python3 scripts/prove_ciso.py` under `prove/work/` (never pack `in/`)
and fail-closes if prove JSON claims a client estate or `paying_day` PASS.

**Primary KEEP path this week** (not pack_drop): redacted
`fixtures/keep-samples/` → `./scripts/sample_to_sor.sh` (or
`python3 -m keep lab`) →
`keep/work/out/ciso-assistant/*.csv` + `IMPORT.md`. Honesty:
`demo: true` / SAMPLE ≠ client / `paying_day: FAIL`. See
`keep/OPERATOR.md`. `python3 -m keep ciso` is the same command.

Separate fixture prove below: **Covey pack_drop** + **Palisade/Beelzebub
honeypot** → existing collectors → `grc_loader` → **`out/ciso-assistant/*.csv`**.

This is not a client estate. It is not a paying-day PASS. HITL stays required
before any live PATH tool or `CISO_PUSH`. RiskReady wrap stays review-only —
never POST `/api/risks`.

## Exact commands

From the clone root. Desktop has no `make` / `gh` — `./scripts/farm_drop_to_sor.sh`
(or `.\scripts\farm_drop_to_sor.ps1`) is the one-command path.

```bash
./scripts/farm_drop_to_sor.sh
# DESKTOP: .\scripts\farm_drop_to_sor.ps1
# make farm-drop-to-sor
```

Same rails without the wrapper:

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
python3 scripts/prove_ciso.py
```

or `make prove-ciso`.

What that does (isolated under `prove/work/`, never pack `in/`):

1. Copy `fixtures/pack_drop/nmap/` → `prove/work/in/nmap/pack_drop/`
2. Copy `fixtures/pack_drop/rustscan/` → `prove/work/in/nmap/pack_drop/rustscan/`
   (stdout-class Covey `export_pack`; `covey.pack_drop.v1`)
3. Copy `fixtures/pack_drop/httpx/` → `prove/work/in/nmap/pack_drop/httpx/`
   (stdout-class Covey `export_pack`; `covey.pack_drop.v1`)
4. Copy `fixtures/pack_drop/unicornscan/` → `prove/work/in/nmap/pack_drop/unicornscan/`
   (stdout-class Covey `export_pack`; `covey.pack_drop.v1`)
5. Copy `fixtures/pack_drop/sslscan/` → `prove/work/in/nmap/pack_drop/sslscan/`
   (stdout/XML-class Covey `export_pack`; `covey.pack_drop.v1`)
6. Copy `fixtures/pack_drop/tlsx/` → `prove/work/in/nmap/pack_drop/tlsx/`
   (stdout-class Covey `export_pack`; `covey.pack_drop.v1`)
7. Copy `fixtures/pack_drop/whatweb/` → `prove/work/in/nmap/pack_drop/whatweb/`
   (stdout-class Covey `export_pack`; `covey.pack_drop.v1`)
8. Copy `fixtures/pack_drop/hping3/` → `prove/work/in/nmap/pack_drop/hping3/`
   (host-only ICMP stdout-class Covey `export_pack`; `covey.pack_drop.v1`;
   no invented open ports)
9. Copy `fixtures/pack_drop/onesixtyone/` → `prove/work/in/nmap/pack_drop/onesixtyone/`
   (SNMP community/sysDescr stdout-class Covey `export_pack`;
   `covey.pack_drop.v1`; no invented open TCP ports)
10. Copy `fixtures/pack_drop/fping/` → `prove/work/in/nmap/pack_drop/fping/`
   (host-only ICMP/reachability stdout-class Covey `export_pack`;
   `covey.pack_drop.v1`; no invented open ports)
11. Copy `fixtures/pack_drop/naabu/` → `prove/work/in/nmap/pack_drop/naabu/`
   (port/service stdout-class Covey `export_pack`; `covey.pack_drop.v1`;
   open TCP ports + `open_port_observed` only)
12. Copy `fixtures/pack_drop/nping/` → `prove/work/in/nmap/pack_drop/nping/`
   (port/service stdout-class Covey `export_pack`; `covey.pack_drop.v1`;
   ICMP echo + TCP handshake completed; open TCP ports + `open_port_observed` only)
13. Copy `fixtures/pack_drop/nbtscan/` → `prove/work/in/nmap/pack_drop/nbtscan/`
   (host-only NetBIOS name-table stdout-class Covey `export_pack`;
   `covey.pack_drop.v1`; no invented open TCP ports)
14. Copy `fixtures/pack_drop/braa/` → `prove/work/in/nmap/pack_drop/braa/`
   (host-only SNMP GET sweeper stdout-class Covey `export_pack`;
   `covey.pack_drop.v1`; community/OID/sysDescr; no invented open TCP ports)
15. Copy `fixtures/pack_drop/ike-scan/` → `prove/work/in/nmap/pack_drop/ike-scan/`
   (host-only IKE Main Mode / Aggressive Mode sweeper stdout-class Covey
   `export_pack`; `covey.pack_drop.v1`; handshake / VPN responder;
   IKE/VPN discover ≠ open TCP port; no invented open TCP ports)
16. Copy `fixtures/pack_drop/svmap/` → `prove/work/in/nmap/pack_drop/svmap/`
   (SIP Device/UA stdout-class Covey `export_pack`; `covey.pack_drop.v1`;
   real User-Agent only; UDP SIP from the svmap table only, default 5060;
   unique observation ids; no invented TCP)
17. Copy `fixtures/demo/honeypot/` → `prove/work/in/honeypot/` (Palisade stages)
18. Copy `fixtures/demo/honeypot_beelzebub/` → `prove/work/in/honeypot/pack_drop/`
   (Beelzebub login/cmd/session; `stage` null)
19. Stamp `SAMPLE.txt` (`SAMPLE/DEMO — not a client estate`)
20. Run the existing SoR path: `run_ciso_path` (same as `python3 -m dropbox ciso`)
21. Write `prove/work/out/ciso-assistant/*.csv` and `prove/work/prove-ciso.json`

Operator-shaped equivalent after the seed (same SoR, still dry):

```bash
python3 -m dropbox ciso \
  --scope dropbox/SCOPE.yaml \
  --in-dir prove/work/in \
  --out-dir prove/work/out
# Desktop: clica  or  bash push_ciso.sh   (posted:false unless CISO_PUSH=1)
python3 -m dropbox mcp export_ciso_poam
```

Pytest lock: `python3 -m pytest tests/test_prove_ciso.py -q`

## Lab / live dest_in (no fixture reseed)

`farm_drop_to_sor` = SAMPLE/DEMO **fixture seed** (`fixtures/pack_drop` →
wipe `DIR/in`). `lab_drop_to_sor` = operator **dest_in, no reseed**
(`prove_ciso --use-existing-in`). Both emit a risk register + POA&M.
LAB != SAMPLE != client. SAMPLE farm nmap `172.16.10.0/24` is a SAMPLE
estate segment, not LAB dest_in `192.168.64.0/24` (`fixtures/lab-drop`).
Ship-gate for the farm seed: [FARM_SHIP_GATE.md](FARM_SHIP_GATE.md).

Default `prove_ciso` still copies `fixtures/pack_drop` (16 adapters) into
`DIR/in` and **wipes** whatever was there (DEMO wipe). DESKTOP compose lab
pack_drop is discarded by that seed. Do **not** run default `prove_ciso` on
a live dest_in.

DESKTOP operators: after compose lab `nmap → pack_drop` lands in `DIR/in`,
keep that dest_in with `lab_drop_to_sor` / `--use-existing-in`:

```bash
# DESKTOP after compose lab pack_drop is already in DIR/in:
./scripts/lab_drop_to_sor.sh --work DIR
# DESKTOP: .\scripts\lab_drop_to_sor.ps1 -Work DIR
python3 scripts/prove_ciso.py --work DIR --use-existing-in
# alias: --no-seed
# MCP conductor (pack dropbox.mcp_stub): tools/call lab_drop
#   arguments.work = DIR  (or arguments.dest_in = DIR/in)
#   without work: arguments.lab_out = lab-estate/out  (reads LAST_LAB_PROVE; auto-hint, no re-prove)
# Console twin of that out/ (no DEMO reseed):
#   OUT_DIR=DIR/out python -m product
#   Windows: set OUT_DIR=DIR\out
#            python -m product
#   or LAB_ESTATE_OUT=lab-estate/out python -m product   (OUT_DIR unset; prefers LAST_LAB_PROVE)
```

Twins (same LAB dest_in rails; no DEMO reseed):

| Path | Command |
|---|---|
| MCP `lab_drop` | `tools/call lab_drop` `arguments.work=DIR` (or `arguments.lab_out` / `LAST_LAB_PROVE` auto-hint, no re-prove) |
| Operator `lab_drop_to_sor` | `./scripts/lab_drop_to_sor.sh --work DIR` / `.\scripts\lab_drop_to_sor.ps1` |
| Console | `OUT_DIR=DIR/out python -m product` (Windows `set OUT_DIR=DIR\out` / `python -m product`) |

MCP `lab_drop` ≡ `lab_drop_to_sor` ≡ console pointed at that `out/`
(no DEMO reseed). DESKTOP one-shot scan→SoR→console
(`scan-to-console.ps1`) is the same SoR rails after pack_drop lands in
`DIR/in`. Bind `127.0.0.1`. Never POSTs `/api/risks`. Does not invent
`client=true`.

`--use-existing-in` does **not** rmtree/reseed `DIR/in`. `DIR/in` must
already hold pack_drop (compose lab or operator copy). Empty `DIR/in`
(or banners only) fail-closed (`EXISTING_IN_FAIL`). If `LAB.txt` (or
nmap pack_drop `lab:true`) is present, dest_in fail-closed
(`LAB_SHAPE_FAIL`) when `seeded=true` or unexpected DEMO adapter trees
appear (honeypot / fixtures pack_drop siblings beyond the operator nmap
leaf — a silent reseed). Collectors + `grc_loader` run; risk-register +
POA&M shape (`shared/ciso_shape`, #102) is fail-closed: findings>0
implies `risk_scenarios` rows and `poam` rows.

CI/lab fixture: `fixtures/lab-drop/` is a scan-shaped LAB dest_in
(192.168.64.0/24 nmap pack_drop leaf). LAB != SAMPLE keep != client.
Pytest copies it into a temp `work/in` and locks this path. It is not
SAMPLE `fixtures/pack_drop` and not a client KEEP.

Point the loopback console at a lab prove `out/` (no DEMO reseed):
`OUT_DIR=/path/to/DIR/out python -m product` (example fixture:
`OUT_DIR=fixtures/lab-drop-out python -m product`). The console reads
honesty from `summary.json` / `LAB.txt` / parent `prove-ciso.json`
(`lab` / `sample` / `demo` / `client=false` / `seeded`). Refresh is a
disk reload only — it does not run DEMO collectors. Bind stays
`127.0.0.1`. Never POSTs `/api/risks`.

Sibling prove `out/` dirs: set `PROVE_WORK_ROOT` at the stamps parent
(e.g. `prove-work/` or `lab-estate/out/`; otherwise the parent of
`OUT_DIR` / those common layouts). The console lists recent `*/out`
and `lab-prove-*` stamps that have `summary.json` and/or `LAB.txt`
(`GET /api/runs`). Pick one in the **Active out/** dropdown, or
`POST /api/runs` `{"stamp":"lab-prove-…"}` / `GET /api/runs/select?stamp=…`.
Switching is process-local `OUT_DIR` (no restart). Honesty is
re-derived via `derive_honesty`; `client` stays false. Latest
`lab-prove-*` is preferred when present. LAB refresh stays a disk
reload. The POA&M tab triages `out/poam/poam.csv` (open + severity +
blank-owner/due KPIs; critical/high first; owner/due stay blank for a
human) via `/api/summary` `poam` and `/api/poam/summary`. Coverage
lists applied controls + risk scenarios (`GET /api/controls`,
`GET /api/scenarios`; semicolon `risk_scenarios.csv`) and a
`framework_refs` heatmap (`GET /api/coverage`) grouping NIST CSF /
CISA CPG / CIS / ISO-ish tokens from POA&M and finding labels.
Evidence rows show `out/evidence` path/size when present. Bind stays
`127.0.0.1`. Never POSTs `/api/risks`.

LAB/DEMO != SAMPLE != client. `paying_day` stays FAIL. Never pack `in/`.
`farm_drop_to_sor` remains the fixture seed path. `sample_to_sor` remains
the primary KEEP path. This is not a new CTA. No Makefile / README
first-line entrypoint.

## Brick 4 — cold farm wipe/clone ship-gate (CI/lab)

When pack HEAD of the farm assertion surface changes, CI job
`farm-drop-to-sor-cold` wipes a dest, extracts this SHA
(`git archive HEAD`), runs `farm_drop_to_sor`, and
`assert_risk_register_and_poam`. See `docs/FARM_SHIP_GATE.md`.
`FARM_SHIP=yes` only on that surface change — identical re-PASS is
not a ship event. Scripts under `scripts/ci/` are CI/lab only, not a
new public operator entrypoint. SAMPLE/DEMO != client. paying_day
FAIL. Not client KEEP.

## Honesty limits

| Claim | Truth |
|---|---|
| Estate | **SAMPLE/DEMO ≠ client.** Fixtures only. |
| Paying-day | **FAIL.** This prove does not stamp PASS. HITL + real KEEP `in/` + compose-on-Docker still open. |
| SoR | `out/ciso-assistant/*.csv` (here: `prove/work/out/ciso-assistant/`) |
| Posted | `false` unless an operator sets `CISO_PUSH=1` and `DRY_RUN!=1` |
| RiskReady | Review-only. `RISKREADY_PUSH` ignored. No wrap. No `/api/risks`. |
| Pack `in/` | Read-only. Prove never writes it. |
| Live scan | Never. Parse-only. No Covey/Nmap/honeypot spawn. |
| Catalog | Unchanged. No new collector. Honeypot is not an 11th compose service. |
| KEEP-minimum | Unchanged. Pack_drop/honeypot are already-on-disk sensor dirs, not new schedule slots. |

CoS #48 honesty sync — farm leave-behind `farm_drop_to_sor`
(`./scripts/farm_drop_to_sor.sh` / `make farm-drop-to-sor` /
`.\scripts\farm_drop_to_sor.ps1`). Pack HEAD this PR (`a3a3651b`
after #91 `sample_to_sor`, #93 keep_ciso SoR paths, #92 honesty).
SAMPLE keep remains the primary KEEP path (`./scripts/sample_to_sor.sh`).
DESKTOP cold run measured ~0.697s (agent-VM ~0.231s) — honesty-only
elapsed; not a paying_day PASS.
SAMPLE keep-lab DESKTOP dry-run (`DRY_RUN=1` `CISO_PUSH=0`;
`docs/DESKTOP_DRY_RUN.md`; `docs/EVAL_PACK_HANDOFF.md`).
Eval HEAD `ebaa9f50` (PR #4 one-command DESKTOP SAMPLE loopback
prove already on main; unit CI green on merge). Eval
DESKTOP-222GHQV day-of SAMPLE PASS at `ebaa9f50` (Hermes Node
v22.23.2; default PATH Node v24 breaks better-sqlite3 ABI;
Node 22 required on DESKTOP). Eval day-of ≠ pack paying_day PASS.
SAMPLE keep cannot stamp client-ready.
Item **COS48-FARM-DROP-TO-SOR**. Item **COS47-HONESTY** = DONE. Item
**COS46-HONESTY** = DONE. Item
**COS45-PACK-DROP-SOURCE-LOCK** = DONE.
16 E2E_PROVEN pack_drop void CLOSED. Next brick named =
Reid-only real KEEP `in/` drop (0/4) — SAMPLE ≠ client; no pack_drop vanity.
SAMPLE_BANNER /
prove_ciso sixteen-set includes unicornscan (joined from
`E2E_PROVEN_PACK_DROP_ADAPTERS`). Covey HEAD `c012dd24`
(farm PR #23 unit-only GHA CI already on main; client-day path
already on main).
pack_drop schema seam **CLOSED**.
Integrity **PARKED**.
20-adapter lane **CLOSED** stands. Covey `E2E_PROVEN` sixteen-set
remains: nmap + rustscan + fping + naabu + nping + httpx + sslscan +
tlsx + whatweb + hping3 + onesixtyone + nbtscan + braa + ike-scan +
svmap + unicornscan. UNPROVEN fail-closed: masscan, arp-scan,
netdiscover, zmap — do not claim a 17th live. Pack does not start
Covey adapter work. Stop for CoS #49. Reid-only
blockers remain (CTA; real KEEP `in/`; Eval `npm start`; compose on this
agent/CI VM still ABSENT — ABSENT ≠ DESKTOP-222GHQV compose_lab
pass_desktop at pack 2680a5b2, not a pass on this VM).

Lane map: [COVEY_PACK_DROP.md](COVEY_PACK_DROP.md), [EVIDENCE_MATRIX.md](EVIDENCE_MATRIX.md).
CSV headers: [../schemas/ciso-assistant.md](../schemas/ciso-assistant.md).

## Other sinks (same intermediate, not a second prove)

After `prove/work/out/ciso-assistant/*.csv` exists, file-only exporters
read those CSVs. They do not change CISO headers. `posted=false`.

```bash
python3 -m exporters --sink all --out-dir prove/work/out
```

- OpenGRC Data Manager CSVs → `prove/work/out/opengrc/` — [IMPORT_OPENGRC.md](IMPORT_OPENGRC.md)
- Probo `addRisk` / `addFinding` drafts → `prove/work/out/import_preview/probo.json` — [IMPORT_PROBO.md](IMPORT_PROBO.md)

RiskReady stay-out. SAMPLE/DEMO ≠ client. Paying-day stays FAIL.
