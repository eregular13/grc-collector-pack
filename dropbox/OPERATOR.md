# Drop-box operator — consent → VM → SCOPE → ingest → CISO

**Written:** 2026-09-04  
**Delivery:** with **written client consent**, Reid drops a box/VM into their environment, runs a one-two combo (internal + external), then dumps files into this pack for CISO Assistant.

This directory is the **gated runner**. The public pack stays parse-only. Do not turn the collectors into a scanner suite.

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
   - `allow_tools` (only `lynis`, `ss`, `ip`, `curl`, plus optional BYO names already on PATH)

No `SCOPE.yaml` → runners do not start. Missing or hash-mismatched attestation → exit 2.

```bash
python3 -m dropbox gate
```

## Drop the VM

Place this repo on the box. Do **not** apt-install Nmap, Nuclei, OpenVAS/GVM, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, or any RiskReady wrap. Those are LICENSE-LOCK. The collector image does not ship them.

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

- No Nmap of CIDRs. CIDRs in SCOPE are the named engagement range, not a scan target list.
- No Wazuh/osquery/BloodHound/PingCastle execution.

## Run external (named SCOPE targets only)

```bash
python3 -m dropbox run --profile external
python3 -m dropbox run --profile external --live   # curl -I named targets only
```

`--live` sends `curl -I` to **each named** external host/IP in SCOPE. It will not fetch a host that is not in SCOPE. Demo (default) writes fixture httpx JSONL for those names and does **not** touch the network.

Output: `in/easm/dropbox-tls.jsonl` (existing easm collector).

## Ingest → CISO

```bash
bash scripts/lab.sh
# or: make lab
python3 -m product          # http://127.0.0.1:18765/
```

Collectors parse `in/<sensor>/`. Empty sensors still fall back to `fixtures/demo/` and label `demo`. Zip `out/` (or the console drop zip) for CISO Assistant. Prefer **clica / UI** CSV import. Do not invent FindingsAssessment UUIDs.

RiskReady JSON is LICENSE-LOCK stay-out — review on disk. `push_riskready.sh` never logs in or POSTs.

SimpleRisk: see `dropbox/SIMPLERISK.md` (leave-behind docs only). No SimpleRisk push.

## Honest: BYO vs shipped

| Shipped in this repo | Not shipped |
|---|---|
| SCOPE gate, demo runners, parse-only collectors, localhost console | Nmap, Nuclei, OpenVAS, Nessus, Zeek, Wazuh agent, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, RiskReady wrap |
| Optional: `ss`/`ip`/`curl`/`lynis` **if already on the box** | Any download of those tools |

`make dropbox-lab` is **fixtures + demo overlays**, not a client estate. The committed `dropbox/SCOPE.yaml` is the DEMO consent fixture.

## Do not

- Live-scan CIDRs or the open internet
- POST `/api/risks`
- Restore RiskReady wrap
- Stamp paying-day PASS
- Copy USB evergreen-assessment
