# Covey pack_drop → `in/nmap/`

[evergreen-covey](https://github.com/eregular13/evergreen-covey) is BYO orchestration.
A sibling export lands a **pack_drop** (not a scanner binary) that this pack accepts
on the existing **inventory-nmap** lane. CISO Assistant remains the system of record.
RiskReady stays review-only — never wrap or POST.

Covey HEAD `30d2197f` `export_pack` writes the same layout for all 16
`E2E_PROVEN` adapters. This pack lifts **nmap** (XML/gnmap-class) and
stdout/XML-class fixtures (**rustscan**, **httpx**, **unicornscan**,
**sslscan**, **tlsx**, **whatweb**, **hping3**, **onesixtyone**,
**fping**, **naabu**). Other
stdout-class adapters (nping, nbtscan, …) use the same files when dropped here —
no 17th live adapter, no pack Covey adapter work. hping3 and fping are
**host-only** (ICMP / reachability discover); onesixtyone is **SNMP
community/sysDescr** discover. naabu is **port/service discovery**
(open TCP ports + `open_port_observed` only). Host-only fixtures invent
no open TCP ports.

## Drop shape

Copy the export onto the nmap lane (flat or nested). `list_files` already rglob's
`in/nmap/`.

```
in/nmap/assets.jsonl
in/nmap/findings.jsonl
in/nmap/meta.json
in/nmap/evidence/<artifact>
```

or

```
in/nmap/pack_drop/assets.jsonl
in/nmap/pack_drop/findings.jsonl
in/nmap/pack_drop/meta.json
in/nmap/pack_drop/evidence/<artifact>
```

| File | Accepted as |
|---|---|
| `assets.jsonl` | Host-shaped `{ip,hostname,ports}` rows reuse `_emit_host` (same SMB/RDP/Telnet POA&M). Canonical `{kind:asset,…}` rows lift through `make_record`. Covey `export_pack` `{kind:host,address}` / `{kind:service,address,port}` (`evergreen.pack_drop.v1`) lift as assets + open-port findings. Host-only adapters (hping3/fping ICMP; onesixtyone SNMP community/sysDescr) emit `{kind:host,address}` with no service/port rows — `_emit_host` writes the asset and invents nothing. |
| `findings.jsonl` | `{kind:finding,…}` rows lift through `make_record` into the same CISO findings CSV. Covey `{kind:observation,claim:open_port_observed}` rows lift the same way (info observation, not a vulnerability claim). Host-only rows use `claim:host_up_observed` (ICMP/reachability) or `claim:snmp_community_observed` / `claim:sysdescr_observed` (onesixtyone) with no `port`. |
| `meta.json` | One evidence attestation (`covey.pack_drop.v1` or `evergreen.pack_drop.v1`). Empty invents nothing. |
| `evidence/` | Artifact rows (or `kind:evidence` JSON). Not parsed as Nmap XML. |

Detection is filename + `schema` / `source: evergreen-covey`. Ordinary gnmap / XML /
masscan / naabu drops are unchanged. Empty / header-only invent nothing.

## Rails

- Parse-only. This pack does not run Nmap, OpenVAS, Nuclei, or Covey workers.
- OpenVAS-class remains file_drop only — never vendor a scanner.
- `python collectors/inventory_nmap.py` is the same collector the nine-service lab
  already runs. No eleventh compose service. No farm slot inflation.

Fixtures used by tests (not loaded on empty `in/nmap/`):
`fixtures/pack_drop/nmap/` and stdout-class `fixtures/pack_drop/rustscan/`
plus `fixtures/pack_drop/httpx/`, `fixtures/pack_drop/unicornscan/`,
stdout/XML-class `fixtures/pack_drop/sslscan/`, stdout-class
`fixtures/pack_drop/tlsx/`, stdout-class
`fixtures/pack_drop/whatweb/`, host-only stdout-class
`fixtures/pack_drop/hping3/`, SNMP community/sysDescr stdout-class
`fixtures/pack_drop/onesixtyone/`, host-only ICMP/reachability
stdout-class `fixtures/pack_drop/fping/`, and port/service
stdout-class `fixtures/pack_drop/naabu/`
(Covey `export_pack` shape).
**SAMPLE/DEMO ≠ client.** End-to-end CISO
prove: [PROVE_CISO.md](PROVE_CISO.md)
(`python3 scripts/prove_ciso.py` → `prove/work/out/ciso-assistant`). Not a
paying-day PASS. Not a client KEEP.

Lane map: [EVIDENCE_MATRIX.md](EVIDENCE_MATRIX.md).
