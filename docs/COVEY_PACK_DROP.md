# Covey pack_drop → `in/nmap/`

[evergreen-covey](https://github.com/eregular13/evergreen-covey) is BYO orchestration.
A sibling export lands a **pack_drop** (not a scanner binary) that this pack accepts
on the existing **inventory-nmap** lane. CISO Assistant remains the system of record.
RiskReady stays review-only — never wrap or POST.

Covey HEAD `30d2197f` `export_pack` writes the same layout for all 16
`E2E_PROVEN` adapters. This pack lifts **nmap** (XML/gnmap-class) and
stdout/XML-class fixtures (**rustscan**, **httpx**, **unicornscan**,
**sslscan**, **tlsx**, **whatweb**, **hping3**, **onesixtyone**,
**fping**, **naabu**, **nping**, **nbtscan**, **braa**, **ike-scan**,
**svmap**). After svmap the 16 `E2E_PROVEN` pack_drop void closes —
no 17th live adapter, no pack Covey adapter work. Pytest locks
`fixtures/pack_drop/` to exactly those sixteen dirs (each with
non-empty `meta.json` / `assets.jsonl` / `findings.jsonl`) and
`seed_prove_in` 1:1 via `E2E_PROVEN_PACK_DROP_ADAPTERS`. Pytest also
locks per-adapter claim-class + DEMO labels
(`tests/test_pack_drop_claim_class.py`), global observation id
uniqueness (`tests/test_pack_drop_observation_ids.py`; namespaced
`<adapter>-…` DEMO ids; unique within each file and across all sixteen),
and global asset/host/service identity
(`tests/test_pack_drop_asset_ids.py`; namespaced `<adapter>-…` DEMO ids
on every `assets.jsonl` `asset` / `host` / `service` row; unique within
each file and across all sixteen; disjoint from finding/observation ids).
hping3 and fping are
**host-only** (ICMP / reachability discover); onesixtyone is **SNMP
community/sysDescr** discover; braa is an **SNMP GET sweeper** (OID /
sysDescr / sysName); nbtscan is **NetBIOS name-table** host discover
(real NetBIOS names only, not `<unknown>` / MAC-only); ike-scan is an
**IKE Main Mode / Aggressive Mode sweeper** (hosts that printed a
handshake with a nonzero responder cookie; IKE/VPN discover ≠ open TCP
port); svmap is a **SIP Device / User-Agent** discover (real UA only —
reject `unknown` / empty / `user agent` / `disabled`; UDP SIP ports from
the svmap table only, default 5060; no invented TCP). naabu and nping
are **port/service discovery** (open TCP ports + `open_port_observed`
only; nping from ICMP echo replies + TCP handshake completed, not
RST/refused). Host-only fixtures invent no open TCP ports.

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
| `assets.jsonl` | Host-shaped `{ip,hostname,ports}` rows reuse `_emit_host` (same SMB/RDP/Telnet POA&M). Canonical `{kind:asset,…}` rows lift through `make_record`. Covey `export_pack` `{kind:host,address}` / `{kind:service,address,port}` (`evergreen.pack_drop.v1`) lift as assets + open-port findings. Every `asset` / `host` / `service` row carries a stable namespaced `id` (`nmap-50-asset`, `fping-10-host`, `rustscan-7-svc-80`, `svmap-96-sip-svc`, …) unique within the adapter file and globally across the sixteen-set, and disjoint from finding/observation ids. Host-only adapters (hping3/fping ICMP; onesixtyone SNMP community/sysDescr; braa SNMP GET OID/sysDescr/sysName; nbtscan NetBIOS name-table; ike-scan IKE/VPN handshake) emit `{kind:host,address}` with no service/port rows — `_emit_host` writes the asset and invents nothing. svmap emits hosts plus **UDP/5060 sip** service rows from the SIP Device/UA table (protocol=`udp`; not invented TCP). |
| `findings.jsonl` | `{kind:finding,…}` rows lift through `make_record` into the same CISO findings CSV. Covey `{kind:observation,claim:open_port_observed}` rows lift the same way (info observation, not a vulnerability claim). Host-only rows use `claim:host_up_observed` (ICMP/reachability), `claim:snmp_community_observed` / `claim:sysdescr_observed` (onesixtyone), `claim:snmp_community_observed` / `claim:sysdescr_observed` / `claim:oid_observed` (braa), `claim:netbios_name_observed` (nbtscan), or `claim:ike_handshake_observed` / `claim:ike_responder_observed` (ike-scan) with no `port`. Every claim / finding / observation row carries a stable namespaced `id` (`fping-10-host-up`, `nmap-50-smb-445`, `svmap-96-sip-ua`, …) unique within the adapter file and globally across the sixteen-set so sibling ids cannot collapse CISO rows. svmap rows use `claim:sip_user_agent_observed` / `claim:sip_udp_port_observed` (UDP/5060 sip from the table; not invented TCP). |
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
stdout-class `fixtures/pack_drop/fping/`, port/service
stdout-class `fixtures/pack_drop/naabu/`, port/service
stdout-class `fixtures/pack_drop/nping/`, host-only NetBIOS
name-table stdout-class `fixtures/pack_drop/nbtscan/`,
SNMP GET sweeper (OID/sysDescr/sysName) stdout-class
`fixtures/pack_drop/braa/`, host-only IKE/VPN handshake
stdout-class `fixtures/pack_drop/ike-scan/`, and SIP Device/UA
stdout-class `fixtures/pack_drop/svmap/`
(Covey `export_pack` shape).
**SAMPLE/DEMO ≠ client.** End-to-end CISO
prove: [PROVE_CISO.md](PROVE_CISO.md)
(`python3 scripts/prove_ciso.py` → `prove/work/out/ciso-assistant`). Not a
paying-day PASS. Not a client KEEP.

Lane map: [EVIDENCE_MATRIX.md](EVIDENCE_MATRIX.md).
