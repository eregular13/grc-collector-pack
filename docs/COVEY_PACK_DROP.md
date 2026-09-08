# Covey pack_drop → `in/nmap/`

[evergreen-covey](https://github.com/eregular13/evergreen-covey) is BYO orchestration.
A sibling export lands a **pack_drop** (not a scanner binary) that this pack accepts
on the existing **inventory-nmap** lane. CISO Assistant remains the system of record.
RiskReady stays review-only — never wrap or POST.

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
| `assets.jsonl` | Host-shaped `{ip,hostname,ports}` rows reuse `_emit_host` (same SMB/RDP/Telnet POA&M). Canonical `{kind:asset,…}` rows lift through `make_record`. |
| `findings.jsonl` | `{kind:finding,…}` rows lift through `make_record` into the same CISO findings CSV. |
| `meta.json` | One evidence attestation (`covey.pack_drop.v1`). Empty invents nothing. |
| `evidence/` | Artifact rows (or `kind:evidence` JSON). Not parsed as Nmap XML. |

Detection is filename + `schema` / `source: evergreen-covey`. Ordinary gnmap / XML /
masscan / naabu drops are unchanged. Empty / header-only invent nothing.

## Rails

- Parse-only. This pack does not run Nmap, OpenVAS, Nuclei, or Covey workers.
- OpenVAS-class remains file_drop only — never vendor a scanner.
- `python collectors/inventory_nmap.py` is the same collector the nine-service lab
  already runs. No eleventh compose service. No farm slot inflation.

Fixture used by tests (not loaded on empty `in/nmap/`): `fixtures/pack_drop/nmap/`.
**SAMPLE/DEMO ≠ client.** End-to-end CISO prove: [PROVE_CISO.md](PROVE_CISO.md)
(`python3 scripts/prove_ciso.py` → `prove/work/out/ciso-assistant`). Not a
paying-day PASS.

Lane map: [EVIDENCE_MATRIX.md](EVIDENCE_MATRIX.md).
