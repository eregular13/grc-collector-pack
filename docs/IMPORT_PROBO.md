# Probo — not on this Windows lab

There is **no Probo** on `C:\GRC Collector`. This sprint does not start pve2, VM 118, or any Probo container.

If a later drop exists, the handoff bundle is still this pack’s CISO CSVs + POA&M:

- `out\ciso-assistant\` (see `docs\IMPORT_CISO.md`)
- `out\poam\poam.csv`
- `engagements\<slug>\` after `new_engagement` (fixture Litware is **not** a customer)

Do **not** live-create risks from this tree. Dual-gate: pack parse/orchestrator stays here; a live Probo tenant is a Reid power-on problem on **`192.168.10.130:8080`**, not something this pack boots.

`client_facing_ready: false`. No tree merge with `C:\Users\R\grc-collector-pack`.
