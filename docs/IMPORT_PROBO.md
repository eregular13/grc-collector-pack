# Probo import

There is **no Probo** on `C:\GRC Collector`. This pack does not start pve2, VM 118, or any Probo container. Do **not** default `192.168.10.130:8080`.

## Dry-run

```powershell
python -m dropbox.import_grc --target probo --dry-run
```

Writes `out/probo/findings_plan.json`: `addFinding` items in batches of **25**. **No createRisk.** No HTTP.

## Live

`--live` requires `PROBO_URL` + `PROBO_TOKEN` **and** `push/GATE_PROBO` (gitignored). Missing gate or env → exit 2, no socket. `PROBO_URL` must never be `192.168.10.130`. This lab still does not POST (no Probo tenant here). Dual-gate is the product; a live tenant is a Reid power-on problem. **No createRisk.**

Never POST RiskReady `/api/risks`. `client_facing_ready: false`.
