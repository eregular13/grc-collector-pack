# CLIENT_READY (software bar)

written_at: 2026-09-12T10:45:00-07:00
version: 0.5.0-rc.3
client_facing_ready: false
paying_day: NO
pack_mapped: 10

This is the **software** a first client assessment would run. Docker-sim is not a paying client.

| Bar | Status |
| --- | --- |
| Isolated HTTP + HTTPS self-signed estate | PASS (`:18081` / `:18082` / `:18443`) |
| Mapped web/TLS POA&M `pack_mapped: 10` | PASS (docker-estate live: Cleartext HTTP; Missing HSTS; Missing web security headers; Server banner disclosure; Git metadata exposed; Directory listing enabled; Environment file exposed; Insecure session cookie; Permissive CORS policy; Untrusted TLS certificate). 24h extra farms torn down (R01); expired/mismatch not folded (R09). |
| `python -m dropbox.product_demo` / `--help` | PASS (`--help` no sink HTTP) |
| `docs/CLIENT_ASSESS.md` checklist | PASS (do not scan a client from this lab) |
| LAN CIDR refuse plan-only | PASS (`192.168.10.0/24`, `0.0.0.0/0`, `10.0.0.0/8`) |
| Unsigned refuse | PASS |
| Estate-down no Litware zip | PASS (exit 2) |
| WRAP_DEAD / no POST `/api/risks` | PASS (403) |
| Zip contract no `.env`, facing false | PASS |
| Host pytest sequential | PASS (≥216; 24h added tests) |
| Two-slug POA&M isolation | PASS (`docker-estate-product` vs `24h-cold`) |
| Deepen batch 2–5 | PASS |
| Worker `.alive` destroy on skip | PASS |
| SimpleRisk estate CSV | PASS (not SMBv1-only) |
| Console GET-only 127.0.0.1:18765 | PASS (POST 405) |
| `python -m dropbox.import_grc --dry-run` | PASS (CISO Extra Import plan; OpenGRC CSVs; Probo addFinding plan; RiskReady WRAP_DEAD; `--live` without gate exit 2) |

Gaps (not paying-day): no signed live drop box; HITL is lab-sim; mock sink not CISO Assistant Community; office LAN never in SCOPE; 24h scheduler cancelled at hard stop; OpenGRC live POST skipped (schema unconfirmed).
