# Client assessment runbook (software)

pack_mapped: 10
client_facing_ready: false

This is the **operator checklist** for a future signed client drop box. It is not a scan. Do **not** run it against `192.168.10.0/24`, pve, Hermes, Probo, or this lab host LAN. Docker-sim is not a paying client. `client_facing_ready` stays false until a real signed SCOPE + HITL. Lab-sim isolated docker-estate `pack_mapped: 10` (PRODUCT.md / CLIENT_READY.md) is this estate, not a paying-day count.

## Before live

1. Written authorization. `client_legal_name`, `named_contact`, `consent_attested: true` (lowercase `true` only).
2. Window `window_start` / `window_end` still open.
3. Targets are **that client’s** named CIDRs/hosts/URLs only. Never add this office LAN (`192.168.10.0/24`). Never `0.0.0.0/0`. Parsed CIDRs overlapping the office LAN refuse live (`forbidden_cidr`, plan-only).
4. `allow_tools` explicit (curl, and BYO nmap only if Reid installed it on PATH). Pack image does not apt nmap/nessus/nuclei.
5. `integrity.allow_live_exec: true` (lowercase) **and** `$env:EVERGREEN_ORCH_LIVE = "1"` (the string `1`, not `true`). Dual gate. Unset the env after the run.
6. `python -m dropbox.product_demo --help` then `--dry-run` (plan-only, no sink POST).
7. PATH binaries exist. Missing binary = plan-only, not a download.

## During

8. Orchestrator: `plan` → discover → destroy workers → deepen (batch **2–5**) → destroy workers → ingest → grc_export.
9. Leftover `.alive` workers are destroyed even if discover is skipped.
10. Two engagement slugs (e.g. `docker-estate-product` vs `24h-cold`) must not steal each other’s POA&M. Estate kits copy `artifact_src` only — not pack Litware `out/ciso-assistant`.
11. CISO auto-push (if ever gated on) is **assets.csv + evidences.csv** only. Findings/POA&M stay HITL. Never POST `/api/risks`. RiskReady WRAP_DEAD. After ingest, `python -m dropbox.import_grc --target all --dry-run` writes OpenGRC CSVs + a Probo `addFinding` plan (no createRisk). `--live` needs env URL/token **and** a gitignored `push/GATE_*` file; missing gate → exit 2, no socket. OpenGRC live POST is skipped until the create-body schema is confirmed. Do not invent FindingsAssessment UUIDs.
12. SimpleRisk leave-behind is `out/simplerisk/risks_import.csv` (or estate `out-estate/simplerisk/` and `engagements/<slug>/out/simplerisk/`) — CSV only, no API. Estate slug rows are the mapped web/TLS classes from this run; pack `out/simplerisk` after `run_lab.ps1` is fixture SMBv1 and is not the estate leave-behind.

## After

13. HITL JSON: attested, matching `client`, evidence_label is **not** `lab-sim` for a paying day. Lab-sim cannot flip `client_facing_ready`.
14. Zip: `python -m dropbox.package_engagement --slug <slug>`. No `.env`. Mapped web/TLS names from **this** estate, not SMBv1 invented from HTTP.
15. Unset `EVERGREEN_ORCH_LIVE`. Quote hours stay blank until Reid fills them.

If any brake fires, stop. Integrity over coverage ego.
