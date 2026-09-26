# Security

## Operator console

The console (`python -m product`) is **localhost only**. Supported bind: `127.0.0.1` (also `localhost` and `::1`). Port default `18765`.

If `GRC_PRODUCT_HOST` is `0.0.0.0`, `::`, `*`, or any non-loopback address, the process **exits 2** and does not start.

There is **no authentication** because the service is loopback-only. A LAN or public bind is refused.

Refresh re-runs local collectors on files under `in/` / `fixtures/demo/` only when honesty is DEMO/SAMPLE. LAB / use-existing-in / non-demo live `OUT_DIR` is a disk reload — collectors do not run. That is intended on loopback. It is unsafe on a LAN bind, which is why a non-loopback bind never starts.

`GET /api/runs` lists sibling prove `out/` dirs under `PROVE_WORK_ROOT` (or the parent of `OUT_DIR` / common `prove-work` layouts). `POST /api/runs` and `GET /api/runs/select` switch process-local `OUT_DIR` on loopback only, then re-derive honesty. They never invent `client=true` and never POST `/api/risks`.

The console opens no outbound HTTP. It never POSTs `/api/risks`.

## Push scripts

Dual-gate: `CISO_PUSH` / `RISKREADY_PUSH` default `0`, and `DRY_RUN` default `1`. Optional CISO live POST (both gates flipped) is limited to `/api/assets/` and `/api/evidences/`. **RiskReady wrap is dead:** `push_riskready.sh` never logs in or POSTs — not `/api/risks`, not assets/evidence/incidents — even if `RISKREADY_PUSH=1`. RiskReady JSON is not generated. Open risks are the POA&M (count identity). Farm SOP never points at a RiskReady write.

## Demo data

`fixtures/demo/` is a synthetic estate. It is not a customer environment.

## Report a vulnerability

Use a [GitHub Security Advisory](https://github.com/eregular13/grc-collector-pack/security/advisories/new) on this repository. Do not open a public issue with exploit details.
