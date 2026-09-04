# Security

## Operator console

The console (`python -m product`) is **localhost only**. Supported bind: `127.0.0.1` (also `localhost` and `::1`). Port default `18765`.

If `GRC_PRODUCT_HOST` is `0.0.0.0`, `::`, `*`, or any non-loopback address, the process **exits 2** and does not start.

There is **no authentication** because the service is loopback-only. A LAN or public bind is refused.

Refresh re-runs local collectors on files under `in/` / `fixtures/demo/`. That is intended on loopback. It is unsafe on a LAN bind, which is why a non-loopback bind never starts.

The console opens no outbound HTTP. It never POSTs `/api/risks`.

## Push scripts

CISO: `CISO_PUSH` default `0` and `DRY_RUN` default `1`. If both gates flip, REST is `/api/assets/` and `/api/evidences/` only. **Never** `POST /api/risks`.

RiskReady: LICENSE-LOCK stay-out. `push_riskready.sh` never POSTs login, assets, evidence, incidents, or `/api/risks`, even when `RISKREADY_PUSH=1` and `DRY_RUN=0`. `out/riskready/` is human-review JSON only. See `NOTICE`.

## Demo data

`fixtures/demo/` is a synthetic estate. It is not a customer environment.

## Report a vulnerability

Use a [GitHub Security Advisory](https://github.com/eregular13/grc-collector-pack/security/advisories/new) on this repository. Do not open a public issue with exploit details.
