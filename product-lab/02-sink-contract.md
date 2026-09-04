# 02 — Sink contract (truth)

**Written:** 2026-09-03 21:40 America/Los_Angeles  
**Repo:** `C:\Users\R\grc-collector-pack`  
**Pass/fail:** PASS (honest no-sink; no `:18080` calls)

## Verdict

**NO SINK ON THIS REPO.**

This checkout has no `mock_sink` service, no `18080` bind in `docker-compose.yml`, and no `tests/mock_grc*` module. Compose publishes **zero** ports. Searching `18080`, `mock_sink`, `push_ciso`, `push_riskready`, `dry_run` finds only comments, safety tests, and the two dry-run push scripts.

`docker ps` at inventory time showed `grc-collector-mock_sink-1` **Up** on `0.0.0.0:18080->8080`. That container’s image is `grc-collector-mock_sink` and its name prefix is `grc-collector-`, not `grc-collector-pack-`. It belongs to **`C:\GRC Collector`**, which was running a lab on this host at the same minute. This product lab **did not** GET/POST `localhost:18080`. Doing so would be guessing another repo’s sink (P1).

## Push scripts (DRY_RUN only)

| Script | Default flags | Allowed live POSTs if flags flipped | Forbidden |
|---|---|---|---|
| `push_ciso.sh` | `CISO_PUSH=0` → exit 0, print dry + clica path | `/api/assets/`, `/api/evidences/` when `CISO_PUSH=1` **and** `DRY_RUN!=1` | `/api/risks`; FindingsAssessment UUIDs |
| `push_riskready.sh` | always review-only | **none** — LICENSE-LOCK stay-out even if `RISKREADY_PUSH=1` | login, `/itsm/assets`, `/evidence`, `/incidents`, `/api/risks` |

Default compose env: `DRY_RUN=1` `CISO_PUSH=0` `RISKREADY_PUSH=0`.

Live dry-run of both scripts is recorded in `04-negative.md` (push without flags / DRY_RUN=1). No HTTP client is invoked on those paths.

## Ship meaning

This pack is a **file emitter**. A buyer still needs a GRC sink (CISO Assistant or RiskReady) or a mock from another tree to prove HTTP contracts. That gap is documented, not papered over. `risks_proposed.json` remains on disk only.
