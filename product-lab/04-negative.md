# 04 — Negative and race

**Written:** 2026-09-03 21:45 America/Los_Angeles  
**Stamp:** `product-lab/TEST_RUNS/20260903-214132-negative`  
**Pass/fail:** PASS (N6 missing-path is documented behavior, not a compose red)

## N1 — empty `in/` (already demo)

**Command:** `Get-ChildItem -Force -Recurse in` plus compose runs 1 and 2  
**Exit:** 0  
**Duration:** listing 19 ms; compose as in `03-compose-lab.md`  
**Pass:** PASS  
**Artifact:** `…/negative/n1-in-listing.txt`

Nine sensor folders, each `.gitkeep` only. Compose still 62 / 59 / 10 with `demo: true`.

**Ship meaning:** A buyer who clones and runs compose gets the fixture story, not their estate. That is correct and must be labeled demo.

## N2 — two loaders at once

**Command:** `python collectors/grc_loader.py` started twice, waited together  
**Exit:** both wrote a complete summary (Start-Process `ExitCode` was empty after `Wait-Process`; both `*.out` files are valid JSON)  
**Duration:** 429 ms  
**Pass:** PASS  
**Artifact:** `n2-loader1.out`, `n2-loader2.out`, `n2-notes.txt`

CSV after: 62 asset rows, 62 unique `ref_id`, header exact. Findings 59 unique. No torn half-write. Loader **overwrites**.

**Ship meaning:** Parallel loaders do not append duplicates. They can interleave writes; last writer wins a full file.

## N3 — `GRC_LIVE_SCAN=1` does not open sockets

**Command:** `python product-lab/tmp/n3_socket_probe.py` (patches `socket.socket` to raise; imports and `main()`s all ten modules with `GRC_LIVE_SCAN=1`)  
**Exit:** 0  
**Duration:** 1.016 s  
**Pass:** PASS  
**Artifact:** `n3-stdout.log` — `SOCKET_HITS 0` then `OK`

Collectors never read `GRC_LIVE_SCAN`. No `socket.socket` / `urllib.request` / `http.client` in `collectors/*.py`.

**Ship meaning:** Flipping the flag cannot turn this pack into a scanner. Live scan is a no-op.

## N4 — push without flags — no HTTP

**Command:** `"C:\Program Files\Git\bin\bash.exe" ./push_ciso.sh` then `./push_riskready.sh`  
**Exit:** 0 / 0  
**Duration:** 2.042 s  
**Pass:** PASS  
**Artifact:** `n4-ciso.out` `CISO_PUSH=0; dry run, not pushing` — `n4-rr.out` `RISKREADY_PUSH=0; dry run, not pushing`

No curl ran. Did not touch `localhost:18080`.

**Ship meaning:** Default checkout cannot POST anywhere, including `/api/risks`.

## N5 — truncated file in `in/cloud`

**Command:** write `in/cloud/bad-truncated.json` = `{"findings":[{"CheckID":` then `docker compose up --build --exit-code-from grc-loader`; delete the bad file  
**Exit:** 0  
**Duration:** 8.086 s  
**Pass:** PASS  
**Artifact:** `n5-compose.out`, `n5-summary.json`

Parse failure on that file → fixture fallback for cloud. Compose stayed 62 / 59 / 15 / 10, `demo: true`. File removed after the run. `in/` is `.gitkeep` only again.

**Ship meaning:** One hostile drop does not crash the ten-service project. The operator still gets a demo-shaped estate if every live file fails.

## N6 — `OUT_DIR` missing vs read-only

### N6a — `OUT_DIR` set to a nonexistent path

**Command:** `python product-lab/tmp/n6a_missing.py` → `OUT_DIR=product-lab/tmp/missing-out`  
**Exit:** 0  
**Duration:** 1.014 s  
**Pass:** documented (not a compose failure)  
**Result:** loader **mkdirs** the tree and writes an **empty** estate (`assets: 0`, evidence row for the loader only). Not fail-closed.

**Product gap (P2):** a typo’d `OUT_DIR` succeeds with zeros instead of exiting non-zero. Not fixed this window (not P0/P1).

### N6b — `OUT_DIR` unset

**Command:** `python product-lab/tmp/n6b_unset.py`  
**Exit:** 0  
**Duration:** 1.023 s  
**Pass:** PASS  
**Result:** resolves to `C:\Users\R\grc-collector-pack\out`, 62 / 59.

### N6c — read-only `OUT_DIR`

**Command:** `python product-lab/tmp/n6c_readonly.py` against ACL-denied directory  
**Exit:** 1  
**Duration:** 1.019 s  
**Pass:** PASS (explicit fail)  
**Error:** `PermissionError: [WinError 5] Access is denied: '...\readonly-out\ciso-assistant'`

**Ship meaning:** Unset env is safe (repo `out/`). A wrong path is silently empty (gap). A locked directory fails closed.
