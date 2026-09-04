# Test matrix

**Written:** 2026-09-03 21:45 America/Los_Angeles  
**Repo:** `C:\Users\R\grc-collector-pack`

| Case | Command | Exit | Duration | Pass/fail | Artifact |
|---|---|---|---|---|---|
| INV-docker-version | `docker version` | 0 | 165 ms | PASS | `raw/docker-version.txt` |
| INV-compose-version | `docker compose version` | 0 | 208 ms | PASS | `raw/compose-version.txt` |
| INV-docker-ps | `docker ps -a` | 0 | 264 ms | PASS | `raw/docker-ps.txt` |
| INV-compose-ps | `docker compose ps` | 0 | 225 ms | PASS | `raw/compose-ps.txt` (empty run list; last batch exited) |
| INV-inspect-10 | `docker inspect` ten `grc-collector-pack-*` | 0 | ~2 s | PASS | `raw/compose-inspect.json` |
| HOST-1 | `powershell -ExecutionPolicy Bypass -File .\scripts\lab.ps1` | 0 | 3.036 s | PASS | `TEST_RUNS/20260903-213934-host1/` |
| HOST-2 | same | 0 | 3.042 s | PASS | `TEST_RUNS/20260903-213949-host2/` (62=62 unique `ref_id`) |
| COMPOSE-1 | `docker compose up --build --exit-code-from grc-loader` | 0 | 8.063 s | PASS | `TEST_RUNS/20260903-214007-compose1/` |
| COMPOSE-2 | same | 0 | 7.078 s | PASS | `TEST_RUNS/20260903-214026-compose2/` |
| SINK | search + no HTTP to `:18080` | n/a | n/a | PASS | `02-sink-contract.md` — **NO SINK ON THIS REPO** |
| N1 empty `in/` | listing + compose 1/2 | 0 | see compose | PASS | `…/negative/n1-in-listing.txt` |
| N2 two loaders | two `python collectors/grc_loader.py` | 0 / 0 | 429 ms | PASS | `n2-loader1.out` `n2-loader2.out` |
| N3 live-scan flag | `python product-lab/tmp/n3_socket_probe.py` | 0 | 1.016 s | PASS | `n3-stdout.log` `SOCKET_HITS 0` |
| N4 push dry | Git bash `push_ciso.sh` `push_riskready.sh` | 0 / 0 | 2.042 s | PASS | `n4-ciso.out` `n4-rr.out` |
| N5 truncated cloud | hostile `in/cloud` + compose | 0 | 8.086 s | PASS | `n5-summary.json` then file deleted |
| N6a missing `OUT_DIR` path | `n6a_missing.py` | 0 | 1.014 s | GAP (mkdir empty) | `n6a-rerun.out` |
| N6b unset `OUT_DIR` | `n6b_unset.py` | 0 | 1.023 s | PASS | `n6b-rerun.out` → repo `out/` |
| N6c read-only `OUT_DIR` | `n6c_readonly.py` | 1 | 1.019 s | PASS (explicit fail) | `n6c-rerun.err` PermissionError |

pytest on HOST-1/HOST-2: **39 passed**, 0 failed. `lab_outputs.py` PASS. No `/api/risks` in logs.
