# FROM_GH_READY (24h-from-gh scorecard)

written_at: 2026-09-11T22:18:53-07:00
window: 24h-from-gh (G01–G23; G24 is hard-stop only)
hard_stop: 2026-09-12T21:37:00-07:00
version: 0.5.0-rc.2
github_repo: eregular13/grc-collector-pack
github_branch: ship-0.4.0
github_sha: 12f27b30b81a6b219aa6ff8fbe00ca240d2d8222
eval24h: quarantined (HISTORICAL DO NOT UP)
docker: up
estate: 127.0.0.1:18081 / :18082 / :18443 (grc-estate, 172.28.90.0/24)
sink: 127.0.0.1:18080 received 0; GET+POST /api/risks 403
pack_mapped: 10
poam_rows: 10
pytest: 302 sequential; run_lab LAB_GREEN
client_facing_ready: false
paying_day: NO
posted: []
facing: false
blocked_by: lab_sim_not_client_estate
wrap_dead_exit: 2
console: GET 200 POST 405 on 127.0.0.1:18765
extras_down: yes
grc_24h_running: no
clone: C:\GRC Collector\_fromgh\clone @ 12f27b3 pytest green
ready_zip_sha256: 341c386df06fc2bd13c68f467bc8805ee6da5c904ec245183f9c818c4179fbec
lab_scheduler: Grok24hFromGh armed until 2026-09-12T21:37:00-07:00
improve_scheduler: 15m (look for P0/P1; do not cancel hourly; G24 still hard-stop only)

Software bar only. Docker-sim is not a paying client. HITL remains lab-sim.

## Ticks

| Item | Result |
| --- | --- |
| G01 | Docker Desktop started; pack == origin `4518c5f` then later G02/G03 |
| G02 | `docker-compose.eval-24h.yml` HISTORICAL DO NOT UP |
| G03 | REFINE_READY/STATUS: Grok24hRefine cancelled, window closed 2026-09-08 |
| G04 | `run_lab.ps1` LAB_GREEN; pytest 302; counts 132/155/9 |
| G05 | estate + mock_sink only; no eval-24h |
| G06 | `--help` sink 0→0; demo pack_mapped 10 facing false posted [] |
| G07/G21 | push `ship-0.4.0` if this scorecard commit lands |
| G08 | `_fromgh/clone` pytest + `--help` |
| G09 | zip 10 classes, no `.env`, no SMBv1 |
| G10 | LAN plan-only; WRAP_DEAD exit 2; `/api/risks` 403; received 0 |
| G11 | QUICKSTART/README exist on clone; no eval-24h |
| G12 | `lab.yml` pytest 3.12; no eval-24h |
| G13 | slug POA&M estate rows after run_lab (pack `out/poam` fixture SMBv1) |
| G14 | `docker ps` = estate web/api/tls + mock_sink |
| G15 | PRODUCT.md pack_mapped 10 + github_sha |
| G16 | VERSION 0.5.0-rc.2 unchanged (no product-code mapper change this compressed pass) |
| G17 | restart estate-web; demo recovers pack_mapped 10 |
| G18 | console GET 200 POST 405 |
| G19 | SimpleRisk zip/slug has 10 estate classes |
| G20 | no new mapped class; still 10 |
| G22 | run_lab after scorecard |
| G23 | this file |
| G24 | hard-stop only — not this tick |

## Safety

DRY_RUN=1 CISO_PUSH=0 RISKREADY_PUSH=0 GRC_LIVE_SCAN=0. Never 192.168.10.0/24. Never POST `/api/risks` as product. Never force master. Never `c11`. Never boot eval-24h.
