# FAULTS

none open P0/P1

P2 PL-OUTDIR-MKDIR (cycle 8 product lab): `OUT_DIR` set to a nonexistent path mkdir's empty outputs (0 assets) instead of failing closed. Read-only dir fails. Unset env uses `./out`. Not fixed this window.

P2 compose-not-run-on-host closed in cycle 2: `docker compose up --build` produced loader summary assets=50 findings=44.
