# LAB multi-run ledger lifecycle

Four Nessus file-drops for the operator path: ten collectors + `grc_loader`
(same as `make lab`). Each run is `LAB` (never SAMPLE / client KEEP). Carry
`out/poam/poam-ledger.json` and `out/assets/asset-ledger.json` into the next
`in/` the way an operator would.

Timeline (see `tests/test_ledger_lifecycle_e2e.py`):

| Run | Date | What changes |
|---|---|---|
| 1 | 2026-09-01 | STABLE (MAC host), COVER, FLAP present |
| 2 | 2026-09-08 | FLAP gone; NEW appears; STABLE host DHCP 10.0.10.10 → 10.0.10.99 (same MAC) |
| 3 | 2026-09-15 | FLAP still gone (2nd covered miss → `pending_verification`) |
| 4 | 2026-09-22 | Operator closed the pending FLAP in the carried ledger; FLAP returns as `-R1` |

The ledger does not mint `-R1` from pending-then-seen alone (that keeps the
same EGP- ID). `-R1` is close-then-reappear. Run 4 documents that operator
closure so both client-facing statuses appear in one coherent scenario.
