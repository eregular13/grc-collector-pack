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

## Clearing a sticky `LEDGER_CHAIN_BROKEN` warning

There is **no explicit reset flag or CLI**. The warning stays on every run
until a **valid** prior ledger is supplied:

1. Put a known-good `poam-ledger.json` (items as a dict, `closed` a list,
   stored `sha256` matching `payload_sha256`) at `in/poam/poam-ledger.json`,
   or leave that same file at `out/poam/poam-ledger.json` as the fallback.
2. Re-run the loader (`grc_loader` / `scripts/lab.sh`). The flag and
   `dropped_poam_ids` clear once that valid prior is read.

Hand-stripping `warnings` / `dropped_poam_ids` on a re-signed file also
clears the flag because `payload_sha256` is unkeyed and does not cover
those fields. That is **not** a supported reset path.

`LEDGER_LOST` is this-run-only once any ledger file is supplied. On
LAB/SAMPLE/DEMO the first-run note (`first run: no prior ledger`) prints
only when there is no prior ledger file and no leftover POA&M history
(`poam.csv` / `poam.md` / members / excluded). A later missing ledger
stays `LEDGER_LOST` without that note.
