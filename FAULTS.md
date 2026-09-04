# FAULTS

none open P0/P1

P2 PL-OUTDIR-MKDIR closed on master cycle 10: `OUT_DIR` unset or missing parent now exits non-zero instead of mkdir an empty estate.

P2 DROPBOX-DEMO-FLAG (cycle 9): `make dropbox-lab` copies fixtures into `dropbox/work/in`, so collectors treat them as live drops and `summary.demo` is false. Estate is still fixtures + demo overlays, not a client. Documented in `dropbox/EXECUTIVE.md`.
