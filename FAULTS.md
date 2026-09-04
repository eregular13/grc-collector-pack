# FAULTS

none open P0/P1

P2 DROPBOX-DEMO-FLAG closed cycle 14: dropbox-* artifacts (and `dropbox-demo` / DEMO banners) now stamp `demo` labels, so `make dropbox-lab` summary.demo is true. Estate is still fixtures + demo overlays, not a client.

P2 PL-OUTDIR-MKDIR closed on master cycle 10: `OUT_DIR` unset or missing parent now exits non-zero instead of mkdir an empty estate.
