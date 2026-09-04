# PASSFAIL — negative + race

written: 2026-09-03 21:41:47 PT
cwd: C:\Users\R\grc-collector-pack
cases:
- N1-empty-in: PASS exit=0 00:00:00.0191224
- N2-two-loaders: FAIL exit=0 00:00:00.4292820
- N3-live-scan-no-sockets: PASS exit=0 00:00:01.0163852
- N4-push-no-flags: PASS exit=0 00:00:02.0418950
- N5-truncated-cloud: PASS exit=0 00:00:08.0860865
- N6a-missing-OUT_DIR: PASS exit=1 00:00:01.0235486
- N6b-unset-OUT_DIR: PASS exit=1 00:00:01.0116292
- N6c-readonly-out: PASS exit=1 00:00:01.0215633
verdict: MIXED — see notes; N6a documents mkdir-not-fail
