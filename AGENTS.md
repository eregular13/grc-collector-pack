# GRC collector pack

Unattended. State lives on disk: STATUS.md, FAULTS.md, DONE.md.

Every invocation: read STATUS.md, run the next graph node, run the lab, update STATUS.md, exit.

Stop only when DONE.md line 1 is GREEN.

Do not ask the human. Do not wait. Do not upload proposed risks. Do not live-scan.

Demo mode: parse `in/<sensor>/` or `fixtures/demo/`. `CISO_PUSH=0`, `RISKREADY_PUSH=0`, `GRC_LIVE_SCAN=0`, `DRY_RUN=1`.
