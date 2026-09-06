# Faults

## F-001

- severity: P2
- status: fixed
- repro: Docker Desktop was off (`dockerDesktopLinuxEngine` pipe missing).
- expected: optional compose lab if daemon is up.
- actual: daemon 29.7.2 in cycle 7–24. `run_lab.ps1` reports `docker daemon up (29.7.2)`.
- notes: compose extra lab is optional; local pytest lab is the gate.

## F-002 through F-005

status: fixed (see cycle 3).

## F-006

- severity: P2
- status: fixed
- repro: Prowler ASFF, Osquery JSON, Subfinder host lists, ScubaGear reports, Semgrep JSON were ignored if dropped in `in/`.
- expected: parse those OSS formats inside the existing ten collectors.
- actual: parsers + demo fixtures in `in/` and `fixtures/demo/`. Pytest covers each format.

## F-007

- severity: P2
- status: fixed
- repro: lab gate did not assert sensor prefixes or that every high/critical finding is in `risks_proposed`.
- expected: both checks in `tests/lab_outputs.py`.
- actual: added; both labs green.

No open P0 or P1. Cycle 71 I-068 lab green; no new tickets.
