# SYNTHETIC HardeningKitty schema fixture

This directory is a **schema fixture for tests**. It is **not** an observed
HardeningKitty scan result. It was hand-authored on a Linux agent VM that
cannot run HardeningKitty.

- Real HardeningKitty audit CSV columns (`ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding`) plus `ComputerName` so the pack can attach the row to a host.
- Real check IDs and names from upstream
  `scipag/HardeningKitty` `lists/finding_list_msft_security_baseline_windows_11_24h2_machine.csv`.
- `Result` is the measured value (official HK report). `TestResult` is Passed/Failed.
- Actual values are placeholders (`[REDACTED]` or obvious non-secret integers). They are **not** Seen.
- Never describe these rows as Seen, live, or client KEEP.

LAB dest_in only. LAB != SAMPLE != client. paying_day FAIL.
