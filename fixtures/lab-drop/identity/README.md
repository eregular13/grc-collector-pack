# SYNTHETIC HardeningKitty schema fixture

This directory is a **schema fixture for tests**. It is **not** an observed
HardeningKitty scan result. It was hand-authored on a Linux agent VM that
cannot run HardeningKitty.

- Official Invoke-HardeningKitty Audit Export-Csv header, in order
  (`scipag/HardeningKitty` `HardeningKitty.psm1` @ `da0976073caa`):
  `ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding,DefaultValue,Filter`
- No `ComputerName` / host column — real HK output has none.
- Hostname comes from the file name:
  `hardeningkitty-<HOSTNAME>-<yyyyMMddTHHmmssZ>-SYNTHETIC.csv`
  (pack dest_in; runner writes `hardeningkitty-<HOSTNAME>-<yyyyMMdd-HHmmss>.csv`).
  Upstream default is `hardeningkitty_report_<hostname>_<list>-<yyyyMMdd-HHmmss>.csv`.
  Optional sidecar: `<csv>.host` or env `HARDENINGKITTY_HOST`.
- `Result` is the measured value. `TestResult` is Passed/Failed.
- Two hosts: `lab-win.lab.internal` and `lab-win-b.lab.internal`.
- Real check IDs and names from upstream
  `lists/finding_list_msft_security_baseline_windows_11_24h2_machine.csv`.
- Values are placeholders (not Seen). Never describe these rows as Seen,
  live, or client KEEP.

LAB dest_in only. LAB != SAMPLE != client. paying_day FAIL.
