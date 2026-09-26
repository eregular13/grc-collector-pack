# Real-shaped parser samples (trimmed)

Provenance matches the research pack `samples/SOURCES.md` (fetched 2026-09-25 PT).
These files are **SAMPLE/DEMO fixtures**, not a client KEEP drop.

| File | Source | What was trimmed |
|---|---|---|
| `prowler/example_output_aws.ocsf.json` | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) `@ c2b80924618a` `examples/output/example_output_aws.ocsf.json` (v5 OCSF default) | First 3 findings (FAIL / MANUAL / FAIL). Compliance maps reduced; `risk_details` dropped. Keys unchanged (`status`, `status_code`, `resources[].uid`, `metadata.event_code`). |
| `prowler/example_output_aws.csv` | Same repo `examples/output/example_output_aws.csv` (`;`-delimited v4/v5 CSV) | Header + first 3 data rows. |
| `wazuh/alerts.jsonl` | [Evaluation-of-APT-Simulation-Tools-artifacts](https://github.com/xXPrXy-rAiJiNzXx/Evaluation-of-APT-Simulation-Tools-artifacts) `@ 1b01e9caa956` `Wazuh/ossec/logs/alerts/alerts.json` (first 3 lines; Wazuh 4.x JSONL) | Already 3 lines. |
| `wazuh/sca-checks.json` | [wazuh/wazuh](https://github.com/wazuh/wazuh) `v4.9.0` API spec `/sca/{agent_id}/checks/{policy_id}` example (`spec.yaml` ~L14452) | Same `data.affected_items[]` shape. One row kept as spec `not applicable`; one `passed`; one `failed` (result value only — field set is the spec's). |
| `sarif/trivy-critical.sarif` | Trivy SARIF writer [`pkg/report/sarif.go`](https://github.com/aquasecurity/trivy) `@ ae561f8cca36` (`toSarifErrorLevel`: CRITICAL and HIGH both → `error`; score in `rules[].properties.security-severity`). Alpine golden only has MEDIUM 5.3. | One CRITICAL (`9.8`, `level=error`) + one MEDIUM (`5.3`, `level=warning`) using that rule-property shape. Result objects have no `properties.severity`. |
| `xccdf/rule-results.xml` | XCCDF 1.2 `rule-result@severity` + `@idref` as in OpenSCAP ARF (`openscap` `@ 6942b59` `test_xccdf_overrides.arf.xml` L3137). | Minimal Benchmark (no OpenSCAP/SSG markers) so the generic CIS/XCCDF path is exercised. Fail low / medium / high + one pass. |
| `enum4linux/enum4linux-ng.json` | [cddmp/enum4linux-ng](https://github.com/cddmp/enum4linux-ng) `@ 288826fd9ee8` (`target:{host}` L404; `sessions.null` AUTH_NULL L275/L1175; share `access:{mapping,listing}` L2468) | One host, null session, Domain Admins, IPC$ + writable NETLOGON (`listing=ok`). |

LAB/SAMPLE/DEMO ≠ client KEEP. Never POST `/api/risks`. RiskReady stay-out.
