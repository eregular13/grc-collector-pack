# Parser samples — real vs synthetic

Provenance matches the research pack `samples/SOURCES.md` (fetched 2026-09-25 PT)
and DefectDojo / ScubaGear / testssl public fixtures used in the §8 audit.
These files are **SAMPLE/DEMO fixtures**, not a client KEEP drop.

**Byte-true** = copied from the public source without invented rows.
**Trimmed real** = subset of a public file; remaining bytes match the source.
**Synthetic** = constructed for a parser edge. Named `synthetic_*` (or documented
here). Do not mix invented rows into a real filename.

PR #134 (not on master at this writing) owns Prowler/Wazuh/XCCDF/SARIF/enum4linux-ng
rows in this file. This table is the §8 collector set (PingCastle, Greenbone,
ScubaGear, testssl, Nikto). Merge by appending, do not overwrite #134's rows.

| File | Kind | Source | Notes |
|---|---|---|---|
| `pingcastle/one.xml` | byte-true | [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) `unittests/scans/pingcastle/one.xml` (Engine 3.2.0.1) | One `A-MinPwdLen` rule. No `ListNoPreAuth`, no extra `HealthCheckGroupData`. |
| `pingcastle/synthetic_group_membership.xml` | synthetic | Pack-constructed | 8 group-membership RiskIds (`P-BackupOperators` … `P-Administrators`) + 0-point rule. 0-member groups must emit no finding. |
| `greenbone/one_vuln.xml` | trimmed real | DefectDojo `unittests/scans/openvas/one_vuln.xml` (GMP 9.0) | One `result` kept (Firefox NVT, CVSS 10.0, **both** CVE-2023-4573 and CVE-2023-4574). Restored report `timestamp` / `scan_start` (`2023-09-28T14:48:02Z`) from the source so detection date is not `not recorded`. Other wrapper metadata dropped. |
| `greenbone/one_vuln.csv` | trimmed real | DefectDojo `unittests/scans/openvas/one_vuln.csv` | Header + the one SSH weak-cipher row. |
| `scuba/ScubaResults_sample.json` | schema-shaped sample | [cisagov/ScubaGear](https://github.com/cisagov/ScubaGear) v1.8.0 `@ 8bbaf75` `docs/misc/tooloutputschema.md` | `MetaData.DomainName` + `DisplayName` / `TenantDisplayName`. **No `TenantName`** (not in the schema). TenantId stays a GUID and is not the label. Two AAD controls (Fail/Shall + Warning/Should) + one Pass. |
| `testssl/synthetic_pretty_sections.json` | synthetic | Pack-constructed 3.x `--jsonfile-pretty` shape | Protocols + serverDefaults + vulnerabilities. **Not** the FINOS `robmoff.at` dump — that filename is reserved for a byte-true copy. |
| `testssl/synthetic_not_offered.json` | synthetic | Pack-constructed | CRITICAL/MEDIUM/LOW `not offered` must stay; OK/INFO `not offered` drop. |
| `testssl/server-defaults.json` | synthetic | Pack-constructed 3.x pretty-JSON, `serverDefaults` only | Certificate expiry HIGH + WARN OCSP row. |
| `nikto/issue_9274.json` | byte-true | DefectDojo `unittests/scans/nikto/issue_9274.json` (Nikto 2.6.1 list-of-hosts JSON) | Untrimmed (already 8 rows). Header noise + BREACH. |
| `nikto/juice-shop-trim.json` | trimmed real | DefectDojo `unittests/scans/nikto/juice-shop.json` | Header rows, **real** 740001 backup/cert hits, BREACH, `/public/`, NextGEN LFI. Backup hits are kept (medium+). |
| `nikto/nikto-output-trim.xml` | trimmed real | DefectDojo `unittests/scans/nikto/nikto-output.xml` (Nikto 2.1.5) | X-Frame, PUT, Tomcat examples, XSS, Manager. |

LAB/SAMPLE/DEMO ≠ client KEEP. Never POST `/api/risks`. RiskReady stay-out.
