# Sample provenance (fixtures/samples)

Trimmed public shapes used to lock parsers against real tool output.
These files are **SAMPLE/DEMO fixtures**, not a client KEEP drop. No live scan.

Provenance matches the research pack `samples/SOURCES.md` (fetched 2026-09-25 PT)
and DefectDojo / ScubaGear / testssl public fixtures used in the §8 / §9 audit.

PR #134 (not on master at this writing) owns Prowler/Wazuh/XCCDF/SARIF/enum4linux-ng
rows in this file. Merge by appending, do not overwrite #134's rows.

LAB/SAMPLE/DEMO ≠ client KEEP. Never POST `/api/risks`. RiskReady stay-out.

## Cloud

- `cloud/s3-encryption-missing/resources.json`: Cloud Custodian (c7n) `resources.json` is a bare list of matched resources (`cloud-custodian` 0.9.52 / `c7n/output.py`). Policy name is the parent directory (plus sibling `metadata.json` `policy.name`).
- `cloud/powerpipe-benchmark.json`: Powerpipe benchmark JSON tree (`group_id` / `groups` / `controls` / `results[].status`) after `steampipe check` was removed in Steampipe v1.0.0. Shape from Powerpipe v1.5.5 `result_row.go`.
- `cloud/steampipe-query.json`: `steampipe query --output json` `{columns,rows}` with no `status` (Steampipe CHANGELOG v2.4.7). Inventory only.

## MDM

- `mdm/intune-manageddevices-v1.json`: Microsoft Graph v1.0 `managedDevice` (`azureADRegistered`, `isEncrypted`, `complianceState`; no `managementState` / `antivirusStatus`). Docs: graph `manageddevice` resource.
- `mdm/jamf-computers-inventory.json`: Jamf Pro API 11.32 `GET /v1/computers-inventory` `{totalCount, results[{general, diskEncryption, operatingSystem}]}` camelCase.

## IdP / SaaS

- `saas/entra-userregistrationdetails.json`: Graph `userRegistrationDetails` (`isAdmin` = any admin role, `isMfaRegistered`, `userType`). Docs identities: AdeleV@contoso.com / DiegoS@contoso.com.
- `saas/okta-users-api.json`: Okta Management API `GET /api/v1/users` bare array (`id`, `status`, `profile.login`). Spec 2026.08.4. No roles/MFA on this endpoint.
- `saas/google-admin-users.csv`: Google Admin console user download headers (`Email Address [Required]`, `Super Admin`) per support.google.com/a/answer/40057.
- `saas/maester-no-severity.json`: Maester 2.2.0 `Tests[]` (`Id`, `Title`, `Result`) with no `Severity`. TenantId is a GUID.

## BloodHound

- `bloodhound/bhce_v6_*.json`: SharpHound CE v6 / BloodHound `@ ca1be93` `Version6AllJSON/raw/{users,computers,domains}.json` (ESC1.LOCAL lab fixture). Trimmed. Default admin ACEs and computer SPNs are present in the source and must not become roastable/critical noise.
- `bloodhound/bhce_v6_real_exposure.json`: same CE v6 ACE shape; `GetChanges`+`GetChangesAll` on `VICTIM@ESC1.LOCAL` (name from that fixture) to prove true DCSync detection. Default `-512` GenericAll stays silent.

## Trivy

- `trivy/secrets.json`, `trivy/dockerfile.json`: trimmed from aquasecurity/trivy `@ ae561f8` `integration/testdata/{secrets,dockerfile}.json.golden` (SchemaVersion 2). Secret match redacted.

## osquery

- `osquery/docs-process-snapshot.json`: osquery 5.x snapshot envelope from `osquery/docs/wiki/deployment/logging.md` `@ d89a164` (`hostIdentifier`, `action: snapshot`). Inventory query — not a finding.
- `osquery/snapshot-disk-encryption.jsonl`: same 5.x envelope for a named disk_encryption snapshot (JSONL as osqueryd writes).

## PingCastle / Greenbone / ScubaGear / testssl / Nikto (§8 / #139)

| File | Source | What was trimmed |
|---|---|---|
| `pingcastle/one.xml` | [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) `unittests/scans/pingcastle/one.xml` (Engine 3.2.0.1). Model: [PingCastle HealthcheckData](https://github.com/vletoux/pingcastle) `HealthcheckRiskRule` / `HealthCheckGroupData`. | Whole one-rule file. Added a `HealthCheckGroupData` (capital C) + `ListNoPreAuth` account so case-insensitive group/account tags are exercised. IPs stay documentation placeholders. |
| `greenbone/one_vuln.xml` | DefectDojo `unittests/scans/openvas/one_vuln.xml` (GMP 9.0 report XML) | One `result` kept (Firefox NVT, CVSS 10.0, CVE-2023-4573). Wrapper scan metadata dropped. |
| `greenbone/one_vuln.csv` | DefectDojo `unittests/scans/openvas/one_vuln.csv` | Header + the one SSH weak-cipher row. |
| `scuba/ScubaResults_sample.json` | [cisagov/ScubaGear](https://github.com/cisagov/ScubaGear) v1.8.0 `@ 8bbaf75` `ScubaResults` shape (`MetaData` + `Results{product:[group.Controls[]]}`). Keys from `docs/misc/tooloutputschema.md`. | Two AAD controls (Fail/Shall + Warning/Should) + one Pass. Tenant from MetaData only. |
| `testssl/finos_robmoff.at_443_vulnerable.json` | testssl.sh 3.x `--jsonfile-pretty` (`scanResult[]` sections `protocols`, `serverDefaults`, `vulnerabilities`). Shape matches the FINOS `robmoff.at` pretty JSON cited in the §8 audit. | One host. SSLv3 HIGH, TLS1 LOW, expired cert HIGH, BREACH MEDIUM, LUCKY13 LOW, one WARN, OK rows. |
| `testssl/server-defaults.json` | Same 3.x pretty-JSON shape, `serverDefaults` only. | Certificate expiry HIGH + WARN OCSP row. |
| `nikto/issue_9274.json` | DefectDojo `unittests/scans/nikto/issue_9274.json` (Nikto 2.6.1 list-of-hosts JSON) | Untrimmed (already 8 rows). Header noise + BREACH. |
| `nikto/juice-shop-trim.json` | DefectDojo `unittests/scans/nikto/juice-shop.json` (dict host + 740001 soft-404 noise) | 2 header rows, 2 backup-noise rows, BREACH, `/public/` interesting, NextGEN LFI. |
| `nikto/nikto-output-trim.xml` | DefectDojo `unittests/scans/nikto/nikto-output.xml` (Nikto 2.1.5) | X-Frame, PUT, Tomcat examples, XSS, Manager. |
