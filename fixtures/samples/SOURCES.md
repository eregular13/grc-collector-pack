# Sample provenance (fixtures/samples)

Trimmed public shapes used to lock parsers against real tool output.
SAMPLE/DEMO only — not a client estate. No live scan.

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
