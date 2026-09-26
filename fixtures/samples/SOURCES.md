# Sample provenance (fixtures/samples)

Trimmed public shapes used to lock parsers against real tool output.
These files are **SAMPLE/DEMO fixtures**, not a client KEEP drop. No live scan.

Provenance matches the research pack `samples/SOURCES.md` (fetched 2026-09-25 PT)
and DefectDojo / ScubaGear / testssl public fixtures used in the §8 / §9 audit.

PR #134 owns Prowler/Wazuh/XCCDF/SARIF/enum4linux-ng rows. PR #139 owns
PingCastle, Greenbone, ScubaGear, testssl, and Nikto rows. Tables are unioned.
This branch also documents Metis §11 / real-sample Cloud / MDM / IdP /
BloodHound / Trivy / osquery fixtures below.

LAB/SAMPLE/DEMO ≠ client KEEP. Never POST `/api/risks`. RiskReady stay-out.

## Cloud

- `cloud/s3-encryption-missing/resources.json`: Cloud Custodian (c7n) `resources.json` is a bare list of matched resources (`cloud-custodian` 0.9.52 / `c7n/output.py`). Policy name is the parent directory (plus sibling `metadata.json` `policy.name`).
- `cloud/powerpipe-benchmark.json`: Powerpipe benchmark JSON tree (`group_id` / `groups` / `controls` / `results[].status`) after `steampipe check` was removed in Steampipe v1.0.0. Shape from Powerpipe v1.5.5 `result_row.go`.
- `cloud/steampipe-query.json`: `steampipe query --output json` `{columns,rows}` with no `status` (Steampipe CHANGELOG v2.4.7). Inventory only.
- `cloud/scoutsuite-results.js`: ScoutSuite `scoutsuite_results =` JavaScript assignment (nccgroup/ScoutSuite `HTMLReport` / `scoutsuite_results.js`). Same danger finding shape as the JSON export.

## MDM

- `mdm/intune-manageddevices-v1.json`: Microsoft Graph v1.0 `managedDevice` (`azureADRegistered`, `isEncrypted`, `complianceState`; no `managementState` / `antivirusStatus`). Docs: graph `manageddevice` resource.
- `mdm/jamf-computers-inventory.json`: Jamf Pro API 11.32 `GET /v1/computers-inventory` `{totalCount, results[{general, diskEncryption, operatingSystem}]}` camelCase. `fileVault2EnabledState` enum from the Jamf Pro API docs: `ALL_ENCRYPTED` / `BOOT_ENCRYPTED` / `SOME_ENCRYPTED` / `NOT_ENCRYPTED`. One `section=GENERAL` row has no `diskEncryption`.

## IdP / SaaS

- `saas/entra-userregistrationdetails.json`: Graph `userRegistrationDetails` (`isAdmin` = any admin role, `isMfaRegistered`, `userType`). Docs identities: AdeleV@contoso.com / DiegoS@contoso.com.
- `saas/okta-users-api.json`: Okta Management API `GET /api/v1/users` bare array (`id`, `status`, `profile.login`). Spec 2026.08.4. No roles/MFA on this endpoint.
- `saas/google-admin-users.csv`: Google Admin console user download headers (`Email Address [Required]`, `Super Admin`) per support.google.com/a/answer/40057.
- `saas/maester-no-severity.json`: Maester 2.2.0 `Tests[]` (`Id`, `Title`, `Result`) with no `Severity`. TenantId is a GUID.

## BloodHound

- `bloodhound/bhce_v6_*.json`: SharpHound CE v6 / BloodHound `@ ca1be93` `Version6AllJSON/raw/{users,computers,domains}.json` (ESC1.LOCAL lab fixture). Trimmed. Default admin ACEs and computer SPNs are present in the source and must not become roastable/critical noise.
- `bloodhound/bhce_v6_real_exposure.json`: same CE v6 ACE shape; `GetChanges`+`GetChangesAll` on `VICTIM@ESC1.LOCAL` (name from that fixture) to prove true DCSync detection. Default `-512` GenericAll stays silent.
- `bloodhound/bhce_v6_sessions.json`: CE v6 `Sessions` / `PrivilegedSessions` (`UserSID` / `ComputerSID`). One privileged principal (`admincount=1`) with three hosts; a non-privileged user session stays inventory.

## Trivy

- `trivy/secrets.json`, `trivy/dockerfile.json`: trimmed from aquasecurity/trivy `@ ae561f8` `integration/testdata/{secrets,dockerfile}.json.golden` (SchemaVersion 2). Secret match redacted.
- `trivy/k8s-cluster.json`: Trivy k8s report (`ClusterName` + `Resources[].Results[]`) from aquasecurity/trivy `trivy k8s` JSON. One alpine musl CVE on `nginx` in `default`.

## osquery

- `osquery/docs-process-snapshot.json`: osquery 5.x snapshot envelope from `osquery/docs/wiki/deployment/logging.md` `@ d89a164` (`hostIdentifier`, `action: snapshot`). Inventory query — not a finding.
- `osquery/snapshot-disk-encryption.jsonl`: same 5.x envelope for a named disk_encryption snapshot (JSONL as osqueryd writes).
- `osquery/it-compliance-pack.json`: official osquery `packs/it-compliance.conf` (32 query names, `@ master`). Combined `{hostIdentifier, queries}` snapshot for a compliant host (`disk_encryption.encrypted=1`; no status/result columns). Inventory only.
- `osquery/osqueryd.results.sample.log`: byte-identical [elastic/beats@94ad82c](https://github.com/elastic/beats/blob/94ad82c/filebeat/module/osquery/result/test/osqueryd.results.sample.log) `filebeat/module/osquery/result/test/osqueryd.results.sample.log` (Apache-2.0; see `osquery/LICENSE.beats.txt`). Ubuntu it-compliance pack. Disk encryption off (ignore `/dev/loop*`).
- `osquery/osqueryd.results.darwin.log`: byte-identical beats `@94ad82c` `osqueryd.results.darwin.log` (Apache-2.0). Mac it-compliance pack. Application firewall `global_state=0`.
- `osquery/msticpy.osqueryd.results.log`: byte-identical [microsoft/msticpy@f78bd67](https://github.com/microsoft/msticpy/blob/f78bd67/tests/testdata/osquery/osqueryd.results.log) (MIT; see `osquery/LICENSE.msticpy`). Custom/IR packs — inventory or unmapped, never failed.
- `cloud/security-context-pods/{metadata,resources}.json`: byte-identical [Policy-as-Code-Book/first-edition@66e1030](https://github.com/Policy-as-Code-Book/first-edition/tree/66e1030/ch10-c7n-k8s/cli-mode/output/security-context-pods) `k8s.pod` run (Apache-2.0; see `cloud/security-context-pods/LICENSE`). Policy name + resource type from `metadata.json`. Asset is `test/test-pod-1`. Real Custodian has no severity field — security policies default Medium.
- `cloud/stop-underutilized-azure-vms/{metadata,resources}.json`: byte-identical [MShujat/basic-cloud-custodian-mcp@883b2bd](https://github.com/MShujat/basic-cloud-custodian-mcp/tree/883b2bd/output/stop-underutilized-azure-vms) `azure.vm` cost policy (MIT; see `cloud/stop-underutilized-azure-vms/LICENSE`). 8 VMs → excluded `NOT_A_WEAKNESS`, not findings.

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
LAB/SAMPLE/DEMO ≠ client KEEP. Never POST `/api/risks`. RiskReady stay-out.

# Sample provenance (network discovery / web collectors)

Trimmed, real-shaped tool output used by `tests/test_discovery_web_samples.py`.
LAB/SAMPLE/DEMO — not a client estate. No invented hostnames or tenants.

## DefectDojo unit-test scans (public)

- `httpx.jsonl`: trimmed from `unittests/scans/httpx/httpx_many_vuln.json`
  https://github.com/DefectDojo/django-DefectDojo (httpx v1.12 JSONL; one row per URL)
- `ffuf.json`: trimmed from `unittests/scans/ffuf/ffuf_many_vuln.json`
  https://github.com/DefectDojo/django-DefectDojo (ffuf `-of json`; `/admin`, `/backup`, `/.git`)
- `nmap-vulners.xml`: trimmed from `unittests/scans/nmap/nmap_script_vulners.xml`
  https://github.com/DefectDojo/django-DefectDojo (nmap 7.60, `vulners` NSE; CVE-2018-15919 / CVE-2017-15906)

## Tool source (format only; no live scan)

- `arp-scan.txt`: line shape from arp-scan 1.10.0 `arp-scan.c`
  (IP\\tMAC\\tVendor). Vendors with `Ltd` tails from IEEE OUI wording
  (TP-LINK / Huawei style). No hostname column on default output.
  `--resolve` (host-first) is covered in tests with inline `.test` names (RFC 2606).
- `netdiscover.txt`: unique-host table from netdiscover 0.21 `data_unique.c` / `screen.c`
  (vendor only; header says "MAC Vendor / Hostname").
- `fping-c.txt`, `fping-e.txt`, `fping-a.txt`, `fping-j.jsonl`: fping 5.5 `output.c`
  (`-c` live `bytes, … ms` vs `timed out`; `-e` `(x ms)`; `-a` bare IP; `-J` `{"resp":…}`).
- `nbtscan.txt`, `nbtscan-s.txt`, `nbtscan-v.txt`: nbtscan 1.7.2 `nbtscan.c`
  (default `%-17s` columns; `-s :` four splits + MAC remainder; `-v` `<00> UNIQUE` + Adapter address).
- `smbmap.txt`, `smbmap.csv`, `smbmap-g.txt`: smbmap v1.10.8 `smbmap.py` `to_string`
  (Status: NULL/Guest; tab-padded share names; `--csv` Host,Share,Privs,Comment; `-g` grepable).
- `naabu.jsonl`: naabu v2.6.1 `output.go` (`protocol`, `cdn`, `cdn-name`; open ports only).
- `nmap-open-filtered.xml`: nmap XML DTD / reference guide port states
  (`open|filtered` is a documented UDP state; MAC `addrtype="mac"`).

Fetched 2026-09-26. Operator file-drop only — parsers never spawn the tools.
