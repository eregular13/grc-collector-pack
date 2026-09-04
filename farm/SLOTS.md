# Farm SLOTS catalog

Private drop-box tool zoo. **No binaries in git.** Most slots are file_drop:
the operator lands artifacts in `in/<sensor>/` for Layer C.

Total: 111
Wired: 32
Invoke: 30
File-drop: 81

## By category

| category | total | wired | invoke | file_drop |
|---|---:|---:|---:|---:|
| cloud | 11 | 2 | 2 | 9 |
| deepen | 14 | 2 | 2 | 12 |
| discover | 18 | 9 | 9 | 9 |
| endpoint | 12 | 4 | 4 | 8 |
| external | 19 | 10 | 10 | 9 |
| identity | 13 | 1 | 1 | 12 |
| k8s | 10 | 3 | 2 | 8 |
| ot | 3 | 0 | 0 | 3 |
| secrets | 8 | 1 | 0 | 8 |
| wifi | 3 | 0 | 0 | 3 |

## Ingest map (Layer C)

Every `output_glob` lands in an existing Layer C sensor directory.
`audit_output_globs()` is empty. No theater parsers.

| sensor | total | invoke | file_drop |
|---|---:|---:|---:|
| in/cloud/ | 9 | 1 | 8 |
| in/code/ | 8 | 0 | 8 |
| in/easm/ | 24 | 10 | 14 |
| in/identity/ | 10 | 1 | 9 |
| in/k8s/ | 10 | 1 | 9 |
| in/nmap/ | 24 | 11 | 13 |
| in/saas/ | 5 | 1 | 4 |
| in/vuln/ | 11 | 3 | 8 |
| in/wazuh/ | 10 | 2 | 8 |

File-drop only (never subprocess even if on PATH): amass, checkov, ffuf, gobuster, nikto, scoutsuite, subfinder.

LICENSE-LOCK names stay file_drop and are never subprocessed.

## Nmap file-drop (Layer C)

Drop Nmap **gnmap** (`-oG`), **XML** (`-oX`), or a thin **JSON** host/port
export under `in/nmap/`. Also drop **masscan** `-oX` XML or `-oJ` JSON
(`scanner="masscan"`, `{ip, ports:[{port, proto, status}]}`). Open ports
only — empty `ports` / empty `nmaprun` invent nothing. masscan stays
`file_drop` / `use_dont_ship` (never subprocess). The inventory-nmap
collector is parse-only — it never subprocesses `nmap` or `masscan`.
Orchestrator discover may land DEMO stub gnmap
(`farm/tool-bin/lab/nmap` → `dropbox-discover-*.gnmap`) or BYO output.
Open 445 / 3389 / 23 map to the existing CISO/POA&M rows (SMB, RDP, Telnet).
Empty `in/` still loads `fixtures/demo/nmap/` (`scan.gnmap`, `scan.xml`,
`masscan.xml`). No new catalog slots.

## Kubernetes file-drop (Layer C)

Drop **Kubescape** JSON (`summaryDetails.controls` or `results`) and
**kube-bench** JSON (`Controls[].tests[].results[]` or a flat FAIL list) under
`in/k8s/`. Failed/FAIL rows only — Passed/PASS stay silent. Parse-only — no
`kubectl`, no live cluster API. High rows map to CISO/POA&M when obvious
(privileged containers, anonymous-auth, privilege escalation, hostNetwork).
Empty `in/` still loads `fixtures/demo/k8s/` (`kubescape.json`,
`kube-bench.json`). kube-bench / kubescape stay file_drop (never subprocess).
No new catalog slots.

## KEEP-chain file-drop (Layer C)

Drop **testssl.sh JSON** (native finding array or `scanResult` wrapper) under
`in/vuln/` or `in/easm/`. HIGH/CRITICAL/WARN rows only — OK/INFO are silent.
Drop **sslscan** XML (`ssltest` / `protocol`) or text (`SSL/TLS Protocols`)
under `in/vuln/` or `in/easm/`. Weak/failed only (TLS 1.0, SSLv2/v3,
Heartbleed, weak ciphers). Empty / TLS 1.2-only invent nothing. sslscan
XML/text is not testssl JSON — a separate parse. No live TLS from Layer C.
High rows map to CISO/POA&M when obvious (Heartbleed, TLS 1.0). Empty `in/`
still loads `fixtures/demo/vuln/testssl.json` and `sslscan.xml`. testssl /
sslscan *invoke* is separate BYO (`allow_tools`) and stays plan-only from
orchestrate.

Drop **Maester** / Entra assessment JSON under `in/saas/` (`TestResults` /
`Tests`, or a Graph `directoryRoles` export). Failed rows only; Passed/Skipped
stay silent. The collector does not call Microsoft Graph. Empty `in/` still
loads `fixtures/demo/saas/maester.json`. Maester *invoke* is separate BYO.
No new catalog slots.

## BloodHound CE file-drop (Layer C)

Drop **BloodHound CE** / **SharpHound** JSON under `in/identity/`
(`data.nodes` / `data.edges`, a top-level `nodes`/`edges` graph, or SharpHound
`data` arrays with `Properties` / `ObjectIdentifier` / `Aces`). Mapped edges
only (GenericAll, DCSync, AdminTo, HasSession, …). Empty `data` / empty
`Members` invent nothing. Parse-only — no LDAP, no BloodHound API, no
SharpHound run. High rows map to CISO/POA&M (DCSync, GenericAll, roastable
SPN, AS-REP, unconstrained delegation, Backup Operators). Empty `in/` still
loads `fixtures/demo/identity/bloodhound.json` and `bloodhound-edges.json`.
bloodhound / azurehound stay file_drop (never subprocess). No new catalog slots.

## Endpoint file-drop (Layer C)

Drop **HardeningKitty Audit CSV** under `in/identity/` (Failed/warning rows
only; Passed and Guest-passed stay silent — the parser does not invent
Windows findings). Drop a **Lynis** report or `report.dat` under `in/wazuh/`
(`*.txt` / `*.log` / `*.dat`). Parse-only — no AD/LDAP/WinRM and no live
Lynis run. High rows map to CISO/POA&M when the title is obvious (password
history, LM hash, host firewall missing, SSH PermitRootLogin). Empty `in/`
still loads `fixtures/demo/identity/hardeningkitty.csv` and
`fixtures/demo/wazuh/lynis-report.txt`. Lynis *invoke* is separate BYO
(`allow_tools`) when the binary is on PATH; this path is file-drop ingest.

Drop **Fleet** host/policy JSON under `in/wazuh/` (`hosts`, `data.hosts`,
or a single `host`, plus failing `policies`). Offline/MIA hosts become
coverage gaps. `disk_encryption_enabled=false` and MDM enrollment Off map
to CISO/POA&M. Passing policies stay silent. Empty `hosts` / `policies`
invent nothing. Parse-only — no Fleet API, no fleetctl, no osqueryi.
Empty `in/` still loads `fixtures/demo/wazuh/fleet.json`. No new catalog slots.

Drop **CIS-CAT** / XCCDF JSON or XML under `in/wazuh/` or `in/identity/`.
Failed/failing rows only — Pass stays silent. Empty `results` invents
nothing. High rows map to CISO/POA&M when obvious (SSH PermitRootLogin,
host firewall, disk encryption). Drop **osquery** check JSON under
`in/wazuh/` (`queries` / `osquery` rows with status=fail). Inventory-only
`system_info` stays host coverage, not invented checks. Parse-only — no
CIS-CAT binary, no osqueryi. Empty `in/` still loads
`fixtures/demo/wazuh/cis-cat.json` and `osquery-checks.json`.
cis-cat / osqueryi stay file_drop. No new catalog slots.

## Cloud file-drop (Layer C)

Drop **Prowler** JSON or **ASFF** (`Findings` array / list / single object)
and **ScoutSuite** `services.*.findings` JSON under `in/cloud/`. Optional
same-folder drops: Cloud Custodian and Steampipe. Parse-only — no AWS/GCP/Azure
API calls, no live cloud scan. High FAIL rows map to CISO/POA&M when the title
or check id is obvious (public S3 / AllUsers, IAM AdministratorAccess, root MFA,
SG `0.0.0.0/0`, public RDS, unencrypted S3/EBS). Empty `in/` still loads demo
`fixtures/demo/cloud/` (including `prowler-asff.json` and `scoutsuite.json`).
Prowler *invoke* is separate BYO (`allow_tools`) when the binary is on PATH;
this path is file-drop ingest. ScoutSuite stays file_drop-only.
No new catalog slots.

## EASM file-drop (Layer C)

Drop **httpx** / **Amass** / **Subfinder** JSON, JSONL, or a host list under
`in/easm/`. Native JSON arrays and `{results|hosts|data}` wrappers parse.
httpx `failed:true` rows and empty arrays invent nothing. Interesting
rows only: sensitive perimeter names (vpn/admin/dev-api/staging) and
admin/login titles. Also drop **ffuf** JSON (`results` + status/url) and
**gobuster** text (`(Status: N)` lines). Interesting paths only
(`/admin`, `/login`, `/.git`) — 404 and robots stay silent. Drop
**WhatWeb** `--log-json` (`target` + `plugins`, or `{data}` wrap).
Admin/login titles and interesting paths only — generic nginx/Home
rows stay silent. Empty arrays invent nothing. High rows map to
CISO/POA&M (perimeter hostnames, exposed admin UI, TLS weak
cipher). Parse-only — no live DNS/HTTP, no amass/httpx/subfinder/ffuf/
gobuster/whatweb subprocess. Empty `in/` still loads `fixtures/demo/easm/`
(`httpx.jsonl`, `httpx.json`, `amass.jsonl`, `ffuf.json`, `whatweb.json`).
amass / subfinder / ffuf / gobuster / whatweb stay file_drop; httpx
*invoke* is separate BYO. No new catalog slots.

## Nuclei JSON file-drop (Layer C)

Drop **Nuclei** JSON / JSONL under `in/vuln/` (JSONL, a single object,
an array, or a `{results|matches|findings}` wrapper). `template-id` /
`template_id` / `info` rows only. INFO stays silent. Empty `results`
invents nothing. Parse-only — this repo never subprocesses `nuclei`.
High rows map to CISO/POA&M when obvious (Log4Shell / RCE). Empty `in/`
still loads `fixtures/demo/vuln/nuclei.jsonl`. nuclei stays file_drop.
No new catalog slots.

## Nikto file-drop (Layer C)

Drop **Nikto** text, XML (`niktoscan` / `scandetails`), or JSON
(`vulnerabilities` / `items`) under `in/vuln/`. Slot glob is
`in/vuln/*.txt`; `.xml` / `.json` also parse. Interesting/high rows
only (`/admin`, `/login`, `/.git`, phpinfo, directory indexing).
Missing security-header noise stays silent. Empty exports invent
nothing. Deepen DEMO `.txt` stubs (NessusClientData) are not Nikto
and invent nothing. High rows map to CISO/POA&M (exposed admin UI).
Parse-only — this repo never subprocesses nikto and does not probe
HTTP. Empty `in/` still loads `fixtures/demo/vuln/nikto.txt`.
nikto stays file_drop. No new catalog slots.

## Nessus file-drop (Layer C)

Drop an operator-landed **NessusClientData** / `.nessus` XML under
`in/vuln/` (`ReportHost` / `ReportItem`). High/Critical rows only,
plus key Medium already patterned (SMB 445, RDP 3389, Telnet, TLS 1.0).
Info/Low and empty `Report` invent nothing. Farm DEMO tool-bin `.txt`
stubs (`NessusClientData` comment, no `ReportHost`) are not exports
and invent nothing. High rows map to CISO/POA&M when the title is
obvious (SMB, RDP, TLS). Parse-only — Layer C never runs a Nessus
binary and never calls a Nessus API. nessus / nessuscli *invoke* is
separate BYO (`allow_tools` + PATH). Empty `in/` still loads
`fixtures/demo/vuln/demo.nessus`. No new catalog slots.

## SaaS file-drop (Layer C)

Drop **ScubaGear** / Entra assessment JSON or JSONL under `in/saas/`
(`Results`, `{data|ScubaResults|scuba}` wrappers, or a row array).
Failed/high rows only — Pass / Skip / Info stay silent. Empty `Results`
invents nothing. Drop **Okta** org/policy JSON (`users` / `policies` /
`org`, or `{data|okta}` wrappers). Inactive MFA_ENROLL (or an MFA-named
policy) becomes a finding; empty `users`/`policies` invent nothing.
Maester Failed rows and Graph `directoryRoles` exports stay parse-only.
High MFA / standing Global Administrator rows map to CISO/POA&M.
Parse-only — Layer C never calls Microsoft Graph or the Okta API.
scuba / okta-logs / entra-export / graph-export stay file_drop.
Maester *invoke* is separate BYO. Empty `in/` still loads
`fixtures/demo/saas/` (`scuba.json`, `scuba-wrap.json`, `okta.json`,
`maester.json`, `graph.json`). No new catalog slots.

## Secrets / IaC file-drop (Layer C)

Drop **Gitleaks** / **TruffleHog** / **Semgrep** / **Checkov** JSON or
JSONL under `in/code/`. Gitleaks arrays and `{findings|leaks|results}`
wrappers parse. TruffleHog JSONL and `{results}` wrappers parse.
Checkov `results.failed_checks` only — passed / skipped / INFO stay
silent. Empty exports invent nothing. Secret material is redacted.
High rows map to CISO/POA&M (credential rotate, public S3 / public ACL).
Parse-only — no gitleaks / trufflehog / semgrep / checkov subprocess.
Empty `in/` still loads `fixtures/demo/code/` (`gitleaks.json`,
`trufflehog.jsonl`, `checkov.json`). gitleaks / checkov stay file_drop.
No new catalog slots.

## SARIF file-drop (Layer C)

nuclei / semgrep / trivy stay file_drop (this repo does not run them).
Operator-landed SARIF is parsed by vuln-scan (`in/vuln/*.sarif`) and
code-secrets (`in/code/*.sarif`). High rules map to CISO/POA&M.
No new catalog slots.

See `SLOTS.yaml`, `INTEGRITY.md`, and `OPERATOR.md`.
