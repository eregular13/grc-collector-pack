# Real-shaped parser samples (trimmed)

Provenance matches the research pack `samples/SOURCES.md` (fetched 2026-09-25 PT)
and DefectDojo / ScubaGear / testssl public fixtures used in the §8 audit.
These files are **SAMPLE/DEMO fixtures**, not a client KEEP drop.

PR #134 (not on master at this writing) owns Prowler/Wazuh/XCCDF/SARIF/enum4linux-ng
rows in this file. This table is the §8 collector set (PingCastle, Greenbone,
ScubaGear, testssl, Nikto). Merge by appending, do not overwrite #134's rows.

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
- `udpConnect_10.11.1.0-254.xml`: [chroniccrash/c4rtographer](https://github.com/chroniccrash/c4rtographer)
  `@ b73866a` `data/udpConnect_10.11.1.0-254.xml` (Nmap 7.40 `-sU` / udpConnect;
  MIT License). Byte-identical. 44 hosts, 36 udp `open`, 101 `open|filtered`.

Fetched 2026-09-26. Operator file-drop only — parsers never spawn the tools.
