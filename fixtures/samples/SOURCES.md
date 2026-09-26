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
