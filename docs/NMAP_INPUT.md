# nmap input

The pack parses nmap **XML** (`-oX` or the `.xml` file from `-oA`). Grepable
`.gnmap` is read for open ports only. Normal output (`.nmap`) is human-readable
text and is not parsed.

- `.nmap` next to a same-stem `.xml` (for example `scan.nmap` + `scan.xml`
  from `-oA scan`) is treated as a copy of the XML and is not reported unread.
- `.nmap` alone (no XML) is reported unread and the sensor status is
  `partial`. Re-run with `-oX` / `-oA`; text output loses NSE script tables
  (vulners CVSS) and cannot be accounted for CVE-by-CVE.
- Second-pass scans go in `in/pass2/` (XML required; see the unread-input
  guard).

CVE accounting (`scripts/cve_accounting.py`, run by `lab_drop_to_sor.sh`)
counts vulners CVE ids from XML NSE tables and CVEs from vuln-category scripts
that report `State: VULNERABLE`.
