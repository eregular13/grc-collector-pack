# DEMO lab stubs

Shell scripts: `nmap`, `curl`, `nessus`, `nessuscli`, `testssl`, `testssl.sh`,
`lynis`. They are **not** scanners.

They write fixture-shaped stdout and make **no** network calls. Used when
`FARM_TOOL_BIN` (or PATH) points at this directory so plan `will_run` and a
controlled dry invoke can be proven without embedding apt packages.

`make farm-toolbin-lab` points `FARM_TOOL_BIN` here and asserts nmap+curl
`will_run`. It does not start compose and does not probe the internet.

On a real drop box: copy **your** allowlisted binaries into `farm/tool-bin/`
(the parent mount) or rely on host PATH. Do not replace these stubs with
downloaded nmap/nessus/nuclei/openvas packages in git.
