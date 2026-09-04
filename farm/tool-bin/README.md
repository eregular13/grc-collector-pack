# tool-bin — bind-mount + optional DEMO lab stubs

Parent directory stays empty in git (`.gitkeep` only). On a consented drop box:

1. **Host PATH** — install allowlisted tools yourself; SCOPE names them.
2. **Copy or bind-mount** real binaries into this directory (or set
   `FARM_TOOL_BIN` to the host dir that already has them).

```bash
export FARM_TOOL_BIN=/usr/local/bin
# or: cp /usr/bin/nmap /path/to/grc-collector-pack/farm/tool-bin/
#      export FARM_TOOL_BIN=/path/to/grc-collector-pack/farm/tool-bin
```

`lab/` holds **DEMO shell stubs** (`nmap`, `curl`, `nessus`, `nessuscli`,
`testssl`, `testssl.sh`, `lynis`) for tests. They are not scanners.
`make farm-toolbin-lab` points `FARM_TOOL_BIN` there. Unset `FARM_TOOL_BIN`
→ PATH only; missing → plan-only.

Do not commit ELF/deb/rpm scanner packages here.
