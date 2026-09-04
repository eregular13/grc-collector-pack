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

`lab/` holds **DEMO shell stubs** (`nmap`, `curl`) for tests. They are not
scanners. Point `FARM_TOOL_BIN` at `farm/tool-bin` or `farm/tool-bin/lab` only
when you intend those stubs. Unset `FARM_TOOL_BIN` → PATH only; missing → plan-only.

Do not commit ELF/deb/rpm scanner packages here.
