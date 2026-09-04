# tool-bin — bind-mount only

Empty on purpose. Put **nothing** executable in git.

On a consented box, bind-mount the host directory that already has allowlisted tools:

```bash
export FARM_TOOL_BIN=/usr/local/bin
```

Or copy (outside git) the binaries Reid installed. Orchestrator uses PATH / this mount. Missing → plan-only.
