# Hexstrike.ai — pattern only, never vendor

Hexstrike’s MCP conductor UX (stage a job, pick a tool, watch status) is a useful **pattern**. Evergreen is not Hexstrike and does not become an exploit farm.

## What we take

- **Stage control** — quiet discover, then a louder deepen that is fail-closed.
- **Tool selection under SCOPE** — `allow_tools` ∩ PATH ∩ stage list. Missing → plan-only.
- **Observability** — `python3 -m dropbox status` and the operator MCP conductor (`scope_status`, `orchestrator_plan`, `orchestrator_status`, `stage_*`, `farm_slots`, `farm_slot_status`, `farm_toolbin_status`, `export_ciso_poam`).

## What we refuse

- Exploit-chain conductors and “AIExploitGenerator”-style autonomous attack graphs.
- Metasploit / `msfconsole` / unauthenticated autonomous spray.
- Standing up a Hexstrike server, vendoring `hexstrike-ai`, or adding it as a git submodule.
- A public attack API. The stub wraps `python3 -m dropbox …` only.

See `operator_mcp_interface.md` and `mcp_stub.py`. Deepen still requires `orchestrator.stages.deepen: true`. Batch / `max_workers` brakes are unchanged.

This stub is **conductor UX for this Python pack**, not USB
`evergreen_assessment_mcp` (21-tool `check_scope` / `license_guard`) and not
paying-day truth. Do not invent a parallel TypeScript refuse matrix. Do not
treat `tools/list` here as an assessment catalog.

