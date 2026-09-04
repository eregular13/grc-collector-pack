# Drop box — authorized assessment brakes

Written client consent → Reid-owned box in their environment → quiet discover → small-batch deepen → ingest files → CISO SoR + POA&M leave-behind.

This folder is the **orchestrator (brakes)**. It is not the scanner zoo and not the parse pack.

1. **Tool zoo** — BYO on the drop box under SCOPE `allow_tools`. This repo does not embed Nmap, Nessus, Nuclei, or OpenVAS.
2. **Orchestrator** — `python -m dropbox.orchestrator`. Stages: plan → shard → discover → destroy → deepen (2–5 hosts) → destroy → ingest → grc_export. Plan-only works with no binaries.
3. **Ingest pack** — existing collectors parse `in/` (or demo fixtures). No live scan in containers.

Unsigned SCOPE, `consent_attested=false`, or empty targets: live stages refuse. Fixture runs are labeled fixtures, not a client estate.

RiskReady wrap is dead (LICENSE-LOCK). See `NOTICE`.
