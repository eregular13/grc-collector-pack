# CRITIC — cycle 15 (MCP serve + worker teardown + external named-only)

**8/10** — zero P0/P1. stdio MCP serve lists the seven tools and handles one JSON-RPC line; still not a hosted conductor. Workers destroyed after timeout/failure. External wildcards/CIDRs refused. testssl/curl adapters tested with PATH stubs. Wrap review-only. Labs green.

−1 compose absent on this VM.  
−1 live BYO still plan-only here (nmap/nessus/testssl missing); MCP serve is list-only, not a long-running FastMCP server.

```json
{"pytest": 132, "assets_empty_in": 62, "findings_empty_in": 62, "evidences": 24, "poam": 61, "assets_dropbox_lab": 68, "findings_dropbox_lab": 71, "poam_dropbox_lab": 64, "host_lab": "pass", "dropbox_lab": "pass", "compose_lab": "absent", "wrap": "review-only", "orchestrator": "plan-only quiet→loud", "demo_dropbox_lab": true}
```
