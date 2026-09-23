# Probo import preview (documentation only)

SAMPLE/DEMO — not a client estate. File-drop parse only. posted=false. Not a paying-day stamp.

Canonical file: `out/import_preview/probo.json`.

- `addFinding` — one draft per CISO finding/vulnerability.
- `addRisk` — CISO risk_scenarios plus high/critical findings.
- `createRisk` — backward-compatible high/critical subset.

`organization_id` and `owner_id` are null. Fill them on the Probo instance. posted=false. No GraphQL/MCP from this pack.
