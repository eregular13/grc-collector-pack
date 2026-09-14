# Import — Probo (addRisk / addFinding drafts)

This pack emits **documentation-only** Probo MCP/GraphQL argument drafts.
It does not call `POST /api/console/v1/graphql` or `/api/mcp/v1`.

Public shapes: [Probo risks](https://mintlify.wiki/getprobo/probo/api-reference/risks)
(`addRisk`) and [findings MCP tools](https://www.probo.com/docs/api/mcp/tools/findings)
(`addFinding`). Source: [getprobo/probo](https://github.com/getprobo/probo).

CISO Assistant Community CSVs remain the prove-path SoR. The Probo file is
a second sink from the same intermediate.

## Honesty

| Claim | Truth |
|---|---|
| Estate | **SAMPLE/DEMO ≠ client** on the fixture / prove path. |
| Paying-day | **FAIL.** Preview is not a live create. |
| Posted | **false.** `organization_id` and `owner_id` stay **null**. |
| HTTP | **false.** No GraphQL, no MCP, no sockets. |
| RiskReady | Stay-out. `createRisk` here is a Probo draft shape, not `/api/risks`. |

## What Probo expects

Operator fills `organization_id` (and optionally `owner_id`) on their
instance, then pastes one object at a time:

### `addRisk`

`name`, `category`, `treatment` (`MITIGATED` \| `ACCEPTED` \| `AVOIDED` \|
`TRANSFERRED`), `inherent_likelihood` / `inherent_impact` (1–5), optional
`description`, residual scores, `note`.

CISO `treatment=mitigate` maps to draft `MITIGATED`. That is **intent**,
not proof that controls already landed.

### `addFinding`

`kind` (`OBSERVATION` \| `MINOR_NONCONFORMITY` \| `MAJOR_NONCONFORMITY` \|
`EXCEPTION`), `description`, `source`, `status` (`OPEN`), `priority`
(`LOW` \| `MEDIUM` \| `HIGH`). `due_date` is omitted — do not invent dates.

Severity map: low → OBSERVATION/LOW; medium/high → MINOR_NONCONFORMITY;
critical → MAJOR_NONCONFORMITY/HIGH.

## Files

- `out/import_preview/probo.json` after `python3 -m exporters --sink probo`
  or `python3 scripts/preview_probo.py`
- `out/probo/README.md` honesty stub
- `out/ciso-assistant/*.csv` (input; unchanged)

`createRisk[]` remains as a high/critical subset so older preview tests
and docs still parse. Prefer `addRisk` + `addFinding` for import.

## Operator path

1. Run the host lab, `python3 -m dropbox ciso`, or `python3 scripts/prove_ciso.py`.
2. Confirm `out/ciso-assistant/findings.csv` (and assets / risk_scenarios).
3. `python3 -m exporters --sink probo` (or `python3 scripts/preview_probo.py`).
4. Read `out/import_preview/probo.json`. Fill `organization_id`. Import in
   Probo MCP (`tools/call` `addRisk` / `addFinding`) or GraphQL **by hand**.

Never `POST /api/risks`. RiskReady wrap stays review-only.

Schema notes: [../schemas/probo.md](../schemas/probo.md).
