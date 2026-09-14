# Probo ingest (documentation-only drafts)

Auth: none from this pack. Operator supplies a Probo API key and
`organization_id` on their instance.

This pack writes `out/import_preview/probo.json` only. It does not POST
`/api/console/v1/graphql` or `/api/mcp/v1`.

```bash
export PYTHONPATH="$PWD"
python3 -m exporters --sink probo
# or python3 scripts/preview_probo.py
```

`posted` is always **false**. `organization_id` / `owner_id` are **null**.

## addRisk (per draft object)

```
organization_id, name, category, treatment,
inherent_likelihood, inherent_impact,
residual_likelihood, residual_impact, description, note
```

`treatment` ∈ `MITIGATED|ACCEPTED|AVOIDED|TRANSFERRED`.
CISO `mitigate` → draft `MITIGATED` (intent, not evidence).

## addFinding (per draft object)

```
organization_id, kind, description, source, status, priority, ref_id
```

- `kind` ∈ `OBSERVATION|MINOR_NONCONFORMITY|MAJOR_NONCONFORMITY|EXCEPTION`
- `status` = `OPEN`
- `priority` ∈ `LOW|MEDIUM|HIGH`
- `due_date` omitted (do not invent)

## createRisk

Legacy high/critical preview array. Same facts as `addRisk` for those
rows. Prefer `addRisk` + `addFinding` for import.
