# RiskReady Community Edition ingest

Auth: `POST /api/auth/login` `{email,password}`
API default: `http://localhost:9380/api`

`push_riskready.sh` only when `RISKREADY_PUSH=1`: assets, evidence, incidents. Never POST `/api/risks`.

## assets.json → POST /api/itsm/assets

```json
{
  "name": "string",
  "assetType": "Server|Cloud|Application|Identity|Network",
  "status": "ACTIVE",
  "businessCriticality": "LOW|MEDIUM|HIGH",
  "dataClassification": "INTERNAL",
  "cloudProvider": "AWS|AZURE|GCP|NONE",
  "inIsmsScope": true,
  "source": "sensor-name",
  "notes": "string"
}
```

## incidents.json → POST /api/incidents

Explicit incidents plus every finding with severity `high|critical`.

## evidence.json → POST /api/evidence

```json
{
  "title": "string",
  "description": "string",
  "evidenceType": "TECHNICAL",
  "sourceType": "SENSOR",
  "status": "DRAFT",
  "source": "sensor-name"
}
```

## risks_proposed.json — NEVER auto-POST /api/risks

Only `high` and `critical` findings.

- likelihood: `RARE|UNLIKELY|POSSIBLE|LIKELY|ALMOST_CERTAIN`
- impact: `NEGLIGIBLE|MINOR|MODERATE|MAJOR|SEVERE`

Map: info→RARE/NEGLIGIBLE, low→UNLIKELY/MINOR, medium→POSSIBLE/MODERATE, high→LIKELY/MAJOR, critical→ALMOST_CERTAIN/SEVERE.
