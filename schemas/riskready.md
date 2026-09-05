# RiskReady Community Edition — review-only export

**LICENSE-LOCK stay-out.** This pack never wraps or runs RiskReady. `push_riskready.sh` is review-only even if `RISKREADY_PUSH=1`: no login, no HTTP client, no POST.

Humans review JSON under `out/riskready/`. Never auto-POST `/api/risks`.

## assets.json — review only

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

## incidents.json — review only

Explicit incidents plus every finding with severity `high|critical`.

## evidence.json — review only

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
