# HITL — human attest or refuse

Findings and POA&M are not auto-pushed. A human writes `dropbox/out/HITL.json` (or a named lab file) after reviewing evidence.

## Fields

| Field | Meaning |
| --- | --- |
| `client` | Must match SCOPE `client_legal_name` |
| `attested` | JSON `true` or `false` (not the string `"true"`, not YAML `yes`) |
| `timestamp` | When the review happened |
| `slug` | Engagement slug, e.g. `docker-estate-product` |
| `evidence_label` | `live-byo` (real drop box) or `lab-sim` / `docker-lab` (isolated compose) |
| `reviewer` | Who attested or refused |

## Lab-sim vs paying client

Attesting **lab-sim** is a real workflow: the operator looked at the estate HEAD/POA&M and signed it as a rehearsal.

It does **not** make `client_facing_ready: true`. Docker-sim is not a customer. Brakes that already refuse fixture evidence, mismatched client, unsigned SCOPE, or leftover other-client evidence stay in force. Do not patch them.

Paying-day ready still requires **all** of: signed live-eligible SCOPE, live-byo evidence whose `client` matches, HITL `attested: true` with matching `client`, and `evidence_label` **not** `lab-sim`/`docker-lab`. Reid's first live drop box is that path — not this estate.

## Example — attest lab-sim

```json
{
  "attested": true,
  "client": "Evergreen Docker Estate LLC",
  "reviewer": "Reid Schram",
  "timestamp": "2026-09-05T21:50:00-07:00",
  "slug": "docker-estate-product",
  "evidence_label": "lab-sim"
}
```

## Example — refuse

```json
{
  "attested": false,
  "client": "Evergreen Docker Estate LLC",
  "reviewer": "Reid Schram",
  "timestamp": "2026-09-05T21:50:00-07:00",
  "slug": "docker-estate-product",
  "evidence_label": "lab-sim"
}
```

Named lab copy: `dropbox/HITL.docker-estate.json`. Orchestrator reads `dropbox/out/HITL.json` (or the `--out` dest).
