# Evidence matrix — assessment lane → `in/<lane>/`

CISO Assistant (`out/ciso-assistant/*.csv`) is the system of record. Each
assessment lane drops files into an existing or stubbed `in/<lane>/` directory.
This pack does not invent a parallel SoR and does not POST RiskReady.

Machine-readable twin: [`evidence_matrix.yaml`](evidence_matrix.yaml)
(aligned with Covey’s upcoming `docs/evidence_matrix.yaml` without blocking on it).

| Assessment | Pack `in/` | What lands | Status |
|---|---|---|---|
| IdP | `in/identity/` + `in/saas/` | BloodHound / PingCastle / HardeningKitty / CIS-CAT / enum4linux-ng; Entra/Okta/Google user-inventory file_drop | exists |
| MDM | `in/wazuh/` + `in/mdm/` | Fleet / osquery / Wazuh / Lynis; Intune/Jamf device inventory (`in/mdm/` is a host-wazuh alias) | exists |
| cloud | `in/cloud/` | Prowler / ScoutSuite / Steampipe / Custodian / ASFF file_drop | exists |
| DNS/email | `in/dns_email/` | SPF/DKIM/DMARC/MX + PEM/crt.sh Seen (Covey `email_dns`) | exists |
| DNS/email EASM | `in/easm/` | Amass / Subfinder / httpx / WhatWeb / ffuf file_drop | exists |
| Covey | `in/nmap/` | pack_drop `assets.jsonl` + `findings.jsonl` + `meta.json` + `evidence/` (also gnmap/XML/masscan/…) | exists — see [COVEY_PACK_DROP.md](COVEY_PACK_DROP.md) |
| VM | `in/vuln/` | OpenVAS/Greenbone / Nuclei / Trivy / Nessus / Nikto / testssl / SARIF **file_drop only** | exists |
| honeypot | `in/honeypot/` | fleet-sensor (Palisade stage 1\|2) **or** Beelzebub pack_drop `events.jsonl` / `sessions.jsonl` / `meta.json` (`honeypot_event.v1`; Beelzebub `stage` is null) | stubbed + fixture — [HONEYPOT_BEELZEBUB.md](HONEYPOT_BEELZEBUB.md) |

Also present (not in the Covey matrix, still Layer C): `in/k8s/`, `in/code/`, `in/saas/`.

## Honesty

- Honeypot stage hits are **deception-sensor evidence / agent-behavior signals**.
  They are not “network compromised” and not a full control failure.
  **Stages are Palisade-only.** Beelzebub is session/cmd/login evidence;
  the parser fails closed with `stage=null` (does not invent trap_id /
  stage-1 / stage-2).
- OpenVAS-class and Nuclei-class are file_drop. This image does not ship those binaries.
- Empty `in/<lane>/` still falls back to `fixtures/demo/<lane>/` for the ten
  compose collectors. Honeypot is **not** a compose service — run
  `python collectors/honeypot.py` only when you want that lane.
- RiskReady wrap stays review-only forever.

## Operator drop

1. Land the export under the `in/<lane>/` directory in the table.
2. Run the matching collector (or `make lab` for the nine + loader).
3. Import `out/ciso-assistant/*.csv`. Do not POST `/api/risks`.
