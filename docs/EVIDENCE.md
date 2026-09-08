# Evidence rows

An evidence row in `out/ciso-assistant/evidences.csv` and `out/riskready/evidence.json` is a **sensor-run attestation**, not a screenshot dump.

Each lab emits:

1. One row per collector that produced canonical records (`{source} collector run`).
2. One row per high/critical **family** (`source` + category/service/check) derived from existing findings. Descriptions list `ref_id`s and point at `out/canonical`. No new assets. No fake screenshots. No secrets.
3. One `grc-loader run` row for the normalize pass.

Names are unique. Floor after this pack: **≥ 18** evidence rows. That is still thinner than findings; it is enough to show which sensor and family produced the high/critical set.

Import these as CISO evidences or RiskReady `TECHNICAL` / `SENSOR` / `DRAFT` evidence. A human attaches screenshots later if the GRC requires them.

Assessment lane → `in/<lane>/` map: [EVIDENCE_MATRIX.md](EVIDENCE_MATRIX.md).
Covey pack_drop on the nmap lane: [COVEY_PACK_DROP.md](COVEY_PACK_DROP.md).
Email / DNS (`in/dns_email/`) is the pack **Seen** twin of Covey lane `email_dns`.
Missing DMARC is a control-gap candidate. A TXT record is not mailbox proof
and not a breach. See [DNS_EMAIL.md](DNS_EMAIL.md).

## IdP / MDM evidence matrix

High/critical families from file-drop identity and endpoint inventory land as
`{source} {family} high-critical attestation` rows. Finding text is assessment
language (not a breach). No live Graph / Okta / Jamf / osquery.

| Drop | Sensor | Family | Typical finding | Operator path |
|---|---|---|---|---|
| Entra users JSON/CSV | saas-idp | identity-gap | MFA not registered; standing Global Administrator; stale guest | `in/saas/` (`entra-export` / `graph-export`) |
| Okta users JSON | saas-idp | identity-gap | Privileged MFA gap; stale guest | `in/saas/` (`okta-logs`) |
| Google Workspace CSV | saas-idp | identity-gap | Admin 2SV gap; stale guest | `in/saas/` (`entra-export` glob) |
| Graph `directoryRoles` | saas-idp | identity-gap | Entra Global Administrator via Graph | `in/saas/` (`graph-export`) |
| Intune `managedDevices` | host-wazuh | host-posture / coverage-gap | encryption compliance %; disk encryption off; missing EDR; MDM unenrolled | `in/mdm/` or `in/wazuh/` |
| Jamf `computers` | host-wazuh | host-posture / coverage-gap | FileVault / encryption %; missing EDR; MDM unenrolled | `in/mdm/` or `in/wazuh/` |
| Fleet hosts/policies | host-wazuh | host-posture / coverage-gap | disk encryption off; MDM enrollment Off; offline coverage | `in/wazuh/` |

Demo fixtures: `fixtures/demo/saas/entra-users.json`, `okta-users.json`,
`google-users.csv`; `fixtures/demo/mdm/intune-devices.json`,
`jamf-computers.json`. Empty `in/` still loads them. See
`schemas/graph-readonly.stub.json` for a future read-only Graph GET stub —
not required to prove this path. **SAMPLE ≠ client.**

## DESKTOP / prove bar (IdP + MDM)

File_drop fixture → detect → `out/canonical` (or a Seen/attestation evidence row).
No live Graph. No osquery wrap. No RiskReady POST.

```text
# from repo root; empty pack in/ falls back to fixtures/demo (SAMPLE ≠ client)
python collectors/saas_idp.py
python collectors/host_wazuh.py
# prove: IdP MFA/GA/guest and MDM encryption/EDR/enrollment rows
rg -n "MFA not registered|Standing Global Administrator|Stale guest|encryption compliance|Missing EDR|MDM enrollment" out/canonical/*.jsonl
```

Operator drop on a real estate: land Entra/Okta/Google under `in/saas/`,
Intune/Jamf under `in/mdm/` (or `in/wazuh/`), then re-run those two collectors.
Fixtures prove the parser; they are not a client KEEP.
>>>>>>> f54e3cf (Add file-drop IdP and MDM inventory intake.)
