# PLAN — grc-collector-pack

Sensors + normalizer only. No GRC UI. Demo mode: parse `in/<sensor>/` or `fixtures/demo/`. Never live-scan. Never POST `/api/risks`.

Drop-box (`dropbox/`): SCOPE-gated internal/external ingest into `in/`. Orchestrator shards CIDRs (discover → deepen → ingest); BYO Nmap/Nessus only if already on PATH. LICENSE-LOCK forbids shipping/embedding Nmap, Nuclei, OpenVAS, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, RiskReady wrap.

## Graph

PLAN → BUILD hooks + pack → SELF-CHECK → LAB → CRITIC → FIX → REGRESSION LAB → DONE GREEN

## Deliverables

1. Nine collectors parse OSS scanner artifacts into canonical JSONL (`asset|finding|evidence|incident`).
2. `grc-loader` emits CISO Assistant CSVs, RiskReady JSON, OCSF class_uid 2003, `summary.json`, `risks_proposed.json`.
3. Compose: one `python:3.12-slim` image, ten services, loader waits on `service_completed_successfully`.
4. Safety: `CISO_PUSH=0` `RISKREADY_PUSH=0` `GRC_LIVE_SCAN=0` `DRY_RUN=1`. Secrets → `[REDACTED]`. LICENSE-LOCK: RiskReady stay-out — `push_riskready.sh` review-only even if `RISKREADY_PUSH=1`.
5. Lab: pytest + nine collectors + loader + `tests/lab_outputs.py`. Counts ≥20 assets, ≥20 findings, ≥8 evidence.
6. Hostile: truncated JSON, blank Nuclei lines, Nmap without hostnames, double loader (no dupes).

## Collector map

| Service | in/ | Prefix | Notes |
|---|---|---|---|
| cloud-prowler | cloud/*.json | CLD- | Prowler FAIL → findings + OCSF |
| inventory-nmap | nmap/*.xml | NMAP- | hosts PR + exposure findings |
| vuln-scan | vuln/* | VULN- | Nuclei/Trivy/Greenbone → vulns |
| host-wazuh | wazuh/* | WAZ- | coverage gaps + incidents |
| identity-ad | identity/* | ID- | BloodHound/PingCastle → SP |
| easm | easm/* | EASM- | Amass/Subfinder/httpx hosts |
| k8s-kubescape | k8s/* | K8S- | cluster findings |
| code-secrets | code/* | CODE- | secrets/SAST redacted |
| saas-idp | saas/* | SAAS- | ScubaGear/Graph/Okta |
| grc-loader | out/canonical | — | all GRC files |

## STOP rules

DONE.md line 1 GREEN only after two consecutive green labs and critic ≥ 8 with zero P0/P1.
