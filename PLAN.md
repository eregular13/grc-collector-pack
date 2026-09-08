# PLAN — grc-collector-pack

Sensors + normalizer only. No GRC UI. Demo mode: parse `in/<sensor>/` or `fixtures/demo/`. Never live-scan. Never POST `/api/risks`.

Drop-box (`dropbox/`): three layers — A BYO tool zoo under SCOPE (`farm/` private catalog 95+ slots + adapters; PATH / bind-mount / Reid’s tags; not Hub soup), B orchestrator brakes (plan → shard → quiet discover → destroy → gated deepen → destroy → external plan-only → ingest → grc_export), C 11 containers parse-only. Orchestrator does not turn collectors into scanners. Hexstrike-pattern operator MCP stub only (no vendor, no exploit API). `stages.deepen` fail-closed unless true. BYO Nmap/Nessus only if already on PATH. LICENSE-LOCK forbids shipping/embedding Nmap, Nuclei, OpenVAS, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, RiskReady wrap.

## Graph

PLAN → BUILD hooks + pack → SELF-CHECK → LAB → CRITIC → FIX → REGRESSION LAB → DONE GREEN

## Deliverables

1. Nine collectors parse OSS scanner artifacts into canonical JSONL (`asset|finding|evidence|incident`).
2. `grc-loader` emits CISO Assistant CSVs, RiskReady JSON, OCSF class_uid 2003, `summary.json`, `risks_proposed.json`, and `out/poam/poam.csv` (CPG/CSF map; owner/due blank).
3. Compose: one `python:3.12-slim` image, ten services, loader waits on `service_completed_successfully`.
4. Safety: `CISO_PUSH=0` `RISKREADY_PUSH=0` `GRC_LIVE_SCAN=0` `DRY_RUN=1`. Secrets → `[REDACTED]`. LICENSE-LOCK: RiskReady stay-out — `push_riskready.sh` review-only even if `RISKREADY_PUSH=1`.
5. Lab: pytest + ten collectors + loader + `tests/lab_outputs.py`. Counts ≥20 assets, ≥20 findings, ≥8 evidence.
6. Hostile: truncated JSON, blank Nuclei lines, Nmap without hostnames, double loader (no dupes).

## Collector map

| Service | in/ | Prefix | Notes |
|---|---|---|---|
| cloud-prowler | cloud/*.json | CLD- | Prowler FAIL → findings + OCSF |
| inventory-nmap | nmap/*.xml | NMAP- | hosts PR + exposure findings |
| vuln-scan | vuln/* | VULN- | Nuclei/Trivy/Greenbone/SARIF → vulns |
| host-wazuh | wazuh/* | WAZ- | coverage gaps + incidents |
| identity-ad | identity/* | ID- | BloodHound/PingCastle → SP |
| easm | easm/* | EASM- | Amass/Subfinder/httpx hosts |
| k8s-kubescape | k8s/* | K8S- | cluster findings |
| code-secrets | code/* | CODE- | secrets/SAST/SARIF redacted |
| saas-idp | saas/* | SAAS- | ScubaGear/Graph/Okta |
| honeypot (stub, not a compose service) | honeypot/* | HPOT- | fleet-sensor events; deception-sensor evidence, not compromise |
| dns-email | dns_email/* | DNS- | SPF/DKIM/DMARC/MX/cert Seen (file_drop) |
| grc-loader | out/canonical | — | all GRC files |

## This window (2026-09-08)

Cycle **93** (this brick): CoS prove bar — fixture file_drop → collector → `out/canonical` (SAMPLE ≠ client). Cycle **91** (master): Honeypot file_drop lane + Covey pack_drop on existing `in/nmap/` + evidence matrix. Not a compose service. Cycle **92**: Email/DNS Seen collector (`in/dns_email/`, Covey `email_dns` lane). File-drop SPF/DKIM/DMARC/MX + optional PEM/crt.sh. Missing DMARC = control gap, not a breach. Live DNS only behind `--live` + signed SCOPE allowlist. Catalog **not inflated** (`dig` remapped to `in/dns_email/`). Compose is 11 services (10 collectors + loader); honeypot stays an optional stub. Cycle **90** honesty next_action sync stands. Cycle **89** DESKTOP SCOPE attestation stands. keep-lab uses redacted samples until Reid drops real KEEP into pack `in/` (0/4 real still open). Remaining Reid-only blockers (CTA, Eval npm start, real KEEP in/ drop, compose-on-Docker) stay open. File-drop remains the default. LICENSE-LOCK / BloodHound / Nuclei-class never `will_run=true`. File-drop-only names never `live_ready`. `FARM_TOOL_BIN` never resolves locked scanners. `SCOPE.example.yaml` does not default-allowlist nmap/nessus. No slot inflation. No live probes from collectors. No fake compose pass. Paying-day stays FAIL. Compose ABSENT until proven on a Docker host. Wrap dead forever. DEMO ≠ client. SAMPLE ≠ client KEEP. Hexstrike pattern-only.

## STOP rules

DONE.md line 1 GREEN only after two consecutive green labs and critic ≥ 8 with zero P0/P1.
