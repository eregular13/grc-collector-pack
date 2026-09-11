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
| host-wazuh | wazuh/* + mdm/* | WAZ- | coverage gaps + Intune/Jamf inventory |
| identity-ad | identity/* | ID- | BloodHound/PingCastle → SP |
| easm | easm/* | EASM- | Amass/Subfinder/httpx hosts |
| k8s-kubescape | k8s/* | K8S- | cluster findings |
| code-secrets | code/* | CODE- | secrets/SAST/SARIF redacted |
| saas-idp | saas/* | SAAS- | ScubaGear/Graph/Okta + Entra/Okta/Google user inventory |
| honeypot (stub, not a compose service) | honeypot/* | HPOT- | Palisade fleet-sensor stage 1\|2 **or** Beelzebub session/cmd/login (stage null); deception-sensor evidence, not compromise |
| dns-email | dns_email/* | DNS- | SPF/DKIM/DMARC/MX/cert Seen (file_drop) |
| grc-loader | out/canonical | — | all GRC files |

## This window (2026-09-11)

Cycle **162**: CoS #44 honesty sync. Pack HEAD `8c442a33` (PR #77 service→host refs already on master). Item **COS44-HONESTY**. Covey HEAD still `30d2197f` multi-adapter `pack_drop` export for all 16 `E2E_PROVEN`. Item **COS43-PACK-DROP-SERVICE-HOST-REFS-LOCK** = DONE. 16 E2E_PROVEN pack_drop void CLOSED. Next brick named = global `pack_drop` observation/finding port→service (or nested asset ports) referential lock. SAMPLE_BANNER / prove_ciso sixteen-set includes unicornscan (joined from `E2E_PROVEN_PACK_DROP_ADAPTERS`). Stop for CoS #45. 20-adapter lane **CLOSED** stands. STATUS `next_action` is current truth — Covey `E2E_PROVEN` sixteen-set remains: nmap + rustscan + fping + naabu + nping + httpx + sslscan + tlsx + whatweb + hping3 + onesixtyone + nbtscan + braa + ike-scan + svmap + unicornscan. UNPROVEN fail-closed: masscan, arp-scan, netdiscover, zmap — do not claim a 17th live. Pack does not start Covey adapter work. Reid-only blockers remain CTA, real KEEP `in/` drop, Eval `npm start`, Docker compose on a real host (this VM `compose_lab` absent ≠ PASS). Pytest locks STATUS `next_action` and PLAN this-window so they cannot lag CoS #44 / pack HEAD `8c442a33` / Covey HEAD `30d2197f` (must name all sixteen: nmap, rustscan, fping, naabu, nping, httpx, sslscan, tlsx, whatweb, hping3, onesixtyone, nbtscan, braa, ike-scan, svmap, unicornscan) and so `compose_lab` absent cannot flip to pass. Cycle **161** service→host lock stands as history. Cycle **160** honesty stands as history. Cycle **159** kind-partition lock stands as history. Cycle **158** honesty stands as history. Cycle **157** JSONL row schema identity lock stands as history. Cycle **156** honesty stands as history. Cycle **155** meta.json schema + adapter identity lock stands as history. Cycle **154** honesty stands as history. Cycle **153** observation→asset refs lock stands as history. Cycle **152** honesty stands as history. Cycle **151** asset-id lock stands as history. Cycle **150** honesty stands as history. Cycle **149** observation-id uniqueness lock stands as history. Cycle **148** honesty stands as history. Cycle **147** claim-class + DEMO-label lock stands as history. Cycle **146** honesty stands as history. Cycle **145** all-16 fixture inventory lock stands as history. Cycle **144** honesty stands as history. Cycle **143** svmap pack_drop→CISO prove stands as history. Cycle **142** honesty stands as history. Cycle **141** ike-scan pack_drop→CISO prove stands as history. Cycle **140** honesty stands as history. Cycle **139** braa pack_drop→CISO prove stands as history. Cycle **138** COS32 honesty stands as history. Cycle **137** nbtscan pack_drop→CISO prove stands as history. Cycle **136** COS31 honesty stands as history. Cycle **135** nping pack_drop→CISO prove stands as history. Cycle **134** COS30 honesty stands as history. Cycle **133** naabu pack_drop→CISO prove stands as history. Cycle **132** COS29 honesty stands as history. Cycle **131** fping pack_drop→CISO prove stands as history. Cycle **130** CoS #28 honesty stands as history. Cycle **129** onesixtyone pack_drop→CISO prove stands as history. Cycle **128** CoS #27 honesty stands as history. Cycle **127** hping3 pack_drop→CISO prove stands as history. Cycle **126** CoS #26 honesty stands as history. Cycle **125** whatweb pack_drop→CISO prove stands as history. Cycle **124** CoS #25 honesty stands as history. Cycle **123** tlsx pack_drop→CISO prove stands as history. Cycle **122** CoS #24 honesty stands as history. Cycle **121** sslscan pack_drop→CISO prove stands as history. Cycle **120** CoS #23 honesty stands as history. Cycle **119** unicornscan pack_drop→CISO prove stands as history. Cycle **118** CoS #22 honesty stands as history. Cycle **117** httpx pack_drop→CISO prove stands as history. Cycle **116** CoS #21 honesty stands as history. Cycle **115** rustscan pack_drop→CISO prove stands as history. Cycle **114** CoS #20 honesty stands as history. Cycle **113** CoS #19 stands as history. Cycle **112** CoS #18 stands as history. Cycle **111** CoS #17 stands as history. Cycle **110** CoS #16 stands as history. Cycle **109** CoS #15 stands as history. Cycle **108** CoS #14 stands as history. Cycle **107** CoS #13 stands as history. Cycle **106** CoS #12 stands as history. Cycle **105** CoS #11 stands as history. Cycle **104** CoS #10 stands as history. Cycle **103** CoS #9 stands as history. Cycle **102** CoS #8 stands as history. Cycle **101** CoS #7 stands as history. Cycle **100** CoS #6 stands as history. Cycle **99** CoS #5 stands. Cycle **98** CoS #4 stands. Cycle **97** CoS #3 stands. Cycle **96** CISO prove stands. Cycle **95** Beelzebub stands. Cycle **94** IdP/MDM stands. Cycle **93** DNS/email CoS prove bar stands. **Stop vanity Layer C parsers.** keep-lab uses redacted samples until Reid drops real KEEP into pack `in/` (0/4 real still open). Remaining work is Reid-only — not catalog inflation. File-drop remains the default. LICENSE-LOCK / BloodHound / Nuclei-class never `will_run=true`. File-drop-only names never `live_ready`. `FARM_TOOL_BIN` never resolves locked scanners. `SCOPE.example.yaml` does not default-allowlist nmap/nessus. nmap/nessus invoke only when SCOPE.allow_tools + stage + PATH + HITL. No slot inflation. No live probes. No fake compose pass. Paying-day stays FAIL. Compose ABSENT until proven on a Docker host. Wrap dead forever (review-only; no login/POST). DEMO ≠ client. SAMPLE ≠ client KEEP. pytest greens are not a paying-day stamp. Hexstrike pattern-only. MCP stub is not USB `evergreen_assessment_mcp` (`dropbox.mcp_stub` = conductor only). `argus_pack_truth` stays `evergreen_assessment_mcp` only.

## STOP rules

DONE.md line 1 GREEN only after two consecutive green labs and critic ≥ 8 with zero P0/P1.
