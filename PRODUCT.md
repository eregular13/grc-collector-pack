# PRODUCT
version: 0.5.0-rc.3
github_branch: ship-0.4.0
github_sha: ef12b7b13d8cfb963f5c910e09869e5c7d01efcf
demo_command: python -m dropbox.product_demo
import_command: python -m dropbox.import_grc --target all --dry-run
live_finding_classes: Cleartext HTTP; Missing HSTS; Missing X-Frame-Options/CSP (mapped as Missing web security headers); Server banner disclosure; Git metadata exposed; Directory listing enabled; Insecure session cookie; Permissive CORS policy; Environment file exposed; Untrusted TLS certificate
pack_mapped: 10
poam_rows_from_estate: 10
client_facing_ready: false
client_ready: CLIENT_READY.md
client_assess: docs/CLIENT_ASSESS.md
why_not_paying_day: docker-sim HITL is attested lab-sim (`blocked_by=lab_sim_not_client_estate`). Estate slug copies `out-estate/` POA&M, not Litware 132/155/9 CISO CSVs. SCOPE.example stays historically closed. No signed live drop box.
ciso_import: docs/IMPORT_CISO.md
opengrc_import: docs/IMPORT_OPENGRC.md (CSV Data Manager; live POST skipped)
probo_import: docs/IMPORT_PROBO.md (addFinding plan; no createRisk)
real_scan_drop: docs/REAL_SCAN_DROP.md
riskready: WRAP_DEAD
buyer_sees_in_30_min: isolated estate :18081/:18082/:18443; live HEAD → mapped POA&M (CPG 2.W / PR.DS-02 / PR.PS-01 / CPG 2.T / PR.DS-10); HITL lab-sim attested; mock sink assets+evidences; zip `engagements/engagement-docker-estate-product-YYYYMMDD.zip` with PRODUCT_RUN.md
still_reid: real signed SCOPE on a drop box; BYO nmap on PATH if they want orchestrator quiet-discover; HITL import of findings/POA&M into real CISO; fill quote hours; do not treat Litware CSVs as this estate
