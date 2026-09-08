# PRODUCT_RUN — docker-estate-product

Isolated Docker estate. Not a client LAN. Not cycle 11. Not a paying client.

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
$env:DRY_RUN = "1"; $env:CISO_PUSH = "0"; $env:RISKREADY_PUSH = "0"; $env:GRC_LIVE_SCAN = "0"
python -m dropbox.product_demo --help
python -m dropbox.product_demo
```

web: http://127.0.0.1:18081/
api: http://127.0.0.1:18082/
pack_mapped: 9
poam_rows: 9
ingest_label: live-byo
client_facing_ready: False
blocked_by: lab_sim_not_client_estate
hitl_attested: True evidence_label=lab-sim
sink: not posted from pack Litware CSVs (see docs/OUT_DIR.md)
mock_push: skipped
zip: C:\GRC Collector\grc-collector-pack\engagements\engagement-docker-estate-product-20260908.zip
kit_facing: False
kit_blocked_by: lab_sim_not_client_estate
kit_evidence_label: lab-sim

Findings/POA&M stay HITL. Risks API is WRAP_DEAD (no POST). WRAP_DEAD.
