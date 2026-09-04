# Executive brief — grc-collector-pack product lab

**Date:** 2026-09-03 21:45 America/Los_Angeles  
**Subject:** Docker stack on this Windows host is shippable as a **demo file emitter**. It is not a live GRC platform and not `C:\GRC Collector`.

An auditor can reproduce the lab: Docker Desktop 4.89.0 is up; `scripts\lab.ps1` passed **twice** (pytest **39**, 3.0 s, exit 0); `docker compose up --build --exit-code-from grc-loader` passed **twice** (8.1 s / 7.1 s, loader exit 0). Live counts: **62 assets, 59 findings, 15 vulns, 10 evidence**. Unique `ref_id`s match row counts. No process POSTed `/api/risks`.

The product is ten one-shot containers, one image, no published ports. Outputs are CISO Assistant CSVs and RiskReady JSON under `out/` and `product-lab/drop/`. High/critical stay in `risks_proposed.json` on disk.

This checkout has **no mock sink**. `:18080` on the host belongs to another repo and was not used. `in/` is `.gitkeep` only — this is a **demo estate**, not a client. Evidence (10) is thinner than findings (59). A misspelled `OUT_DIR` currently mkdir’s an empty tree instead of failing closed.

**Recommendation:** ship as a collector pack with those labels. Do not market it as a connected GRC or as the larger `C:\GRC Collector` tree (more tests / more assets). Next product work is a sink and real `in/` drops, not more parsers.
