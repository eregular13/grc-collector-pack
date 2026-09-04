# Changelog

## 0.4.0 — 2026-09-03

Assessment engine brakes.

- RiskReady wrap killed fail-closed (no login/POST even if PUSH=1).
- `dropbox/` SCOPE + orchestrator plan/run (quiet → destroy → deepen 2–5 → ingest).
- BYO nmap/nessus adapters; plan-only and fixture path without binaries.
- POA&M export + CPG/CSF stubs; SMBv1 golden fixture.
- NOTICE: Nmap use-don't-ship; RiskReady stay-out.

## 0.3.0 — 2026-09-03

Public-repo hardening.

- CI: `.github/workflows/lab.yml` (pytest + collectors + `lab_outputs.py` on Python 3.12).
- `SECURITY.md`: localhost console, dual-gate push, GitHub Security Advisory.
- Bind lock: `GRC_PRODUCT_HOST` must be loopback (`127.0.0.1` / `localhost` / `::1`). `0.0.0.0` exits 2.
- HTTP 500 on refresh no longer returns a traceback.
- `OUT_DIR` unset or missing parent fails closed.
- Evidence floor raised to ≥ 18 (sensor run + high/critical family attestations). See `docs/EVIDENCE.md`.
- Import preview: `scripts/preview_probo.py`, `scripts/preview_rr.py`, `docs/IMPORT_*.md`.
- Customer clone notes: `docs/PUBLIC_CLONE.md`, `docs/CANONICAL_TREE.md`.
