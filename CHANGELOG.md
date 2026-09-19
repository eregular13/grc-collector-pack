# Changelog

## Unreleased

- DESKTOP/client-host dry-run: `docs/DESKTOP_DRY_RUN.md` (`DRY_RUN=1` `CISO_PUSH=0`). `python3 -m keep lab --pack-in/--work`.
- Fail-closed: SAMPLE cannot emit `paying_day` PASS (`honest_paying_day`). RiskReady stay-out.
- Honesty restamp: pack HEAD `7c9c56a5` / Covey HEAD `3cf8bb86` (PR #22 pack_drop schema align). Schema seam CLOSED. Integrity PARKED.
- CI runs SAMPLE keep-lab as a subprocess. Honesty lock follows live pack HEAD `7c9c56a5`.
- OpenGRC Data Manager CSV exporter and Probo `addRisk` / `addFinding` drafts from the CISO intermediate (`python3 -m exporters`). File-only. `posted=false`. RiskReady stay-out.
- SAMPLE keep-lab writes those sinks from `keep/work/out/ciso-assistant` (`demo: true`). Do not wait for denser KEEP.

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
