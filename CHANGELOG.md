# Changelog

## Unreleased

- Hotfix: `prove_ciso.py --verify-only` and `farm_drop_to_sor` console lines are ASCII (`!=`, not U+2260) so Windows cp1252 (DESKTOP-222GHQV) exits 0. Wrappers set `PYTHONIOENCODING=utf-8`.
- Farm leave-behind operator twin: `scripts/farm_drop_to_sor.sh` / `make farm-drop-to-sor` / `scripts/farm_drop_to_sor.ps1` — Covey `fixtures/pack_drop` → `prove/work/out/ciso-assistant/` via `prove_ciso.py`. Fail-closed if prove JSON claims client estate or `paying_day` PASS. SAMPLE keep remains the primary KEEP path (`sample_to_sor`). SAMPLE/DEMO ≠ client.
- Eval↔pack handoff: `docs/EVAL_PACK_HANDOFF.md` — Eval `DESKTOP-DAY-OF.md` (loopback HITL) → pack `DESKTOP_DRY_RUN.md`. Eval day-of ≠ pack paying_day PASS. SAMPLE keep cannot stamp client-ready.
- Honesty restamp: pack HEAD `37386693` (PR #95 farm_drop cp1252 + PR #94 `farm_drop_to_sor` already on master) / farm HEAD `20e4f8c0` (PR #24 `client_day_dry` already on main; PR #23 unit-only GHA CI already on main). Eval HEAD `e04c2d88` (PR #5 Node 20/22 LTS + `sample_to_sor` pointer). Schema seam CLOSED. Integrity PARKED.
- DESKTOP/client-host dry-run: `docs/DESKTOP_DRY_RUN.md` (`DRY_RUN=1` `CISO_PUSH=0`). `python3 -m keep lab --pack-in/--work`.
- Fail-closed: SAMPLE cannot emit `paying_day` PASS (`honest_paying_day`). RiskReady stay-out.
- CI runs SAMPLE keep-lab as a subprocess. Honesty lock follows live pack HEAD `37386693`.
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
