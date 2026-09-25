# Changelog

## Unreleased

- NMAP_NSE_MISCONFIG: `inventory_nmap` now reads NSE `<script>` output from dropped nmap XML (`shared/nmap_nse.py`, parse-only) and emits evidence-backed misconfig findings: anonymous FTP, Redis without auth, HTTP directory listing, deprecated TLS protocols, weak TLS ciphers, self-signed / weak-key certs, SMB signing not required, SMB guest, DB empty password, vendor default creds (http-default-accounts; creds never echoed). `control_map` maps each to a topic-specific control, a non-restating fix with a rescan-to-verify step, real SP 800-53 Rev.5 ids (`nist80053_*`) and CIS v8 safeguards (`cis_*`), CSF by topic (protect), and always POA&M. Existing FTP/Telnet/SMB/RDP/TLS rules gain 800-53 ids. Samba hosts no longer get an inferred Windows C$/ADMIN$ finding. Console coverage counts NIST 800-53 as its own family. LAB fixture: `fixtures/lab-misconfig/` (real nmap 7.95 vs loopback LAB, not client).
- MCP_LAB_DROP_AUTO_HINT: `lab_drop` without work/dest_in auto-hints `LAST_LAB_PROVE` / `lab_out` / `LAB_ESTATE_OUT` (`auto_hint=true` `ran=false`; no re-prove; no seed). Console `python -m product` with `OUT_DIR` unset prefers that stamp. LAB≠SAMPLE≠client. paying_day FAIL. Never POSTs `/api/risks`.
- FARM_LAB_ALIGN: operator note that `farm_drop_to_sor` is the SAMPLE/DEMO fixture seed and `lab_drop_to_sor` is dest_in `--use-existing-in` (no reseed). Both emit risk register + POA&M. SAMPLE dual-net `172.16.10.0/24` is not LAB dest_in `192.168.64.0/24`. LAB != SAMPLE != client. paying_day FAIL. No new public entrypoint.
- Brick 4: cold farm_drop→SoR wipe/clone ship-gate (`farm-drop-to-sor-cold`). Isolated clean checkout + `farm_drop_to_sor` + risk-register/POA&M shape. `FARM_SHIP=yes` only when pack HEAD of that assertion surface changes — identical re-PASS is not a ship event. CI/lab scripts under `scripts/ci/` are not a public operator entrypoint. SAMPLE/DEMO != client. paying_day FAIL.
- Hotfix: `prove_ciso.py --verify-only` and `farm_drop_to_sor` console lines are ASCII (`!=`, not U+2260) so Windows cp1252 (DESKTOP-222GHQV) exits 0. Wrappers set `PYTHONIOENCODING=utf-8`.
- Farm leave-behind operator twin: `scripts/farm_drop_to_sor.sh` / `make farm-drop-to-sor` / `scripts/farm_drop_to_sor.ps1` — Covey `fixtures/pack_drop` → `prove/work/out/ciso-assistant/` via `prove_ciso.py`. Fail-closed if prove JSON claims client estate or `paying_day` PASS. SAMPLE keep remains the primary KEEP path (`sample_to_sor`). SAMPLE/DEMO ≠ client.
- Eval↔pack handoff: `docs/EVAL_PACK_HANDOFF.md` — Eval `DESKTOP-DAY-OF.md` (loopback HITL) → pack `DESKTOP_DRY_RUN.md`. Eval day-of ≠ pack paying_day PASS. SAMPLE keep cannot stamp client-ready.
- Honesty restamp: pack HEAD `9a872ef5` (PR #91 `sample_to_sor` already on master) / farm HEAD `c012dd24` (PR #23 unit-only GHA CI already on main). Eval HEAD `ebaa9f50` (PR #4). Schema seam CLOSED. Integrity PARKED.
- DESKTOP/client-host dry-run: `docs/DESKTOP_DRY_RUN.md` (`DRY_RUN=1` `CISO_PUSH=0`). `python3 -m keep lab --pack-in/--work`.
- Fail-closed: SAMPLE cannot emit `paying_day` PASS (`honest_paying_day`). RiskReady stay-out.
- CI runs SAMPLE keep-lab as a subprocess. Honesty lock follows live pack HEAD `9a872ef5`.
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
