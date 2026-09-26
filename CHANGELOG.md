# Changelog

## Unreleased

- EXEC_COUNT_RECONCILE: executive page names kind-excluded and
  merged-into aliases so POA&M + (excluded − merged) + kind-excluded
  equals register. Printed sums are the computed totals; a mismatch
  always warns. Headline `open=` / `Open POA&M (poam.csv)` is poam.csv
  (FedRAMP Open #179). Ledger-open including excluded is secondary.
  SAMPLE/DEMO/LAB never client KEEP. No POST `/api/risks`. Does not
  touch `product-lab/drop`.
- CR7_BH_HIGH_VALUE: `bh-high-value` (Administrators / Enterprise
  Admins / Schema Admins) keeps the high-value group playbook and
  AC-2/AC-6. Typed generic falls through to the legacy title map.
  POA&M IDs unchanged (`bh-high-value`). Sample generic fix rows
  return to the pre-#177 count (5). No POST `/api/risks`. Does not
  touch `product-lab/drop`.
- B8_STABLE_CHECK_ID: title-keyed DEMO families (secrets, easm, wazuh
  posture, identity) stamp a stable `extra.check_id` so percentages and
  hostnames in the display title cannot remint EGP IDs. Intune
  encryption compliance uses `enc-compliance-{provider}`; 33.3%→50.0%
  keeps the same fingerprint. `httpx-admin` / `whatweb-admin` /
  `path-exposure-*` keep the #170 path/url location discriminator so
  root vs `/login` stay two items. `_legacy_fps_for` chains
  title→check_id + #172 host-less + #170 `pre_location_*` (#172 first)
  so a 7ebc697 DEMO ledger upgrades with 0 duplicate opens, 1 new
  (#170 split), 127 FedRAMP Open. Vendor fields stay out of `fp_v1`.
  MIN_ gates unchanged. No POST `/api/risks`. Does not touch
  `product-lab/drop`.
- POAM_GAP2_VENDOR_DEPENDENCY: FedRAMP R3.0 Open O/P/Q. Vendor
  Dependency defaults to No (`vd_source=default`); never invents Yes.
  Last Vendor Check-in Date and Vendor Dependent Product Name are blank
  when O=No (never N/A). O=Yes only via `in/poam/overrides.csv`. Operator
  Yes **and** No persist on the ledger across later runs without the
  file (`vd_source=operator`). Any O/P/Q / `vd_source` change updates
  `status_date` and writes a `field_changed` event (spec §3.4 step 3).
  Invalid override tokens (e.g. `Maybe`) warn `VD_INVALID_OVERRIDE`.
  Vendor-dependent Yes stays off the Closed tab (`VD_NOT_CLOSED`). Q
  uses `Vendor – Product`. Scanner "no fix available" is
  suggestion-only. KEV / BOD 22-01 due dates are not suspended.
  `poam.md` states the No default is not a verified determination.
  Vendor fields stay out of `fp_v1`; EGP IDs unchanged. Upgrading a
  pre-#160 ledger backfills No/default as a schema baseline — no
  `field_changed` event and no Status Date (col N) churn. Host-lab
  unchanged (79 / 107 / poam 124 / excluded 5). MIN_ gates unchanged.
  No POST `/api/risks`. Does not touch `product-lab/drop`.
- B6_PLAYBOOKS: unmapped PingCastle RiskIds (A-ZeroPoint, P-SchemaAdmins,
  group-operator rules) fall through to the #145 playbook instead of the
  generic fallback. Mapped ids (SSLv2, P-Delegated, S-NoPreAuth*) stay typed.
- B6_PLAYBOOKS: per-type remediations for Nikto web-app findings, TLS
  side-channels (BREACH / LUCKY13), and PingCastle RiskIds. HOLD remap:
  testssl exact `SSLv2`; PingCastle `P-Delegated` is Protected Users (not
  unconstrained — that is `P-UnconstrainedDelegation`); AS-REP is
  `S-NoPreAuth` / `S-NoPreAuthAdmin`; Nikto PUT/DELETE including 999995;
  no substring TLS/RDP on NextGEN LFI; XSS is output-encoding/CSP;
  `A-DsHeuristicsLDAPSecurity` cites CVE-2021-42291 / KB5008383. Each
  class has a short `source` field. Paraphrase only (PingCastle NPOSL-3.0;
  Nikto DBs All Rights Reserved). No POST `/api/risks`. Does not touch
  `product-lab/drop`.
- LAB_EXCLUDED_HONESTY: lab collectors (`Makefile` / `scripts/lab.sh` /
  `scripts/lab.ps1` / CI lab job) now run `collectors/honeypot.py` so DEMO
  `fixtures/demo/honeypot*` land in `poam/excluded.csv` (not header-only).
  `severity_info` rows keep canonical `severity=info` on excluded.csv — they
  are not labeled `low`. Exec summary counts info as its own bucket, not as
  dropped Lows. CISO `findings.csv` still maps info→low for the importer.
  Farm identity unchanged (findings=174 / poam=106 / excluded=68, of which
  60 severity_info now labeled `info`). Host lab measured assets=79
  findings=107 poam=125 excluded=4 (3 honeypot + 1 superseded_by_specific).
  MIN_ gates unchanged. Not a 12th compose service. No POST `/api/risks`.
  Does not touch `product-lab/drop`.
- PORT_ONLY_FOLD: when a specific finding (nuclei / Nessus / testssl / NSE / CVE)
  already names a host+port, the bare nmap-style "port open" row is folded into
  that finding as evidence (source + `nmap` label/tools) and listed in
  `poam/excluded.csv` as `superseded_by_specific` with the winner's `EGP-` id.
  Winner = highest severity, then lowest EGP- id. Port-only rows with no
  specific peer stay on the POA&M. Count identity holds
  (`weaknesses_total == poam_included + excluded`). Farm_drop measured
  findings=174 / poam=106 / excluded=68 (unchanged). Host lab measured
  weaknesses=125 / poam=124 / excluded=1. MIN_ gates unchanged. No POST
  `/api/risks`. Does not touch `product-lab/drop`.
- RETIRE_RISKREADY_JSON: `grc_loader` no longer writes `out/riskready/`. `summary.json` drops `incidents` / `risks_proposed` (outside count identity). The loopback console reads POA&M / CISO register for open-risk KPIs and `/api/proposed`. `out/simplerisk/poam.csv` starts with the exact header (no `#` preamble), carries the per-row `estate` column, and has sidecar `out/simplerisk/ESTATE.txt`. Never POSTs `/api/risks`. Does not touch `product-lab/drop`.
- EXEC_AND_TRUST_PAGES: one-page exec summary + `SCOPE_AND_TRUST.md` plus fail-closed estate label. Machine-imported CSVs start with the locked importer header (no `#` preamble). CISO/OpenGRC omit an extra `estate` column; POA&M keeps it. Banner lives in the human pages and `out/<sink>/ESTATE.txt`. SAMPLE/DEMO/LAB and any `product-lab/drop` fallback cannot become CLIENT and cannot be suppressed. Missing values print `not recorded`. RiskReady stay-out. No POST `/api/risks`.
- POAM_FEDRAMP_FIELDS: `poam.csv` keeps its first nine columns and appends FedRAMP POA&M R3.0-style fields from existing data: `poam_id` (POAM-<ref_id>), `finding_ref_id`, `controls` (SP 800-53 ids from control_map; blank if unmapped), `weakness_description`, `detector_source` (collector + tool/NSE script), `weakness_source_id`, `original_detection_date` (first-seen > nmap scan time > collected_at, UTC), `scheduled_completion_date` (DEFAULT 30/90/180 by risk; `due` stays blank), `status_date`, `milestones` (3 dated defaults: validate, apply fix, rescan), `original_risk_rating` (Low/Moderate/High/Critical), `point_of_contact` (blank), `cve` (explicit or known alias, e.g. Heartbleed -> CVE-2014-0160). `poam.md` states the dates are defaults. nmap XML findings carry `extra.scan_time`.
- NMAP_NSE_MISCONFIG: `inventory_nmap` now reads NSE `<script>` output from dropped nmap XML (`shared/nmap_nse.py`, parse-only) and emits evidence-backed misconfig findings: anonymous FTP, Redis without auth, HTTP directory listing, deprecated TLS protocols, weak TLS ciphers, self-signed / weak-key certs, SMB signing not required, SMB guest, DB empty password, vendor default creds (http-default-accounts; creds never echoed). `control_map` maps each to a topic-specific control, a non-restating fix with a rescan-to-verify step, real SP 800-53 Rev.5 ids (`nist80053_*`) and CIS v8 safeguards (`cis_*`), CSF by topic (protect), and always POA&M. Existing FTP/Telnet/SMB/RDP/TLS rules gain 800-53 ids. Samba hosts no longer get an inferred Windows C$/ADMIN$ finding. Console coverage counts NIST 800-53 as its own family. LAB fixture: `fixtures/lab-misconfig/` (real nmap 7.95 vs loopback LAB, not client).
- CONSOLE_SINK_FAILCLOSED + ESTATE_WATERMARK (cold CISO review of a84007e): the SAMPLE packaged-sinks pill shows whenever any OpenGRC/Probo sink source is `product-lab/drop` (no longer gated on `estate.lab`). `/export.zip` ships packaged `product-lab/drop` only for LAB runs; non-LAB runs fail closed and IMPORT.md says so. `poam.csv` gains a trailing `estate` column (LAB/SAMPLE/DEMO/UNLABELED, never client; off-list `GRC_ESTATE_LABEL` ignored); `poam.md` opens with an `ESTATE:` banner; CISO `findings.csv`/`assets.csv` carry `estate_<label>` in `filtering_labels` (import headers unchanged) plus `ciso-assistant/ESTATE.txt`; `summary.json.estate`.
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
