# First live drop-box checklist (Reid only — do not run from this lab)

This file is a power-on list. **Grok Build must not execute it** on `C:\GRC Collector`.

1. Written authorization sheet. Named contact. Window start/end.
2. Copy `dropbox/SCOPE.example.yaml` → a **new** SCOPE. Fill:
   - `client_legal_name`, `named_contact` (blank contact is unsigned)
   - `consent_attested: true` (lowercase `true` only — `yes`/`True` do not attest)
   - named CIDRs/hosts/URLs only (no neighbor ranges, no `/16`-class prefixes)
   - `allow_tools` explicit
   - `integrity.allow_live_exec: true` (lowercase `true` only)
3. On the drop box PATH: only scanners Reid installed. Pack never downloads nmap/nessus/nuclei.
4. `$env:EVERGREEN_ORCH_LIVE = "1"` (not `true`).
5. Leftover-estate: if `dropbox/out/discover.json` is another client, deepen/ingest **exit 2** / ignore. Do not reuse Litware lab leftovers.
6. USB KEEP / evergreen-assessment tree stays **off** this checkout.
7. HITL: `dropbox/out/HITL.json` attested with matching `client` **after** live-byo evidence. Fixture evidence cannot be client-facing.
8. Quote hours stay blank until Reid fills them. RiskReady WRAP_DEAD. CISO auto-push is assets+evidences only.

If any brake fires, stop. Integrity over coverage ego.
