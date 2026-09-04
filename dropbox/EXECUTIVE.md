# Executive — evergreen drop-box (this slice)

Reid’s delivery is a **consented drop-box**, not a SaaS scanner and not a RiskReady wrap.

With written consent he places a VM, fills `SCOPE.yaml` (client, attestation hash, window, named internal CIDRs/hosts, named external hosts/domains/IPs), runs **internal** then **external**, and hands CISO Assistant CSVs from this pack.

**This checkout’s `dropbox/SCOPE.yaml` is DEMO.** Empty pack `in/` is still fixture theater until an operator drops real files or runs a consented box.

Labs on this Linux VM (Docker absent), 2026-09-04:

| Run | Assets | Findings | Vulns | Evidence | `demo` |
|---|---|---|---|---|---|
| `make lab` (empty pack `in/` → fixtures) | 62 | 59 | 15 | 10 | true |
| `make dropbox-lab` (fixtures copied into `work/in` + demo overlays) | 65 | 63 | 15 | 10 | false |

`demo: false` on dropbox-lab means files were in `IN_DIR`, not that this is a client estate. It is still fixtures + demo gnmap/httpx/lynis-host overlays.

LICENSE-LOCK: the image and drop-box do not ship or run Nmap, Nuclei, OpenVAS/GVM, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, or RiskReady wrap. Allowlisted host tools (`ss`/`ip`/`curl`/`lynis`) run only when already on PATH and named in SCOPE.

CISO Assistant is the system of record (CSV + optional assets/evidences REST). RiskReady stays review-only JSON. SimpleRisk is leave-behind documentation only.

Not a paying-day PASS. USB evergreen-assessment was not copied.
