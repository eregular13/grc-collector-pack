# Executive — evergreen drop-box (this slice)

Reid’s delivery is a **consented drop-box**, not a SaaS scanner and not a RiskReady wrap.

With written consent he places a VM, fills `SCOPE.yaml` (client, attestation hash, window, named internal CIDRs/hosts, named external hosts/domains/IPs), runs **internal** then **external**, and hands CISO Assistant CSVs from this pack.

**This checkout’s `dropbox/SCOPE.yaml` is DEMO.** Empty pack `in/` is still fixture theater until an operator drops real files or runs a consented box.

Labs on this Linux VM (Docker absent), 2026-09-04:

| Run | Assets | Findings | Vulns | Evidence | `demo` |
|---|---|---|---|---|---|
| `make lab` (empty pack `in/` → fixtures) | 62 | 59 | 15 | 10 | true |
| `make dropbox-lab` (fixtures copied into `work/in` + demo overlays + extra SCOPE hosts) | 68 | 69 | 15 | 10 | false |

POA&M this lab: **58** rows (`out/poam/poam.csv`). pytest **80**.

`demo: false` on dropbox-lab means files were in `IN_DIR`, not that this is a client estate. It is still fixtures + demo gnmap/httpx/lynis-host overlays. Orchestrator on this VM is **plan-only** (no Nmap/Nessus): 3 /24 shards from `10.20.30.0/23` + `192.168.10.0/24`, 2 deepen batches of 3, discover workers destroyed.

LICENSE-LOCK: the image does not ship or apt-install Nmap, Nuclei, OpenVAS/GVM, Nessus, Zeek, Wazuh, osquery, PingCastle, Purple Knight, BloodHound, CIS-CAT, HailMary, or RiskReady wrap. Allowlisted host tools (`ss`/`ip`/`curl`/`lynis`) run only when already on PATH and named in SCOPE.

The orchestrator (`python3 -m dropbox orchestrate`) shards internal CIDRs into /24 jobs and batches hosts 2–5 for deepen. If the operator installed Nmap/Nessus on the box and listed them in `allow_tools`, a short-lived worker may run **that shard/batch only**. Without those binaries the farm is plan-only. Never one scanner on a /16. Never download Nessus plugins.

CISO Assistant is the system of record (CSV + optional assets/evidences REST). RiskReady stays review-only JSON. SimpleRisk is leave-behind documentation only.

**Pentera finds it; Evergreen maps it.** High/critical (and key medium, e.g. RDP/SMB exposure) become `applied_controls` plus wizard-safe `cpg_*` / `csf_*` labels and `out/poam/poam.csv`. Example: open TCP/445 is “restrict SMB / confirm SMBv1 is disabled” — a port finding, not a CVE. Owner and due are blank.

Not a paying-day PASS. USB evergreen-assessment was not copied.
