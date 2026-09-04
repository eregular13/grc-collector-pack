# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 54):** arp-scan file-drop polish. `in/nmap/` now
accepts operator-landed arp-scan text and JSON (`Starting arp-scan` /
IP + MAC + vendor, or `{ip, mac, vendor}`). Hosts become assets only.
Empty / header-only invent nothing. Collector stays parse-only — no
arp-scan run, no live ARP. Slot stays `file_drop`. Demo `arp-scan.txt`
attaches MAC/vendor to existing `filesrv.corp.local` (no new findings).

**Cycle 53 (stands):** rustscan / naabu JSON/JSONL file-drop. Open ports
only. Invoke slots stay BYO.

**Cycle 52 (stands):** masscan `-oX` / `-oJ` file-drop. Slot stays
`file_drop` / `use_dont_ship`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **272 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. DEMO ≠ client.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 75 | 19 | 27 | 78 | true |
| `make farm-lab` | 64 | 75 | 19 | 27 | 78 | true |
| `make farm-toolbin-e2e` | 64 | 76 | 19 | 27 | 78 | true |
| `make dropbox-lab` | 69 | 84 | 19 | 27 | 81 | true |

**Deltas vs cycle 53:** counts unchanged (demo attaches MAC/vendor to
existing `filesrv.corp.local`; empty/header-only silent). pytest
**268→272**. Catalog / wrap / compose / paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
