# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 56):** netdiscover file-drop polish. `in/nmap/` now
accepts operator-landed netdiscover text (`Currently scanning` /
IP + MAC + Count + Len + vendor). Hosts become assets only. Empty /
header-only invent nothing. arp-scan detect does not claim netdiscover
tables. Collector stays parse-only — no netdiscover run, no live ARP.
Slot stays `file_drop`. Demo `netdiscover.txt` attaches MAC/vendor to
existing `filesrv.corp.local` (no new findings).

**Cycle 55 (stands):** fping text/JSON file-drop. Alive hosts become
assets only. No live ping. Slot stays `file_drop`.

**Cycle 54 (stands):** arp-scan text/JSON file-drop. Hosts become assets
only. No live ARP. Slot stays `file_drop`.

**Cycle 53 (stands):** rustscan / naabu JSON/JSONL file-drop. Open ports
only. Invoke slots stay BYO.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **280 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. DEMO ≠ client.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 75 | 19 | 27 | 78 | true |
| `make farm-lab` | 64 | 75 | 19 | 27 | 78 | true |
| `make farm-toolbin-e2e` | 64 | 76 | 19 | 27 | 78 | true |
| `make dropbox-lab` | 69 | 84 | 19 | 27 | 81 | true |

**Deltas vs cycle 55:** counts unchanged (demo attaches MAC/vendor to
existing `filesrv.corp.local`; empty/header-only silent). pytest
**276→280**. Catalog / wrap / compose / paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
