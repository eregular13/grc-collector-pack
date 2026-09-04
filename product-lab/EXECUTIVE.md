# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 55):** fping file-drop polish. `in/nmap/` now accepts
operator-landed fping text and JSON (`host is alive` /
`{ip, hostname, alive}`). Alive hosts become assets only. Unreachable /
empty invent nothing. Collector stays parse-only — no fping run, no live
ping. Slot stays `file_drop`. Demo `fping.txt` attaches to existing
`filesrv.corp.local` (no new findings).

**Cycle 54 (stands):** arp-scan text/JSON file-drop. Hosts become assets
only. No live ARP. Slot stays `file_drop`. Demo `arp-scan.txt` attaches
MAC/vendor to existing `filesrv.corp.local`.

**Cycle 53 (stands):** rustscan / naabu JSON/JSONL file-drop. Open ports
only. Invoke slots stay BYO.

**Cycle 52 (stands):** masscan `-oX` / `-oJ` file-drop. Slot stays
`file_drop` / `use_dont_ship`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **276 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. DEMO ≠ client.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 75 | 19 | 27 | 78 | true |
| `make farm-lab` | 64 | 75 | 19 | 27 | 78 | true |
| `make farm-toolbin-e2e` | 64 | 76 | 19 | 27 | 78 | true |
| `make dropbox-lab` | 69 | 84 | 19 | 27 | 81 | true |

**Deltas vs cycle 54:** counts unchanged (demo attaches alive host to
existing `filesrv.corp.local`; unreachable/empty silent). pytest
**272→276**. Catalog / wrap / compose / paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
