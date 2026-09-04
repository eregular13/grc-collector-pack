# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 52):** masscan file-drop polish. `in/nmap/` now
accepts operator-landed masscan `-oX` XML and `-oJ` JSON. Open ports
only. Empty invents nothing. Collector stays parse-only — no masscan
run. Catalog slot stays `file_drop` / `use_dont_ship`. Demo
`masscan.xml` attaches one RDP 3389 exposure to existing
`filesrv.corp.local`. Maps to existing RDP POA&M.

**Cycle 51 (stands):** sslscan XML/text file-drop. Weak/failed TLS only.
Not testssl JSON. No live sslscan.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **265 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. DEMO ≠ client.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 74 | 19 | 27 | 77 | true |
| `make farm-lab` | 64 | 74 | 19 | 27 | 77 | true |
| `make farm-toolbin-e2e` | 64 | 75 | 19 | 27 | 77 | true |
| `make dropbox-lab` | 69 | 83 | 19 | 27 | 80 | true |

**Deltas vs cycle 51:** host/farm findings **73→74**, POA&M **76→77** (demo
`masscan.xml` RDP 3389 on existing `filesrv.corp.local`; empty/closed
silent). Assets unchanged. e2e findings **74→75**, assets still 64.
dropbox findings **82→83**, POA&M **79→80**. Catalog / wrap / compose /
paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
