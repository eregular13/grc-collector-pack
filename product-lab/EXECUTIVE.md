# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 48):** Nessus `.nessus` file-drop polish. `in/vuln/` now
accepts operator-landed NessusClientData XML (`ReportHost` / `ReportItem`).
High/Critical plus key Medium (SMB 445, RDP 3389, TLS). Info/Low and empty
`Report` invent nothing. Farm DEMO tool-bin `.txt` stubs stay non-Nessus
(e2e assets still 64). Collector stays parse-only — no Nessus API, no
collector nessuscli. nessus *invoke* stays BYO on a consented box. Demo
`demo.nessus` attaches one SMB High (vulnerability row) to existing
`http://10.0.0.20`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **247 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. Nikto cycle 47 stands.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 71 | 18 | 27 | 73 | true |
| `make farm-lab` | 64 | 71 | 18 | 27 | 73 | true |
| `make farm-toolbin-e2e` | 64 | 72 | 18 | 27 | 73 | true |
| `make dropbox-lab` | 69 | 80 | 18 | 27 | 76 | true |

**Deltas vs cycle 47:** host/farm vulns **17→18**, POA&M **72→73** (demo
`demo.nessus` SMB High on existing `http://10.0.0.20`; Info scan-metadata
silent). Findings unchanged (Nessus row is a vulnerability). e2e vulns
**17→18**, assets still 64. dropbox vulns **17→18**, POA&M **75→76**.
Catalog / wrap / compose / paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
