# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 58):** smbmap file-drop polish. `in/nmap/` now
accepts operator-landed smbmap share tables (`[+] IP:` / Disk +
Permissions). Hosts become assets. READ/WRITE shares become exposure
findings mapped to existing SMB POA&M. Empty / NO ACCESS invent nothing.
Detect does not steal nmap / arp-scan / nbtscan. Collector stays
parse-only — no smbmap/smbclient run, no live SMB, no credentials.
Slot stays `file_drop`. Demo `smbmap.txt` attaches writable C$ to
existing `filesrv.corp.local`.

**Cycle 57 (stands):** nbtscan name/IP file-drop. Assets only. No live
NetBIOS. Detect does not steal arp-scan / netdiscover / fping.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **288 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. DEMO ≠ client.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 76 | 19 | 27 | 79 | true |
| `make farm-lab` | 64 | 76 | 19 | 27 | 79 | true |
| `make farm-toolbin-e2e` | 64 | 77 | 19 | 27 | 79 | true |
| `make dropbox-lab` | 69 | 85 | 19 | 27 | 82 | true |

**Deltas vs cycle 57:** host/farm findings **75→76**, POA&M **78→79**
(demo writable C$ on existing `filesrv.corp.local`; NO ACCESS silent).
Assets unchanged. e2e findings **76→77**, POA&M **78→79**. dropbox
findings **84→85**, POA&M **81→82**. pytest **284→288**. Catalog / wrap /
compose / paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
