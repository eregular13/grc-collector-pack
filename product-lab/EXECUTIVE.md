# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 47):** Nikto file-drop polish. `in/vuln/` now accepts
Nikto text, XML (`niktoscan` / `scandetails`), and JSON (`vulnerabilities`).
Interesting/high only (`/admin`, `/login`, `/.git`, directory indexing).
Missing security-header noise and empty exports invent nothing. Deepen
DEMO NessusClientData `.txt` is not Nikto. Collector stays parse-only —
no nikto subprocess, no live HTTP. Demo `nikto.txt` attaches one extra
finding to existing `http://10.0.0.20`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **243 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. Cycles 44–46 stand.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 71 | 17 | 27 | 72 | true |
| `make farm-lab` | 64 | 71 | 17 | 27 | 72 | true |
| `make farm-toolbin-e2e` | 64 | 72 | 17 | 27 | 72 | true |
| `make dropbox-lab` | 69 | 80 | 17 | 27 | 75 | true |

**Deltas vs cycle 46:** host/farm findings **70→71**, POA&M **71→72**,
evidence **26→27** (demo `nikto.txt` admin-login on existing
`http://10.0.0.20`; X-Frame-Options silent). e2e findings **71→72**.
dropbox findings **79→80**, POA&M **74→75**. Catalog / wrap / compose /
paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
