# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 46):** ffuf / gobuster file-drop polish. `in/easm/` now
accepts ffuf JSON (`results` + status/url) and gobuster `(Status: N)` text.
Interesting paths only (`/admin`, `/login`, `/.git`). 404 and robots invent
nothing. Collector stays parse-only — no live DNS/HTTP, no ffuf/gobuster
subprocess. Demo `ffuf.json` attaches one extra finding to existing
`admin.example.com`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **240 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 70 | 17 | 26 | 71 | true |
| `make farm-lab` | 64 | 70 | 17 | 26 | 71 | true |
| `make farm-toolbin-e2e` | 64 | 71 | 17 | 26 | 71 | true |
| `make dropbox-lab` | 69 | 79 | 17 | 26 | 74 | true |

**Deltas vs cycle 45:** host/farm findings **69→70**, POA&M **70→71**
(demo `ffuf.json` `/admin` 200 on existing `admin.example.com`; robots/404
silent). e2e findings **70→71**. dropbox findings **78→79**, POA&M **73→74**.
Catalog / wrap / compose / paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT. Next leftover:
nikto file-drop under `in/vuln/`.
