# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 49):** SaaS file-drop polish. `in/saas/` now
accepts operator-landed ScubaGear / Okta / Maester / Graph exports
(`Results`, wrappers, JSONL). Failed/high only. Pass / Skip / empty
invent nothing. Collector stays parse-only — no Graph API, no Okta API.
scuba / okta-logs stay file_drop. Maester *invoke* stays BYO on a
consented box. Demo `scuba-wrap.json` attaches one MFA high to existing
`contoso.onmicrosoft.com`. MFA and standing Global Administrator map to
existing CISO/POA&M.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **255 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. Nessus cycle 48 stands.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 72 | 18 | 27 | 74 | true |
| `make farm-lab` | 64 | 72 | 18 | 27 | 74 | true |
| `make farm-toolbin-e2e` | 64 | 73 | 18 | 27 | 74 | true |
| `make dropbox-lab` | 69 | 81 | 18 | 27 | 77 | true |

**Deltas vs cycle 48:** host/farm findings **71→72**, POA&M **73→74** (demo
`scuba-wrap.json` MFA high on existing `contoso.onmicrosoft.com`; Pass/empty
silent). Assets unchanged. e2e findings **72→73**, assets still 64. dropbox
findings **80→81**, POA&M **76→77**. Catalog / wrap / compose / paying-day
unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
