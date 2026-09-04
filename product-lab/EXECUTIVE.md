# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 50):** WhatWeb file-drop polish. `in/easm/` now
accepts operator-landed WhatWeb `--log-json` (`target` + `plugins`).
Admin/login only. Empty / Home invent nothing. Collector stays parse-only
— no whatweb run, no live HTTP. whatweb stays file_drop. Demo
`whatweb.json` attaches one admin-login high to existing
`admin.example.com`. Admin UI maps to existing CISO/POA&M.

**Cycle 49 (stands):** SaaS file-drop polish. ScubaGear / Okta / Maester /
Graph exports under `in/saas/`. Failed/high only. No Graph or Okta API.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **258 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. SaaS cycle 49 stands.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 73 | 18 | 27 | 75 | true |
| `make farm-lab` | 64 | 73 | 18 | 27 | 75 | true |
| `make farm-toolbin-e2e` | 64 | 74 | 18 | 27 | 75 | true |
| `make dropbox-lab` | 69 | 82 | 18 | 27 | 78 | true |

**Deltas vs cycle 49:** host/farm findings **72→73**, POA&M **74→75** (demo
`whatweb.json` admin-login on existing `admin.example.com`; Home silent).
Assets unchanged. e2e findings **73→74**, assets still 64. dropbox
findings **81→82**, POA&M **77→78**. Catalog / wrap / compose / paying-day
unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
