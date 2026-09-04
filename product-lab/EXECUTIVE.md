# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 51):** sslscan file-drop polish. `in/vuln/` and
`in/easm/` now accept operator-landed sslscan XML (`ssltest`) or text.
Weak/failed only (TLS 1.0, SSLv2/v3, Heartbleed). Empty / TLS 1.2-only
invent nothing. This is **not** testssl JSON. Collector stays parse-only
— no sslscan run, no live TLS. sslscan *invoke* stays BYO. Demo
`sslscan.xml` attaches one TLS 1.0 row to existing `vpn.example.com`
(counted as a vulnerability, like Nessus). Maps to existing TLS POA&M.

**Cycles 49–50 (stand):** SaaS Scuba/Okta file-drop; WhatWeb `--log-json`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **262 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. DEMO ≠ client.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 73 | 19 | 27 | 76 | true |
| `make farm-lab` | 64 | 73 | 19 | 27 | 76 | true |
| `make farm-toolbin-e2e` | 64 | 74 | 19 | 27 | 76 | true |
| `make dropbox-lab` | 69 | 82 | 19 | 27 | 79 | true |

**Deltas vs cycle 50:** host/farm vulns **18→19**, POA&M **75→76** (demo
`sslscan.xml` TLS 1.0 on existing `vpn.example.com`; TLS 1.2 / empty
silent). Findings and assets unchanged. e2e vulns **18→19**, assets still
64. dropbox vulns **18→19**, POA&M **78→79**. Catalog / wrap / compose /
paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
