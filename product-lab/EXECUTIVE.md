# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 53):** rustscan / naabu file-drop polish. `in/nmap/`
now accepts operator-landed rustscan / naabu JSON and JSONL (`{ip, port}`
or `{ip, ports:[int]}`). Open ports only. Empty / closed invent nothing.
Collector stays parse-only — no rustscan/naabu run. Invoke slots stay BYO
(`allow_tools` + PATH). Demo `naabu.jsonl` attaches one Telnet 23 exposure
to existing `filesrv.corp.local`. Maps to existing Telnet POA&M.

**Cycle 52 (stands):** masscan `-oX` / `-oJ` file-drop. Slot stays
`file_drop` / `use_dont_ship`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **268 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands. DEMO ≠ client.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 75 | 19 | 27 | 78 | true |
| `make farm-lab` | 64 | 75 | 19 | 27 | 78 | true |
| `make farm-toolbin-e2e` | 64 | 76 | 19 | 27 | 78 | true |
| `make dropbox-lab` | 69 | 84 | 19 | 27 | 81 | true |

**Deltas vs cycle 52:** host/farm findings **74→75**, POA&M **77→78** (demo
`naabu.jsonl` Telnet 23 on existing `filesrv.corp.local`; closed/empty
silent). Assets unchanged. e2e findings **75→76**, assets still 64.
dropbox findings **83→84**, POA&M **80→81**. Catalog / wrap / compose /
paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
