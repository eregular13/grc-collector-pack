# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 44):** EASM file-drop polish. `in/easm/` now accepts
httpx / amass / subfinder JSON arrays and `{results|hosts|data|subdomains}`
wrappers (plus existing JSONL / text). Failed httpx rows (`failed:true`) and
empty `[]` / `{results:[]}` invent nothing. Sensitive prefixes (`vpn.` /
`dev-api.` / `admin.`) and admin-login titles map to dedicated POA&M
controls. Collector stays parse-only — no live `amass enum` / `httpx` /
`subfinder`. Demo `httpx.json` attaches one extra finding to existing
`admin.example.com`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **229 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 68 | 17 | 25 | 69 | true |
| `make farm-lab` | 64 | 68 | 17 | 25 | 69 | true |
| `make farm-toolbin-e2e` | 64 | 69 | 17 | 25 | 69 | true |
| `make dropbox-lab` | 69 | 77 | 17 | 25 | 72 | true |

**Deltas vs cycle 43:** host/farm findings **67→68**, POA&M **68→69**
(demo `httpx.json` admin-login on existing `admin.example.com`; failed vpn
row silent). e2e findings **68→69**. dropbox findings **76→77**, POA&M **71→72**.
Catalog / wrap / compose / paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
