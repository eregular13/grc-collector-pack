# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 63):** zmap/unicornscan file-drop polish. `in/nmap/`
now accepts operator-landed zmap JSON/CSV/text and unicornscan text.
Open ports only. Empty/closed/RST invent nothing. Detect does not steal
nmap / smbmap / arp / naabu. Slots stay `file_drop`. Demo attaches FTP/21
to existing `filesrv.corp.local`. No zmap/unicornscan run. No catalog
growth. Paying-day **FAIL**. Compose **ABSENT**.

**LICENSE-LOCK rail (Metis, reconfirmed this pass):** BloodHound / Nuclei /
OpenVAS / GVM / PingCastle / exploit-class / zmap / unicornscan /
enum4linux-ng / smbmap **never** appear in invoke `will_run=true` even
when every slot is allowlisted and on PATH. nmap/nessus invoke only when
explicitly in SCOPE.allow_tools AND stages.deepen/discover enabled AND
binary on PATH/FARM_TOOL_BIN.

**Cycle 62 (stands):** MCP stub honesty. `dropbox.mcp_stub` is
conductor UX for this Python pack — not USB `evergreen_assessment_mcp`,
not FastMCP, not a TypeScript refuse matrix, not paying-day truth.
No new Layer C parser. Catalog unchanged. Paying-day **FAIL**.
Compose **ABSENT**.

**Cycle 61 (stands):** wrap-dead farm SOP. RiskReady wrap stays dead
forever — no login, no assets/evidence/incidents POST, not only
`/api/risks`. Farm SOP never points at a RiskReady write. Stale
IMPORT_RR/SECURITY dual-gate wrap language removed. No new Layer C
parser. Catalog unchanged. Paying-day **FAIL**. Compose **ABSENT**.

**Cycle 60 (stands):** LICENSE-LOCK / compose honesty. pytest now
asserts BloodHound / Nuclei / OpenVAS/GVM / PingCastle / enum4linux-ng /
smbmap (and the rest of the lock list) never appear in invoke
`will_run=true` even when every slot is allowlisted and on PATH.
Operator docs list exact `docker compose` commands and PASS criteria.
This VM still stamps compose **ABSENT**. Paying-day **FAIL**. No new
Layer C parser. Catalog unchanged.

**Cycle 59 (stands):** enum4linux-ng file-drop polish. `in/identity/`
now accepts operator-landed enum4linux-ng JSON or text (`target` +
users/groups/shares). Listed identities stay listed. Null session,
writable shares, and Domain Admins hints map to existing identity/SMB
POA&M only when the export already shows them. Empty invents nothing.
Detect does not steal HardeningKitty or BloodHound. Collector stays
parse-only — no enum4linux run, no credentials, no live SMB/LDAP/auth.
Slot stays `file_drop`. Demo `enum4linux-ng.txt` attaches to existing
`DC01.CORP.LOCAL`.

**Cycle 58 (stands):** smbmap share-table file-drop. READ/WRITE → existing
SMB POA&M. Empty/NO ACCESS invent nothing. No live SMB.

**Honest stamp:** compose **ABSENT** (hole, not a PASS). Host `make lab` /
`make farm-lab` / `make farm-toolbin-e2e` / `make dropbox-lab` / pytest
**301 passed, 1 skipped**. Catalog **111 / 32 wired / 30 invoke / 81 file_drop**.
Wrap review-only. **Paying-day FAIL.** No USB copy. Cycle 20 (105) stands.
DEMO ≠ client. LICENSE-LOCK / file_drop-only names never `will_run=true`.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 79 | 19 | 27 | 82 | true |
| `make farm-lab` | 64 | 79 | 19 | 27 | 82 | true |
| `make farm-toolbin-e2e` | 64 | 80 | 19 | 27 | 82 | true |
| `make dropbox-lab` | 69 | 88 | 19 | 27 | 85 | true |

**Deltas vs cycle 62:** host/farm findings **78→79**, POA&M **81→82**
(demo FTP/21 on existing `filesrv.corp.local`; zmap+unicornscan dedupe).
Assets unchanged. e2e findings **79→80**, POA&M **81→82**. dropbox
findings **87→88**, POA&M **84→85**. pytest **296→301**. Catalog / wrap /
compose / paying-day / LICENSE-LOCK will_run unchanged.

**Deltas vs cycle 58 (enum4linux-ng, still standing):** host/farm findings
**76→78**, POA&M **79→81** (demo null session + Domain Admins on existing
`DC01.CORP.LOCAL`; listed Administrator and IPC$ READ silent). Assets
unchanged. e2e findings **77→79**, POA&M **79→81**. dropbox findings
**85→87**, POA&M **82→84**.

**LICENSE-LOCK rail:** BloodHound / Nuclei / OpenVAS/GVM / PingCastle /
exploit-class stay `file_drop` and never appear in invoke `will_run=true`.
nmap/nessus invoke only when explicitly in SCOPE.allow_tools AND
stages.deepen/discover enabled AND binary on PATH/FARM_TOOL_BIN.

**Still open:** Docker/compose runtime unexercised — stamp ABSENT until
proven on an operator host with Docker. Live BYO on this box is DEMO
stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT; remaining
cycles harden existing farm/SCOPE honesty, not new Layer C parsers.
