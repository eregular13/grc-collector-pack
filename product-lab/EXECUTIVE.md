# Executive brief — product-lab (private drop-box)

**Product:** Layer A farm + Layer B orchestrator. Public Layer C parse-only.

**This window (cycle 45):** Checkov / Gitleaks / TruffleHog file-drop polish.
`in/code/` now accepts Checkov `results.failed_checks` (and a report list),
Gitleaks `{findings|leaks|results}` wrappers, and TruffleHog `{results}`
(plus existing JSONL / arrays). Passed / INFO / empty invent nothing.
Secrets stay `[REDACTED]`. Public S3 ACL and exposed credentials map to
existing POA&M. Collector stays parse-only — no live checkov / gitleaks /
semgrep / trufflehog. Demo `checkov.json` attaches one extra finding to
existing `infra/terraform.tfvars`.

**Honest stamp:** compose **ABSENT**. Host `make lab` / `make farm-lab` /
`make farm-toolbin-e2e` / `make dropbox-lab` / pytest **237 passed, 1 skipped**.
Catalog **111 / 32 wired / 30 invoke / 81 file_drop**. Wrap review-only.
No paying-day PASS. No USB copy. Cycle 20 (105) stands.

| Surface | Assets | Findings | Vulns | Evidence | POA&M | demo |
|---|---:|---:|---:|---:|---:|---|
| Host `make lab` | 64 | 69 | 17 | 26 | 70 | true |
| `make farm-lab` | 64 | 69 | 17 | 26 | 70 | true |
| `make farm-toolbin-e2e` | 64 | 70 | 17 | 26 | 70 | true |
| `make dropbox-lab` | 69 | 78 | 17 | 26 | 73 | true |

**Deltas vs cycle 44:** host/farm findings **68→69**, POA&M **69→70**,
evidence **25→26** (demo `checkov.json` public-ACL FAIL on existing
`infra/terraform.tfvars`; versioning PASS silent). e2e findings **69→70**.
dropbox findings **77→78**, POA&M **72→73**. Catalog / wrap / compose /
paying-day unchanged.

**Still open:** Docker/compose runtime unexercised. Live BYO on this box is
DEMO stubs. Catalog ≠ 100 running binaries. Overnight loop ended 2026-09-02
— do not re-arm. Afternoon build continues until 16:00 PT.
