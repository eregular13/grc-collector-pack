> **DEMO: NOT A CLIENT**: Built from demo fixtures because no scanner output was supplied. None describes any real organization.
> Run `not recorded` · generated 2026-10-04 05:19 UTC · pack `05c1551`

**DEMO: NOT A CLIENT**. Assessment window 2026-09-04 to 2026-09-24 (66 of 210 rows dated).

### What we found
125 weaknesses, 119 on the open POA&M (18 Critical, 77 High).

| Severity | Findings | In POA&M | Duplicates merged |
|---|---|---|---|
| Critical | 18 | 18 | not recorded |
| High | 77 | 76 | not recorded |
| Medium | 19 | 16 | not recorded |
| Low | 11 | 9 | not recorded |
| Info | 0 | 0 | not recorded |
| **Total** | 125 | 119 | 17 |

Open POA&M (poam.csv): 119

Changed since last run: open=119 new=119 pending verification=0 reopened=0 closed=0.
Ledger open including excluded: 125.

Ledger warning: LEDGER_LOST (first run: no prior ledger).

125 weaknesses, 119 POA&M, 13 excluded, 0 kind-excluded, 125 register (119 + (13 - 7) = 125; 125 + 0 - 0 = 125).
7 C5 duplicate-instance extras stay off the register.
Also: 17 duplicates were merged.

### Fix these first (top 5 by risk, not by scanner severity alone)
| # | Weakness | Affected | Why it matters | Recommended action | Finding ref |
|---|---|---|---|---|---|
| 1 | Telnet exposed | filesrv.corp.local | filesrv.corp.local has open TCP/23 \(tcp\). | Disable Telnet \(TCP/23\). Use SSH or an approved jump host. Do not leave cleartext remote admin on the network. | `NMAP-filesrv-corp-local-23-tcp` |
| 2 | Telnet exposed | telnet-legacy.corp.local | telnet-legacy.corp.local has open TCP/23 \(telnet\). | Disable Telnet \(TCP/23\). Use SSH or an approved jump host. Do not leave cleartext remote admin on the network. | `NMAP-telnet-legacy-corp-local-23-tcp` |
| 3 | IAM user has standing AdministratorAccess | iam-admin-breakglass | User has AdministratorAccess attached directly. | Detach AdministratorAccess from IAM users. Prefer a role or break-glass group. This is an IAM posture finding, not a CVE. | `CLD-iam-user-administrator-access-123456789012-iam-admin-breakglass` |
| 4 | S3 bucket allows public access | demo-public-assets | Bucket ACL and policy allow public List/Get. | Remove public ACLs and bucket policies \(S3 Public Access Block; drop AllUsers/AuthenticatedUsers\). This is an ACL/public-access finding, not a default-encryption change. | `CLD-s3-bucket-public-access-123456789012-demo-public-assets` |
| 5 | Generic API Key | services/payments/config.py | Secret rule generic-api-key in services/payments/config.py:12 value=\[REDACTED\]. | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | `CODE-generic-api-key-services-payments-config-py` |

### Where the risk concentrates
identity: 41 findings, mapped to cpg_3_H, csf_PR_AA_05, nist80053_AC-2, nist80053_AC-6, cpg_3_S, nist80053_AC-3, nist80053_SC-7, csf_PR_IR_01.
external exposure: 31 findings, mapped to cpg_3_K, csf_PR_DS_02, nist80053_SC-8, nist80053_SC-8(1), nist80053_SC-13, nist80053_SC-17, cpg_3_L, nist80053_SI-8.
cloud configuration: 16 findings, mapped to cpg_3_K, csf_PR_DS_01, nist80053_SC-28, nist80053_SC-13, cpg_3_S, csf_PR_AA_05, nist80053_AC-3, nist80053_AC-6.
vulnerability: 13 findings, mapped to cpg_3_I, csf_PR_IR_01, nist80053_CM-7, nist80053_SC-7, cpg_2_B, csf_PR_PS_06, nist80053_SI-10, nist80053_SA-11.

### What this does not tell you
- Demo/sample estate — no live scan of a client environment. Findings come from bundled fixtures, not a real estate.
- This is a point-in-time review of scanner artifacts. It is not a penetration test and not continuous monitoring.
- Owners and due dates in the POA&M are blank until the operator assigns them.

### Coverage gaps
None. Every sensor that received input was assessed.

### Next step
This is demo/sample data, not a live scan of a client estate. Review poam.csv after a real-environment engagement.

Companion files: `poam.csv`, `risk_register` (`ciso/risk_scenarios.csv`), the scope and trust statement, and `SHA256SUMS` (hashes). Verify with `sha256sum -c SHA256SUMS` (Git Bash / Linux) or `python scripts/verify_manifest.py`.
