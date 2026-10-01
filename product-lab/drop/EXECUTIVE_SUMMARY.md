> **DEMO: NOT A CLIENT**: Built from demo fixtures because no scanner output was supplied. None describes any real organization.
> Run `not recorded` · generated 2026-10-01 20:55 UTC · pack `9e8e570`

**DEMO: NOT A CLIENT**. Assessment window 2026-09-04 to 2026-09-24 (66 of 210 rows dated).

### What we found
[reviewer: one to three plain sentences — not generated]

| Severity | Findings | In POA&M | Duplicates merged |
|---|---|---|---|
| Critical | 18 | 18 | not recorded |
| High | 77 | 76 | not recorded |
| Medium | 19 | 16 | not recorded |
| Low | 11 | 9 | not recorded |
| Info | 0 | 0 | not recorded |
| **Total** | 125 | 119 | 17 |

Open POA&M (poam.csv): 119

Changed since last run: open=119 new=125 pending verification=0 reopened=0 closed=0.
Ledger open including excluded: 125.

125 weaknesses, 119 POA&M, 6 excluded, 0 kind-excluded, 125 register (119 + 6 + 0 = 125; 125 + 0 = 125).
Also: 17 duplicates were merged.

### Fix these first (top 5 by risk, not by scanner severity alone)
| # | Weakness | Affected | Why it matters | Recommended action | Finding ref |
|---|---|---|---|---|---|
| 1 | Telnet exposed | filesrv.corp.local | [reviewer: one-sentence business impact — not generated] | Disable Telnet \(TCP/23\). Use SSH or an approved jump host. Do not leave cleartext remote admin on the network. | `NMAP-filesrv-corp-local-23-tcp` |
| 2 | Telnet exposed | telnet-legacy.corp.local | [reviewer: one-sentence business impact — not generated] | Disable Telnet \(TCP/23\). Use SSH or an approved jump host. Do not leave cleartext remote admin on the network. | `NMAP-telnet-legacy-corp-local-23-tcp` |
| 3 | IAM user does not have AdministratorAccess | iam-admin-breakglass | [reviewer: one-sentence business impact — not generated] | Detach AdministratorAccess from IAM users. Prefer a role or break-glass group. This is an IAM posture finding, not a CVE. | `CLD-iam-user-administrator-access-123456789012-iam-admin-breakglass` |
| 4 | S3 bucket prohibits public access | demo-public-assets | [reviewer: one-sentence business impact — not generated] | Remove public ACLs and bucket policies \(S3 Public Access Block; drop AllUsers/AuthenticatedUsers\). This is an ACL/public-access finding, not a default-encryption change. | `CLD-s3-bucket-public-access-123456789012-demo-public-assets` |
| 5 | Generic API Key | services/payments/config.py | [reviewer: one-sentence business impact — not generated] | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | `CODE-generic-api-key-services-payments-config-py` |

### Where the risk concentrates
identity: 41 findings, mapped to cpg_3_H, csf_PR_AA_05, nist80053_AC-2, nist80053_AC-6, cpg_3_S, nist80053_AC-3, nist80053_SC-7, csf_PR_IR_01.
external exposure: 31 findings, mapped to cpg_3_K, csf_PR_DS_02, nist80053_SC-8, nist80053_SC-8(1), nist80053_SC-13, nist80053_SC-17, cpg_3_L, nist80053_SI-8.
cloud configuration: 16 findings, mapped to cpg_3_K, csf_PR_DS_01, nist80053_SC-28, nist80053_SC-13, cpg_3_S, csf_PR_AA_05, nist80053_AC-3, nist80053_AC-6.
vulnerability: 13 findings, mapped to cpg_3_I, csf_PR_IR_01, nist80053_CM-7, nist80053_SC-7, cpg_2_B, csf_PR_PS_06, nist80053_SI-10, nist80053_SA-11.

### What this does not tell you
- none. These areas were out of scope or had no scanner output. See the scope statement.
- This is a point-in-time review of scanner artifacts. It is not a penetration test and not continuous monitoring.
- Owners and due dates in the POA&M are blank until the operator assigns them.

### Coverage gaps
None. Every sensor that received input was assessed.

### Next step
[reviewer: one sentence — not generated]

Companion files: `poam.csv`, `risk_register` (`ciso/risk_scenarios.csv`), the scope and trust statement, and `MANIFEST` (hashes).
