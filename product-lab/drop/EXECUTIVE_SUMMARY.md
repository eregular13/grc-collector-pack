> **DEMO: NOT A CLIENT**: Built from demo fixtures because no scanner output was supplied. None describes any real organization.
> Run `not recorded` · generated 2026-09-26 09:39 UTC · pack `02da545`

**DEMO: NOT A CLIENT**. not recorded. Assessment window 2023-11-14 to 2023-11-14 (12 of 214 rows dated).

### What we found
[reviewer: one to three plain sentences — not generated]

| Severity | Findings | In POA&M | Duplicates merged |
|---|---|---|---|
| Critical | 20 | 20 | not recorded |
| High | 79 | 79 | not recorded |
| Medium | 19 | 16 | not recorded |
| Low | 11 | 9 | not recorded |
| Info | 0 | 0 | not recorded |
| **Total** | 129 | 124 | 13 |

Changed since last run: open=126 new=126 pending verification=0 reopened=0 closed=0.

129 findings produced 124 POA&M rows and 129 risk-register entries because 5 findings were not included in the POA&M; 13 duplicates were merged.

### Fix these first (top 5 by risk, not by scanner severity alone)
| # | Weakness | Affected | Why it matters | Recommended action | Finding ref |
|---|---|---|---|---|---|
| 1 | IAM user does not have AdministratorAccess | iam-admin-breakglass | [reviewer: one-sentence business impact — not generated] | Detach AdministratorAccess from IAM users. Prefer a role or break-glass group. This is an IAM posture finding, not a CVE. | `CLD-iam-user-administrator-access-123456789012-iam-admin-breakglass` |
| 2 | S3 bucket prohibits public access | demo-public-assets | [reviewer: one-sentence business impact — not generated] | Remove public ACLs and bucket policies (S3 Public Access Block; drop AllUsers/AuthenticatedUsers). This is an ACL/public-access finding, not a default-encryption change. | `CLD-s3-bucket-public-access-123456789012-demo-public-assets` |
| 3 | Generic API Key | services/payments/config.py | [reviewer: one-sentence business impact — not generated] | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | `CODE-generic-api-key-services-payments-config-py` |
| 4 | Generic Secret | deploy/.env.sample | [reviewer: one-sentence business impact — not generated] | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | `CODE-generic-secret-deploy-env-sample` |
| 5 | TruffleHog Github | scripts/deploy.sh | [reviewer: one-sentence business impact — not generated] | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | `CODE-trufflehog-github-scripts-deploy-sh` |

### Where the risk concentrates
identity: 43 findings, mapped to cpg_3_H, csf_PR_AA_05, nist80053_AC-2, nist80053_AC-6, cpg_3_S, nist80053_AC-3, nist80053_SC-7, csf_PR_IR_01.
external exposure: 31 findings, mapped to cpg_3_K, csf_PR_DS_02, nist80053_SC-8, nist80053_SC-8(1), nist80053_SC-13, cpg_3_L, nist80053_SI-8, cis_9_5.
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
