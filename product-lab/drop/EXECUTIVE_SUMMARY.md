> **DEMO: NOT A CLIENT**: Built from demo fixtures because no scanner output was supplied. None describes any real organization.
> Run `not recorded` · generated 2026-09-26 06:46 UTC · pack `1f8d347`

**DEMO: NOT A CLIENT**. not recorded. Assessment window 2023-11-14 to 2023-11-14.

### What we found
[reviewer: one to three plain sentences — not generated]

| Severity | Findings | In POA&M | Duplicates merged |
|---|---|---|---|
| Critical | 22 | 22 | not recorded |
| High | 77 | 77 | not recorded |
| Medium | 16 | 16 | not recorded |
| Low | 10 | 10 | not recorded |
| **Total** | 125 | 125 | 52 |

### Fix these first (top 5 by risk, not by scanner severity alone)
| # | Weakness | Affected | Why it matters | Recommended action | Finding ref |
|---|---|---|---|---|---|
| 1 | IAM user does not have AdministratorAccess | iam-admin-breakglass | [reviewer: one-sentence business impact — not generated] | Detach AdministratorAccess from IAM users. Prefer a role or break-glass group. This is an IAM posture finding, not a CVE. | `CLD-iam-user-administrator-access-iam-admin-breakgla` |
| 2 | ScoutSuite s3: Bucket readable by AllUsers | demo-scout-public | [reviewer: one-sentence business impact — not generated] | Remove public ACLs and bucket policies (S3 Public Access Block; drop AllUsers/AuthenticatedUsers). This is an ACL/public-access finding, not a default-encryption change. | `CLD-s3-bucket-allusers-read-demo-scout-public` |
| 3 | S3 bucket prohibits public access | demo-public-assets | [reviewer: one-sentence business impact — not generated] | Remove public ACLs and bucket policies (S3 Public Access Block; drop AllUsers/AuthenticatedUsers). This is an ACL/public-access finding, not a default-encryption change. | `CLD-s3-bucket-public-access-demo-public-assets` |
| 4 | Generic API Key | services/payments/config.py | [reviewer: one-sentence business impact — not generated] | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | `CODE-generic-api-key-services-payments-config-py` |
| 5 | Generic Secret | deploy/.env.sample | [reviewer: one-sentence business impact — not generated] | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | `CODE-generic-secret-deploy-env-sample` |

### Where the risk concentrates
identity: 42 findings, mapped to csf_PR, csf_protect, nist80053_AC-2, nist80053_AC-6, cpg_2_W, nist80053_AC-3, nist80053_SC-7, nist80053_AC-17.
external exposure: 28 findings, mapped to csf_PR, csf_protect, nist80053_SC-8, nist80053_SC-8(1), nist80053_SC-13, nist80053_SI-8, cis_9_5, cpg_1_E.
cloud configuration: 16 findings, mapped to csf_PR, csf_protect, nist80053_SC-28, nist80053_SC-13, cpg_2_W, nist80053_AC-3, nist80053_AC-6, nist80053_SC-7.
vulnerability: 13 findings, mapped to cpg_2_W, csf_PR, csf_protect, nist80053_CM-7, nist80053_SC-7, nist80053_SI-10, nist80053_SA-11, csf_ID.

### What this does not tell you
- Cloud configuration, Host / network exposure, Vulnerability scan, Host coverage, Identity, External exposure, Kubernetes, Code secrets, SaaS / identity, Deception sensors, DNS / email. These areas were out of scope or had no scanner output. See the scope statement.
- This is a point-in-time review of scanner artifacts. It is not a penetration test and not continuous monitoring.
- Owners and due dates in the POA&M are blank until the operator assigns them.

### Next step
[reviewer: one sentence — not generated]

Companion files: `poam.csv`, `risk_register` (`ciso/risk_scenarios.csv`), the scope and trust statement, and `MANIFEST` (hashes).
