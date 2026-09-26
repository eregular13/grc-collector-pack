> **DEMO: NOT A CLIENT**: Built from demo fixtures because no scanner output was supplied. None describes any real organization.
> Run `not recorded` · generated 2026-09-26 09:39 UTC · pack `02da545`

**DEMO: NOT A CLIENT**. Run `not recorded`, pack `02da545`, generated 2026-09-26 09:39 UTC.

### Authorization
- No client authorization applies. No client systems were touched.

### What was in scope
| Area | Targets / source | Scanner or export used | Version | Collected (date/time) | Records |
|---|---|---|---|---|---|
| Cloud configuration | bundled sample / fixture | cloud-prowler | not recorded | not recorded | 25 |
| Code secrets | bundled sample / fixture | code-secrets | not recorded | not recorded | 17 |
| DNS / email | bundled sample / fixture | dns-email | not recorded | not recorded | 17 |
| External exposure | bundled sample / fixture | easm | not recorded | not recorded | 32 |
| Deception sensors | bundled sample / fixture | honeypot | not recorded | not recorded | 6 |
| Host coverage | bundled sample / fixture | host-wazuh | not recorded | not recorded | 30 |
| Identity | bundled sample / fixture | identity-ad | not recorded | not recorded | 27 |
| Host / network exposure | bundled sample / fixture | inventory-nmap | not recorded | not recorded | 39 |
| Kubernetes | bundled sample / fixture | k8s-kubescape | not recorded | not recorded | 14 |
| SaaS / identity | bundled sample / fixture | saas-idp | not recorded | not recorded | 36 |
| Vulnerability scan | bundled sample / fixture | vuln-scan | not recorded | not recorded | 28 |

Out of scope, or no data supplied: none.

### Coverage gaps
None. Every sensor that received input was assessed.

### Method
1. Scanner output was supplied as files. The pack parses files only. It does not run exploits, log in to client systems, or call client APIs.
2. Each result is normalized, and duplicates are merged (13 merged).
3. Each finding is mapped to controls (CISA CPG, NIST CSF, NIST SP 800-53, CIS Controls) using a per-finding rule table, not by severity.
4. Severity is taken from the source tool and adjusted only where noted in the finding's `severity_rationale`.
5. A human reviewer (not human-reviewed) checked the top findings and the recommended actions before release.

### What the labels mean
CLIENT is authorized scanner output. LAB is an Evergreen test environment. SAMPLE/DEMO is bundled example data. MIXED includes bundled sample files and is not client-ready.

### Limits (read before relying on this)
Covers only the listed scanners at collection time. A clean area is not proof of safety. Control mappings are advisory, not an audit. Secrets are redacted. Nothing was uploaded to a GRC platform.

### Integrity and traceability
- Every POA&M row carries a `ref_id` that links to its finding and to the raw artifact under `evidence/`.
- SHA-256 hashes for every exported file are in `MANIFEST`. Verify with `sha256sum -c MANIFEST`.
- Contact for questions or corrections: not recorded.
