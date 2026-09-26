> **DEMO: NOT A CLIENT**: Built from demo fixtures because no scanner output was supplied. None describes any real organization.
> Run `not recorded` · generated 2026-09-26 06:46 UTC · pack `1f8d347`

**DEMO: NOT A CLIENT**. Run `not recorded`, pack `1f8d347`, generated 2026-09-26 06:46 UTC.

### Authorization
- No client authorization applies. No client systems were touched.

### What was in scope
| Area | Targets / source | Scanner or export used | Version | Collected (date/time) | Records |
|---|---|---|---|---|---|
| Cloud configuration | bundled sample / fixture | cloud-prowler | not recorded | not recorded | 25 |
| Code secrets | bundled sample / fixture | code-secrets | not recorded | not recorded | 15 |
| DNS / email | bundled sample / fixture | dns-email | not recorded | not recorded | 16 |
| External exposure | bundled sample / fixture | easm | not recorded | not recorded | 15 |
| Host coverage | bundled sample / fixture | host-wazuh | not recorded | not recorded | 30 |
| Identity | bundled sample / fixture | identity-ad | not recorded | not recorded | 25 |
| Host / network exposure | bundled sample / fixture | inventory-nmap | not recorded | not recorded | 25 |
| Kubernetes | bundled sample / fixture | k8s-kubescape | not recorded | not recorded | 11 |

Out of scope, or no data supplied: Cloud configuration, Host / network exposure, Vulnerability scan, Host coverage, Identity, External exposure, Kubernetes, Code secrets, SaaS / identity, Deception sensors, DNS / email. List every collector folder that was empty or fell back to fixtures, by name.

### Method
1. Scanner output was supplied as files, or collected by not recorded under the authorization above. The pack parses files only. It does not run exploits, log in to client systems, or call client APIs.
2. Each result is normalized, and duplicates are merged (52 merged).
3. Each finding is mapped to controls (CISA CPG, NIST CSF, NIST SP 800-53, CIS Controls) using a per-finding rule table (`per-finding control mapping table`), not by severity.
4. Severity is taken from the source tool and adjusted only where noted in the finding's `severity_rationale`.
5. A human reviewer (not human-reviewed) checked the top findings and the recommended actions before release. If no one did, print "not human-reviewed".

### What the labels mean
- **CLIENT**: derived only from scanner output collected under the authorization above.
- **LAB**: derived from an Evergreen-controlled test environment. It proves the pipeline works, not anything about your organization.
- **SAMPLE / DEMO**: bundled example data used to show the output format. Any hostnames, accounts, or findings in it are fictional.
- **MIXED**: some outputs fell back to bundled sample files. Treat the whole package as not client-ready.

### Limits (read before relying on this)
- The review covers only what the listed scanners could see, at the collection time shown. A clean area means no data or no detection, not proof of safety.
- No exploitation or verification testing was performed unless a row says otherwise.
- Control mappings are advisory. They show which control would most directly address each weakness, not an audit opinion or a compliance attestation.
- Secrets found in code are redacted in every output. Rotation must be confirmed by the client.
- Nothing was uploaded to any GRC platform. The OpenGRC, Probo, and CISO Assistant files are for the client to import.

### Integrity and traceability
- Every POA&M row carries a `ref_id` that links to its finding and to the raw artifact under `evidence/`.
- SHA-256 hashes for every exported file are in `MANIFEST`. Verify with `sha256sum -c MANIFEST`.
- Contact for questions or corrections: not recorded.
