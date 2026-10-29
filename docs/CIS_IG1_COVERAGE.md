<!-- Generated: python scripts/ig1_coverage.py <report_dir> product-lab/drop (bundled SAMPLE/DEMO drop, so nothing here is REAL). Run it on a LAB or CLIENT out/ dir to see real-scan backing. -->
# CIS Controls v8 IG1 coverage

Safeguard ids only. REAL = a LAB/CLIENT POA&M row carries the id. SAMPLE-ONLY = only bundled sample/demo rows do. MAPPED-NO-EVIDENCE / MAPPED-INTERNAL are not evidence that a safeguard is met.

safeguards=56 mapped=16 REAL=0 SAMPLE-ONLY=9 MAPPED-NO-EVIDENCE=1 MAPPED-INTERNAL=6 UNMAPPED=40

Inputs: drop

| Safeguard | Status | Surface | Real rows | Sample rows | Note |
|---|---|---|---|---|---|
| 1.1 | SAMPLE-ONLY | refs | 0 | 4 | only bundled sample/demo rows carry this id |
| 1.2 | UNMAPPED | - | 0 | 0 | nmap/asset ledger record discovered hosts, but the pack has no authorized-asset baseline to call a host unauthorized |
| 2.1 | UNMAPPED | - | 0 | 0 | grype/vuln collectors emit only vulnerable packages, not a full software inventory |
| 2.2 | UNMAPPED | - | 0 | 0 | no collector derives end-of-support status; the asset ledger eol field is operator-entered |
| 2.3 | UNMAPPED | - | 0 | 0 | needs an authorized-software list; no collector produces one |
| 3.1 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 3.2 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 3.3 | SAMPLE-ONLY | refs | 0 | 5 | only bundled sample/demo rows carry this id |
| 3.4 | UNMAPPED | - | 0 | 0 | no collector reads data-retention settings |
| 3.5 | UNMAPPED | - | 0 | 0 | no collector reads data-disposal evidence |
| 3.6 | UNMAPPED | - | 0 | 0 | no collector reads disk-encryption state on end-user devices |
| 4.1 | SAMPLE-ONLY | refs | 0 | 3 | only bundled sample/demo rows carry this id |
| 4.2 | UNMAPPED | - | 0 | 0 | nmap sees services such as SNMP, but collectors do not classify a host as network infrastructure, so a device-config finding cannot be attributed honestly |
| 4.3 | MAPPED-INTERNAL | internal | 0 | 0 | id is internal-only; it never reaches POA&M framework_refs |
| 4.4 | SAMPLE-ONLY | refs | 0 | 1 | only bundled sample/demo rows carry this id |
| 4.5 | SAMPLE-ONLY | refs | 0 | 1 | only bundled sample/demo rows carry this id |
| 4.6 | UNMAPPED | - | 0 | 0 | no collector reads how assets and software are administered |
| 4.7 | MAPPED-NO-EVIDENCE | refs | 0 | 0 | no POA&M row in these outputs; not evidence of compliance |
| 5.1 | MAPPED-INTERNAL | internal | 0 | 0 | id is internal-only; it never reaches POA&M framework_refs |
| 5.2 | SAMPLE-ONLY | refs | 0 | 3 | only bundled sample/demo rows carry this id |
| 5.3 | SAMPLE-ONLY | refs | 0 | 3 | only bundled sample/demo rows carry this id |
| 5.4 | MAPPED-INTERNAL | internal | 0 | 0 | id is internal-only; it never reaches POA&M framework_refs |
| 6.1 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 6.2 | MAPPED-INTERNAL | internal | 0 | 0 | id is internal-only; it never reaches POA&M framework_refs |
| 6.3 | UNMAPPED | - | 0 | 0 | no collector reads MFA for externally exposed apps separately from admin MFA |
| 6.4 | UNMAPPED | - | 0 | 0 | no collector reads remote-network-access MFA |
| 6.5 | UNMAPPED | - | 0 | 0 | no collector reads admin MFA as a distinct safeguard signal |
| 7.1 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 7.2 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 7.3 | SAMPLE-ONLY | refs | 0 | 5 | only bundled sample/demo rows carry this id |
| 7.4 | SAMPLE-ONLY | refs | 0 | 5 | only bundled sample/demo rows carry this id |
| 8.1 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed (audit-log collection itself is covered by another safeguard) |
| 8.2 | MAPPED-INTERNAL | internal | 0 | 0 | id is internal-only; it never reaches POA&M framework_refs |
| 8.3 | UNMAPPED | - | 0 | 0 | no collector reads log storage capacity |
| 9.1 | UNMAPPED | - | 0 | 0 | no collector identifies browser or mail-client versions as such |
| 9.2 | UNMAPPED | - | 0 | 0 | dns_email checks SPF/DKIM/DMARC records only; nothing reads DNS filtering |
| 10.1 | MAPPED-INTERNAL | internal | 0 | 0 | id is internal-only; it never reaches POA&M framework_refs |
| 10.2 | UNMAPPED | - | 0 | 0 | no collector reads anti-malware signature update state |
| 10.3 | UNMAPPED | - | 0 | 0 | no collector reads removable-media autorun settings |
| 11.1 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 11.2 | UNMAPPED | - | 0 | 0 | no collector reads backup job state |
| 11.3 | UNMAPPED | - | 0 | 0 | no collector reads backup protection |
| 11.4 | UNMAPPED | - | 0 | 0 | no collector reads backup isolation |
| 12.1 | UNMAPPED | - | 0 | 0 | vuln collectors see outdated software, but collectors do not classify a host as network infrastructure |
| 14.1 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 14.2 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 14.3 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 14.4 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 14.5 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 14.6 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 14.7 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 14.8 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 15.1 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 17.1 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 17.2 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
| 17.3 | UNMAPPED | - | 0 | 0 | process or policy safeguard; no scanner output can show it is met or missed |
