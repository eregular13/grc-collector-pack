# Plan

```
PLAN → BUILD → SELF-CHECK → LAB → CRITIC → FIX → REGRESSION LAB
```

## Scope

Build `grc-collector-pack` only. Ten compose services, stdlib Python collectors, pytest + `lab_outputs.py` gate.

## Sensors

| Service | Prefix | Input |
|---|---|---|
| cloud_prowler | CLD- | Prowler JSON + Prowler CSV (`CHECK_ID`/`STATUS`/`SEVERITY`) |
| inventory_nmap | NMAP- | Nmap XML (hostname `type=user` over PTR; skip `state=down`) + gnmap (`# Nmap` / `Host:` lines) |
| vuln_scan | VULN- | Nuclei JSONL (`matched-at` URL → hostname; `ip` only; `classification.cve-id`) + SARIF + OpenVAS numeric CVSS + empty `<host>` text → `ip=` + `NOCVE` → `<ref type="cve">` |
| host_wazuh | WAZ- | Wazuh agents/alerts JSON (`Disconnected`, `data`/`rule.level`) + SCA + Osquery nested `columns` / `osquery` list of rows |
| identity_ad | ID- | BloodHound CE (`data` node list or `data.nodes`) + PingCastle XML (`DomainFQDN` when Host empty) + PingCastle JSON `HealthcheckRisk` + ScubaGear Results/Failed (`RelativePath` id fallback) |
| easm | EASM- | Amass txt + Amass JSON `{name}`/`{fqdn}` + `names`/`domains` arrays + httpx JSONL (`input` hostname when `host` empty) + URL-only `https://host` + Subfinder JSONL `{host}` |
| k8s_kubescape | K8S- | Kubescape (`summaryDetails.resourcesSeverity` + `failedControls` controlID, no resources) + kube-bench JSON (`Fail`/`Failed`; hyphenated `test-number`/`test-result`) |
| code_secrets | CODE- | Gitleaks JSON (`Fingerprint`/`DetectorName` when RuleID empty) + Gitleaks SARIF (`ruleId`) + Trivy Secrets + Trivy Misconfigurations (FAIL) + package-lock.json SP + Semgrep SARIF + YAML/JSONL aws_secret_access_key redaction |
| saas_idp | SAAS- | M365 + Okta JSON + Okta `/api/v1/users` (`credentials.provider` MFA) |
| grc_loader | — | canonical JSONL → CISO/RiskReady/OCSF |

## Lab gate

- Windows real lab entry: `powershell -ExecutionPolicy Bypass -File .\run_lab.ps1` (Makefile `make lab` is optional Unix/WSL only)
- pytest tests (parsers, safety, dedupe)
- run collectors + loader twice in `run_lab.ps1`; `summary-pass1.json` counts must match `summary.json`
- `python tests/lab_outputs.py`
  - required files and exact headers
  - `out/evidence/{sensor}.md` exists for all nine sensors
  - semicolon risk file
  - enums valid (findings.csv status `open|closed|in_progress`)
  - assets≥20 findings≥20 evidence≥8
  - `risks_proposed` only high/critical
  - `risk_scenarios.csv` row count equals high+critical findings
  - no raw AWS keys
  - push scripts do not contain `POST /api/risks`
  - CHANGELOG.md latest cycle has summary.json keys; `run_lab.ps1` stamps `## latest lab` from summary.json

## Hostile inputs

Truncated Prowler JSON, blank/invalid Nuclei lines, nmap host without hostname, loader run twice (overwrite + asset dedupe).
