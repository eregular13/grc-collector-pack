# PASSFAIL — compose lab 1

written: 2026-09-03 21:40:15 PT
command: docker compose up --build --exit-code-from grc-loader
cwd: C:\Users\R\grc-collector-pack
exit: 0
duration: 00:00:08.0628228
service_count: 10
services:
inventory-nmap
saas-idp
vuln-scan
cloud-prowler
code-secrets
easm
host-wazuh
identity-ad
k8s-kubescape
grc-loader

out_changed: True
out_before_utc: 2026-09-04T04:39:51.6408874Z
out_after_utc: 2026-09-04T04:40:14.3574316Z
summary:
{
  "assets": 62,
  "findings": 59,
  "vulnerabilities": 15,
  "evidences": 10,
  "applied_controls": 74,
  "risk_scenarios": 74,
  "incidents": 58,
  "risks_proposed": 57,
  "ocsf": 59,
  "canonical": 137,
  "demo": true,
  "generated_at": "2026-09-04T04:40:14Z"
}

verdict: PASS
