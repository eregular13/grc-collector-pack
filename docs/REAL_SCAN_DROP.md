# Real scanner drop (analysis engine)

This pack **parses files**. It does not run nmap/nessus/nuclei. Do **not** scan `192.168.10.0/24` from this lab.

## Drop

Put vendor output under `in/<sensor>/`:

| Folder | Examples |
| --- | --- |
| `in/cloud/` | Prowler JSON / ASFF / CSV |
| `in/nmap/` | Nmap `-oX` XML, `.gnmap` |
| `in/vuln/` | Nuclei JSONL / SARIF, OpenVAS XML, Nessus XML |
| `in/wazuh/` | agents / SCA / osquery / alerts JSON |
| `in/identity/` | BloodHound / PingCastle / ScubaGear |
| `in/easm/` | httpx / amass / subfinder |
| `in/k8s/` | Kubescape / kube-bench |
| `in/code/` | Gitleaks / Trivy / Semgrep |
| `in/saas/` | M365 / Okta JSON |

If `in/<sensor>/` has files, collectors use **those** (not silent `fixtures/demo/`). Empty `in/` falls back to demo fixtures.

## Run

```powershell
cd "C:\GRC Collector\grc-collector-pack"
$env:PYTHONPATH = (Get-Location)
$env:DRY_RUN = "1"; $env:CISO_PUSH = "0"; $env:RISKREADY_PUSH = "0"; $env:GRC_LIVE_SCAN = "0"
python collectors/grc_loader.py
python -m dropbox.import_grc --target all --dry-run
```

Or `run_lab.ps1` (pytest + collectors + loader). Then Extra Import CISO CSVs (`docs/IMPORT_CISO.md`) and OpenGRC CSVs (`docs/IMPORT_OPENGRC.md`).

A signed SCOPE + BYO binary on PATH is a **different** sprint (`docs/FIRST_LIVE_CHECKLIST.md`). Not this drop.
