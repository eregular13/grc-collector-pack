# Farm SLOTS catalog

Private drop-box tool zoo. **No binaries in git.** Most slots are file_drop:
the operator lands artifacts in `in/<sensor>/` for Layer C.

Total: 111
Wired: 32
Invoke: 30
File-drop: 81

## By category

| category | total | wired | invoke | file_drop |
|---|---:|---:|---:|---:|
| cloud | 11 | 2 | 2 | 9 |
| deepen | 14 | 2 | 2 | 12 |
| discover | 18 | 9 | 9 | 9 |
| endpoint | 12 | 4 | 4 | 8 |
| external | 19 | 10 | 10 | 9 |
| identity | 13 | 1 | 1 | 12 |
| k8s | 10 | 3 | 2 | 8 |
| ot | 3 | 0 | 0 | 3 |
| secrets | 8 | 1 | 0 | 8 |
| wifi | 3 | 0 | 0 | 3 |

## Ingest map (Layer C)

Every `output_glob` lands in an existing Layer C sensor directory.
`audit_output_globs()` is empty. No theater parsers.

| sensor | total | invoke | file_drop |
|---|---:|---:|---:|
| in/cloud/ | 9 | 1 | 8 |
| in/code/ | 8 | 0 | 8 |
| in/easm/ | 24 | 10 | 14 |
| in/identity/ | 10 | 1 | 9 |
| in/k8s/ | 10 | 1 | 9 |
| in/nmap/ | 24 | 11 | 13 |
| in/saas/ | 5 | 1 | 4 |
| in/vuln/ | 11 | 3 | 8 |
| in/wazuh/ | 10 | 2 | 8 |

File-drop only (never subprocess even if on PATH): amass, checkov, ffuf, gobuster, nikto, scoutsuite, subfinder.

LICENSE-LOCK names stay file_drop and are never subprocessed.
See `SLOTS.yaml`, `INTEGRITY.md`, and `OPERATOR.md`.
