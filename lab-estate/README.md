# lab-estate hardening scan (Lynis + OpenSCAP)

Isolated Linux lab containers only. Writes raw Lynis `report.dat` and
OpenSCAP XCCDF `--results` XML into the same dest_in the nmap pack_drop
leaf already uses (`in/wazuh/` beside `in/nmap/pack_drop/`).

Not a CIS benchmark / CIS-CAT deliverable. Pack artifact stays
scanner-free. No `POST /api/risks`. LAB != SAMPLE != client.

## DESKTOP (Windows + Docker Desktop)

From this folder:

```powershell
cd lab-estate
.\scan-hardening.ps1
# or: .\scan-hardening.ps1 -DestIn C:\path\to\prove\work\in
cd ..
.\scripts\lab_drop_to_sor.ps1 -Work .\prove\work
```

That lands `prove\work\in\wazuh\lynis-*.dat` + `openscap-*.xml` +
`MANIFEST` (SHA256, LF), then ingest through collectors → CISO CSVs.

CI / no Docker: copy `fixtures/lab-drop/wazuh/` into dest_in and run
`.\scripts\lab_drop_to_sor.ps1` (pytest does this).

## What runs

| Tool | License | Profile | Becomes a finding |
|---|---|---|---|
| Lynis | GPLv3 | host audit `--quick` | mapped warnings + suggestions only |
| OpenSCAP `oscap` | LGPL | ANSSI / standard / STIG SSG (never CIS) | `fail` / `error` only |

Hardening index / XCCDF score are scores, not findings.

## Follow-up

Windows checker (HardeningKitty already parses operator-landed CSV) is
out of scope for this runner.
