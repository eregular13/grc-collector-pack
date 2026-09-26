# lab-estate hardening scan (Lynis + OpenSCAP + HardeningKitty)

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

## Windows lab host (HardeningKitty, no Docker)

Authorized Windows lab host only. Does **not** start Docker. Fetches
HardeningKitty (MIT) at run time on that host — not in the pack image.
Uses `finding_list_msft_security_baseline_*` only. Never `finding_list_cis_*`.
Not a CIS benchmark / CIS-CAT deliverable.

```powershell
cd lab-estate
.\scan-windows-hardening.ps1 -AuthorizedLab
# or: .\scan-windows-hardening.ps1 -AuthorizedLab -DestIn C:\path\to\prove\work\in
cd ..
.\scripts\lab_drop_to_sor.ps1 -Work .\prove\work
```

CI / no Windows: copy `fixtures/lab-drop/identity/` (synthetic schema
fixture, not an observed scan) into dest_in. Pytest does this.

## Follow-up

Linux Lynis/oscap runner is `scan-hardening.ps1` (Docker Desktop).
Windows HardeningKitty runner is `scan-windows-hardening.ps1` (local host).
