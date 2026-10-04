"""Refresh product-lab/drop from a host-lab out/ (or packaged CISO CSVs).

Operator path matches scripts/lab.sh: empty in/ → fixtures/demo → collectors
→ grc_loader → out/, then this script copies CISO/POA&M/estate pages into
product-lab/drop and rebuilds OpenGRC + Probo from those CSVs.

File-true leave-behind. posted=false. SAMPLE/DEMO fixtures ≠ LAB ≠ client.
Never POSTs. Never /api/risks. Cron-safe (no python -c).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from exporters.model import load_pack_estate
from exporters.opengrc import write_opengrc
from exporters.probo import write_probo

ROOT = Path(__file__).resolve().parents[1]
DROP = ROOT / "product-lab" / "drop"
CISO_CSVS = (
    "applied_controls.csv",
    "assets.csv",
    "evidences.csv",
    "findings.csv",
    "risk_scenarios.csv",
    "vulnerabilities.csv",
)
ESTATE_PAGES = ("EXECUTIVE_SUMMARY.md", "SCOPE_AND_TRUST.md")
# One row list for hashes + MANIFEST. Count is "draft" or a counts[] key
# (same as rel). poam_members.csv is this-scan plan members (#158).
MANIFEST_ROWS: tuple[tuple[str, str], ...] = (
    ("ciso/applied_controls.csv", "ciso/applied_controls.csv"),
    ("ciso/assets.csv", "ciso/assets.csv"),
    ("ciso/evidences.csv", "ciso/evidences.csv"),
    ("ciso/findings.csv", "ciso/findings.csv"),
    ("ciso/risk_scenarios.csv", "ciso/risk_scenarios.csv"),
    ("ciso/vulnerabilities.csv", "ciso/vulnerabilities.csv"),
    ("ciso/ESTATE.txt", "draft"),
    ("poam/poam.csv", "poam/poam.csv"),
    ("poam/poam.md", "draft"),
    ("poam/excluded.csv", "poam/excluded.csv"),
    ("poam/poam_members.csv", "poam/poam_members.csv"),
    ("poam/poam_fedramp.csv", "poam/poam_fedramp.csv"),
    ("poam/poam-ledger.json", "draft"),
    ("poam/ESTATE.txt", "draft"),
    ("EXECUTIVE_SUMMARY.md", "draft"),
    ("SCOPE_AND_TRUST.md", "draft"),
    ("opengrc/risks.csv", "opengrc/risks.csv"),
    ("opengrc/assets.csv", "opengrc/assets.csv"),
    ("opengrc/implementations.csv", "opengrc/implementations.csv"),
    ("import_preview/probo.json", "import_preview/probo.json"),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _csv_rows(path: Path) -> int:
    from shared.ciso_shape import csv_rows

    return len(csv_rows(path))


def _copied_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sync_from_out(src_out: Path, drop: Path = DROP) -> None:
    """Copy host-lab generator outputs into the packaged drop (DEMO/SAMPLE only)."""
    src_out = Path(src_out)
    drop = Path(drop)
    ciso_src = src_out / "ciso-assistant"
    if not (ciso_src / "findings.csv").is_file():
        raise SystemExit(f"no host-lab CISO CSVs under {ciso_src}")
    for name in CISO_CSVS:
        dest = drop / "ciso" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ciso_src / name, dest)
    estate = ciso_src / "ESTATE.txt"
    if estate.is_file():
        shutil.copy2(estate, drop / "ciso" / "ESTATE.txt")
    poam_src = src_out / "poam"
    if poam_src.is_dir():
        (drop / "poam").mkdir(parents=True, exist_ok=True)
        for path in sorted(poam_src.iterdir()):
            if path.is_file():
                shutil.copy2(path, drop / "poam" / path.name)
    for name in ESTATE_PAGES:
        src = src_out / name
        if src.is_file():
            shutil.copy2(src, drop / name)


def _write_manifest(counts: dict[str, int], hashes: dict[str, str]) -> None:
    copied = _copied_at()
    lines = [
        "# product-lab/drop MANIFEST — CISO Assistant CSVs + POA&M + OpenGRC + Probo",
        "",
        "Estate: demo (`in/` empty → fixtures/demo). Not a client. SAMPLE/DEMO ≠ LAB dest_in.",
        f"Copied from out/ after host lab {copied} (this Linux VM).",
        "OpenGRC/Probo files regenerated from packaged `ciso/` via `python -m exporters` (file-true, posted=false).",
        "Do not invent FindingsAssessment UUIDs. Import CISO CSVs with clica or the CISO Assistant UI.",
        "OpenGRC Data Manager CSVs are leave-behind only — not live import. Do not POST /api/risks.",
        "Probo `import_preview/probo.json` is documentation-only (posted=false). Not live GraphQL.",
        "POA&M owner/due are blank for a human. Do not POST /api/risks.",
        "",
        "| File | Rows | SHA256 |",
        "|---|---|---|",
    ]
    for rel, count_key in MANIFEST_ROWS:
        count = "draft" if count_key == "draft" else counts[count_key]
        lines.append(f"| {rel} | {count} | `{hashes[rel]}` |")
    lines.append("")
    lines.append("Do not POST /api/risks.")
    lines.append("")
    lines.append(
        "POA&M goldens this lab: SMB/445 (SMBv1 confirm, not a CVE), open RDP/3389, TLS weak cipher, admin shares, Telnet/23. Owner and due blank on every row."
    )
    lines.append("")
    lines.append(
        "Verify hashes with `sha256sum -c SHA256SUMS` or "
        "`python scripts/verify_manifest.py product-lab/drop` "
        "(MANIFEST is this count table, not sha256sum format)."
    )
    lines.append("")
    (DROP / "MANIFEST").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    sums = [f"{hashes[rel]}  {rel}" for rel, _count_key in MANIFEST_ROWS]
    (DROP / "SHA256SUMS").write_text(
        "\n".join(sums) + ("\n" if sums else ""),
        encoding="utf-8",
        newline="\n",
    )


def _write_readme(counts: dict[str, int]) -> None:
    text = f"""# Drop package

**Copied:** {_copied_at()} from this Linux VM `out/` after host lab (`scripts/lab.sh`).  
**Estate:** demo (`in/` empty → fixtures). SAMPLE/DEMO. Not a client. Not a LAB dest_in prove.

See `MANIFEST` for CISO CSV + POA&M + OpenGRC + Probo row counts. Verify bytes with `SHA256SUMS` (`sha256sum -c SHA256SUMS` or `python scripts/verify_manifest.py product-lab/drop`).

Hand `poam/poam.csv` with the CISO CSVs. Owner and due are blank.

OpenGRC and Probo files are **file-true leave-behind, posted=false, not live import**. Do not POST `/api/risks`.

## `ciso/`

CISO Assistant Community import CSVs. Headers are the contract. `risk_scenarios.csv` is **semicolon**-separated. Finding severity `low|medium|high|critical`. Vuln severity `Information|Low|Medium|High|Critical`. Asset type `PR` or `SP`. `filtering_labels` include wizard-safe `cpg_2_W` / `csf_*` (no colons).

`filtering_labels` include `estate_demo`. `ciso/ESTATE.txt` is the estate banner sidecar (import CSVs stay header-first). Preferred import: clica or CISO Assistant UI. Do not invent FindingsAssessment UUIDs.

| File | Rows |
|---|---|
| `assets.csv` | {counts["ciso/assets.csv"]} |
| `findings.csv` | {counts["ciso/findings.csv"]} |
| `vulnerabilities.csv` | {counts["ciso/vulnerabilities.csv"]} |
| `evidences.csv` | {counts["ciso/evidences.csv"]} |
| `applied_controls.csv` | {counts["ciso/applied_controls.csv"]} |
| `risk_scenarios.csv` | {counts["ciso/risk_scenarios.csv"]} |

## `poam/`

Operator draft. Not a CISO import. Owner and due stay blank. `poam.csv` has an `estate` column (DEMO/SAMPLE/LAB, never client KEEP). Banner lives in `poam/ESTATE.txt` plus `EXECUTIVE_SUMMARY.md` / `SCOPE_AND_TRUST.md`.

| File | Rows |
|---|---|
| `poam.csv` | {counts["poam/poam.csv"]} |
| `excluded.csv` | {counts.get("poam/excluded.csv", "")} |
| `poam_members.csv` | {counts.get("poam/poam_members.csv", "")} |
| `poam.md` | same draft, markdown |

`poam.csv` and `poam_members.csv` carry a per-row `estate` column. Member rows are this-scan plan rows (pending carried items can appear on `poam.csv` without a member row).

Example: open TCP/445 on `filesrv.corp.local` → restrict SMB / confirm SMBv1 disabled (`cpg_2_W`, `csf_PR`). Port finding, not a CVE.

## `opengrc/`

OpenGRC Data Manager CSVs (Risks / Assets / Implementations). File-true leave-behind. posted=false. Not live import. Do not POST `/api/risks`.

| File | Rows |
|---|---|
| `risks.csv` | {counts["opengrc/risks.csv"]} |
| `assets.csv` | {counts["opengrc/assets.csv"]} |
| `implementations.csv` | {counts["opengrc/implementations.csv"]} |

Operator path: Data Manager → Import Data → map headers. Status is **Not Assessed**. No taxonomy FKs invented.

## `import_preview/` + `probo/`

Probo drafts (`addFinding` / `addRisk`). File-true, posted=false, documentation-only. Not live GraphQL. `organization_id` stays null.

| File | Rows |
|---|---|
| `import_preview/probo.json` | {counts["import_preview/probo.json"]} addFinding drafts |

Do not POST `/api/risks`.
"""
    (DROP / "README.md").write_text(text, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"--from-out", "sync"}:
        raw = args[1] if len(args) > 1 else os.environ.get("OUT_DIR") or str(ROOT / "out")
        sync_from_out(Path(raw), DROP)
    estate = load_pack_estate(DROP)
    stamp = write_opengrc(DROP, estate=estate)
    probo_path = write_probo(DROP, estate=estate)
    payload = json.loads(probo_path.read_text(encoding="utf-8"))
    files = {rel: DROP.joinpath(*rel.split("/")) for rel, _count_key in MANIFEST_ROWS}
    hashes = {rel: _sha256(path) for rel, path in files.items()}
    counts: dict[str, int] = {}
    for rel, path in files.items():
        if path.suffix == ".csv":
            counts[rel] = _csv_rows(path)
        elif rel == "import_preview/probo.json":
            counts[rel] = int((payload.get("counts") or {}).get("addFinding") or 0)
        else:
            counts[rel] = 0
    _write_manifest(counts, hashes)
    _write_readme(counts)
    report = {
        "posted": False,
        "http": False,
        "sample": True,
        "lab": False,
        "client": False,
        "paying_day": "FAIL",
        "opengrc": stamp.get("counts"),
        "probo_addFinding": counts["import_preview/probo.json"],
        "dir": str(DROP),
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
