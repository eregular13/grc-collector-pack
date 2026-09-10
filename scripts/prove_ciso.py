#!/usr/bin/env python3
"""SAMPLE/DEMO CISO prove: fixture Covey pack_drop + honeypot → out/ciso-assistant.

Uses the existing operator SoR path (`run_ciso_path` / `python3 -m dropbox ciso`).
Not a client estate. Never writes pack in/. Never POSTs. Paying-day stays FAIL.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
CISO_CSVS = (
    "assets.csv",
    "applied_controls.csv",
    "evidences.csv",
    "findings.csv",
    "vulnerabilities.csv",
    "risk_scenarios.csv",
)
SAMPLE_BANNER = (
    "SAMPLE/DEMO — not a client estate.\n"
    "Fixture Covey pack_drop (nmap + rustscan + httpx + unicornscan + sslscan + tlsx + whatweb + hping3 + onesixtyone + fping + naabu + nping) + honeypot file_drop. Not a client export.\n"
    "Not a paying-day stamp. RiskReady wrap stays review-only.\n"
)

ENV_KEYS = (
    "IN_DIR",
    "OUT_DIR",
    "DRY_RUN",
    "GRC_LIVE_SCAN",
    "CISO_PUSH",
    "RISKREADY_PUSH",
    "DROPBOX_LIVE",
    "DROPBOX_DEMO",
    "PYTHONPATH",
)


def _copy_tree(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        target = dest / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def seed_prove_in(dest_in: Path, root: Path | None = None) -> dict[str, Any]:
    """Copy labeled fixtures into dest_in. Never touches pack in/."""
    root = Path(root or ROOT)
    dest_in = Path(dest_in)
    if dest_in.exists():
        shutil.rmtree(dest_in)
    dest_in.mkdir(parents=True)
    nmap_drop = dest_in / "nmap" / "pack_drop"
    rustscan_drop = dest_in / "nmap" / "pack_drop" / "rustscan"
    httpx_drop = dest_in / "nmap" / "pack_drop" / "httpx"
    unicornscan_drop = dest_in / "nmap" / "pack_drop" / "unicornscan"
    sslscan_drop = dest_in / "nmap" / "pack_drop" / "sslscan"
    tlsx_drop = dest_in / "nmap" / "pack_drop" / "tlsx"
    whatweb_drop = dest_in / "nmap" / "pack_drop" / "whatweb"
    hping3_drop = dest_in / "nmap" / "pack_drop" / "hping3"
    onesixtyone_drop = dest_in / "nmap" / "pack_drop" / "onesixtyone"
    fping_drop = dest_in / "nmap" / "pack_drop" / "fping"
    naabu_drop = dest_in / "nmap" / "pack_drop" / "naabu"
    nping_drop = dest_in / "nmap" / "pack_drop" / "nping"
    honeypot = dest_in / "honeypot"
    beelzebub = dest_in / "honeypot" / "pack_drop"
    _copy_tree(root / "fixtures" / "pack_drop" / "nmap", nmap_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "rustscan", rustscan_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "httpx", httpx_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "unicornscan", unicornscan_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "sslscan", sslscan_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "tlsx", tlsx_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "whatweb", whatweb_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "hping3", hping3_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "onesixtyone", onesixtyone_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "fping", fping_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "naabu", naabu_drop)
    _copy_tree(root / "fixtures" / "pack_drop" / "nping", nping_drop)
    _copy_tree(root / "fixtures" / "demo" / "honeypot", honeypot)
    _copy_tree(root / "fixtures" / "demo" / "honeypot_beelzebub", beelzebub)
    (dest_in / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (nmap_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (rustscan_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (httpx_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (unicornscan_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (sslscan_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (tlsx_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (whatweb_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (hping3_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (onesixtyone_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (fping_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (naabu_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (nping_drop / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (honeypot / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (beelzebub / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    return {
        "dest_in": str(dest_in),
        "covey": str(nmap_drop),
        "rustscan": str(rustscan_drop),
        "httpx": str(httpx_drop),
        "unicornscan": str(unicornscan_drop),
        "sslscan": str(sslscan_drop),
        "tlsx": str(tlsx_drop),
        "whatweb": str(whatweb_drop),
        "hping3": str(hping3_drop),
        "onesixtyone": str(onesixtyone_drop),
        "fping": str(fping_drop),
        "naabu": str(naabu_drop),
        "nping": str(nping_drop),
        "honeypot": str(honeypot),
        "beelzebub": str(beelzebub),
        "sample": True,
        "client": False,
    }


def prove_ciso(root: Path | None = None, dest: Path | None = None) -> dict[str, Any]:
    """Seed fixtures → run_ciso_path → out/ciso-assistant. SAMPLE ≠ client."""
    from dropbox.orchestrator.ciso_path import run_ciso_path
    from dropbox.orchestrator.estate import fingerprint, pack_in_dir

    root = Path(root or ROOT)
    dest = Path(dest or (root / "prove" / "work"))
    dest_in = dest / "in"
    dest_out = dest / "out"
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    pack = pack_in_dir()
    before = fingerprint(pack)
    try:
        os.environ["DRY_RUN"] = "1"
        os.environ["GRC_LIVE_SCAN"] = "0"
        os.environ["CISO_PUSH"] = "0"
        os.environ["RISKREADY_PUSH"] = "0"
        os.environ["DROPBOX_LIVE"] = "0"
        os.environ["DROPBOX_DEMO"] = "1"
        os.environ.setdefault("PYTHONPATH", str(root))
        seed = seed_prove_in(dest_in, root)
        if dest_out.exists():
            shutil.rmtree(dest_out)
        dest_out.mkdir(parents=True)
        result = run_ciso_path(dest_in, dest_out, scope_path=SCOPE, write_pack_in=False)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    after = fingerprint(pack)
    ciso_dir = dest_out / "ciso-assistant"
    ciso_files = [name for name in CISO_CSVS if (ciso_dir / name).is_file()]
    findings_text = ""
    assets_text = ""
    if (ciso_dir / "findings.csv").is_file():
        findings_text = (ciso_dir / "findings.csv").read_text(encoding="utf-8")
    if (ciso_dir / "assets.csv").is_file():
        assets_text = (ciso_dir / "assets.csv").read_text(encoding="utf-8")
    summary: dict[str, Any] = {}
    if (dest_out / "summary.json").is_file():
        summary = json.loads((dest_out / "summary.json").read_text(encoding="utf-8"))
    paying = "FAIL"
    for line in (root / "STATUS.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("paying_day:"):
            paying = line.split(":", 1)[1].strip()
            break
    ok = (
        bool(ciso_files)
        and "filesrv.corp.local" in assets_text
        and "10.9.8.7" in assets_text
        and "10.9.8.20" in assets_text
        and "10.9.8.40" in assets_text
        and "10.9.8.50" in assets_text
        and "10.9.8.60" in assets_text
        and "10.9.8.70" in assets_text
        and "10.9.8.80" in assets_text
        and "10.9.8.81" in assets_text
        and "10.9.8.90" in assets_text
        and "10.9.8.91" in assets_text
        and "10.9.8.10" in assets_text
        and "10.9.8.11" in assets_text
        and "10.9.8.30" in assets_text
        and "10.9.8.31" in assets_text
        and "10.9.8.32" in assets_text
        and "10.9.8.33" in assets_text
        and "SMB" in findings_text
        and (
            "open_port_observed" in findings_text.lower()
            or "tcp/80" in findings_text.lower()
            or "open tcp/80" in findings_text.lower()
        )
        and "deception-sensor" in findings_text.lower()
        and ("beelzebub" in findings_text.lower() or "beelzebub" in assets_text.lower())
        and result.get("posted") is False
        and result.get("http") is False
        and after == before
        and paying == "FAIL"
        and result.get("sample") is True
        and result.get("client_keep") is False
        and result.get("pack_in_written") is False
    )
    stamp = {
        "status": "pass" if ok else "fail",
        "demo": True,
        "sample": True,
        "client": False,
        "client_keep": False,
        "estate": "SAMPLE/DEMO — not a client estate",
        "paying_day": paying,
        "posted": result.get("posted"),
        "http": result.get("http"),
        "wrap": "review-only",
        "sor": "ciso-assistant",
        "pack_in_used": False,
        "pack_in_written": after != before,
        "file_drop_read_only": True,
        "live": False,
        "hitl": True,
        "sensors": result.get("sensors"),
        "collectors": result.get("collectors"),
        "ciso_dir": str(ciso_dir),
        "ciso_files": [str(ciso_dir / name) for name in ciso_files],
        "counts": result.get("counts") or {
            "assets": summary.get("assets", 0),
            "findings": summary.get("findings", 0),
            "poam": summary.get("poam", 0),
            "demo": summary.get("demo"),
        },
        "seed": seed,
        "in_dir": str(dest_in),
        "out_dir": str(dest_out),
        "note": (
            "Fixture Covey pack_drop (nmap + rustscan + httpx + unicornscan + sslscan + tlsx + whatweb + hping3 + onesixtyone + fping + naabu + nping stdout-class) + honeypot → "
            "existing collectors → grc_loader → out/ciso-assistant. SAMPLE ≠ client. "
            "This prove is not a paying-day PASS."
        ),
    }
    if not ok:
        stamp["reason"] = {
            "ciso_files": ciso_files,
            "posted": result.get("posted"),
            "http": result.get("http"),
            "pack_in_written": after != before,
            "paying_day": paying,
            "sample": result.get("sample"),
            "client_keep": result.get("client_keep"),
        }
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "prove-ciso.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    return stamp


def main() -> int:
    stamp = prove_ciso()
    print(json.dumps(stamp, indent=2, default=str))
    print(
        f"PROVE_CISO={stamp['status']} sample={stamp['sample']} client={stamp['client']} "
        f"paying_day={stamp['paying_day']} posted={stamp['posted']} "
        f"assets={stamp['counts'].get('assets')} findings={stamp['counts'].get('findings')}"
    )
    if stamp.get("status") != "pass":
        return 1
    print("Estate is SAMPLE/DEMO fixtures. Not a client. Paying-day stays FAIL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
