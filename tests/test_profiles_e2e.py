"""Internal + external DEMO scripts → in/ → control map → POA&M → CISO."""

from __future__ import annotations

import csv
import subprocess
from pathlib import Path

import pytest

from collectors.easm import parse_file as parse_easm
from collectors.grc_loader import load
from collectors.inventory_nmap import parse_file as parse_nmap
from shared.io_util import write_canonical

ROOT = Path(__file__).resolve().parents[1]


def test_internal_external_scripts_leave_demo_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "in"
    out = tmp_path / "out"
    monkeypatch.setenv("IN_DIR", str(work))
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("DROPBOX_DEMO", "1")
    monkeypatch.setenv("DROPBOX_LIVE", "0")
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    env = dict(**{k: str(v) for k, v in __import__("os").environ.items()})
    env["IN_DIR"] = str(work)
    env["OUT_DIR"] = str(out)
    env["PYTHONPATH"] = str(ROOT)
    env["DROPBOX_DEMO"] = "1"
    env["DROPBOX_LIVE"] = "0"
    for script in ("dropbox-internal.sh", "dropbox-external.sh"):
        proc = subprocess.run(
            ["bash", str(ROOT / "scripts" / script)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert "DEMO" in proc.stdout
    gnmap = work / "nmap" / "dropbox-inventory.gnmap"
    tls = work / "easm" / "dropbox-tls.jsonl"
    assert gnmap.is_file()
    assert tls.is_file()
    text = gnmap.read_text(encoding="utf-8")
    assert "DEMO — not a client estate" in text
    assert "Host:" in text and "Ports:" in text
    assert "445" in text and "3389" in text
    tls_text = tls.read_text(encoding="utf-8")
    assert "dropbox-demo" in tls_text
    assert "tls-weak-cipher" in tls_text
    assert "vpn.example.com" in tls_text
    nmap_recs = parse_nmap(gnmap)
    easm_recs = parse_easm(tls)
    assert any("demo" in (r.get("labels") or []) for r in nmap_recs)
    assert any("demo" in (r.get("labels") or []) for r in easm_recs)
    assert any(
        (r.get("extra") or {}).get("port") == "445" or "SMB" in (r.get("name") or "")
        for r in nmap_recs
        if r["kind"] == "finding"
    )
    assert any("RDP" in (r.get("name") or "") or (r.get("extra") or {}).get("port") == "3389" for r in nmap_recs)
    assert any("C$" in (r.get("name") or "") or "admin-share" in (r.get("labels") or []) for r in nmap_recs)
    assert any("TLS weak cipher" in (r.get("name") or "") for r in easm_recs)
    write_canonical("inventory-nmap", nmap_recs)
    write_canonical("easm", easm_recs)
    summary = load()
    assert summary.get("poam", 0) >= 1
    poam = out / "poam" / "poam.csv"
    with poam.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    blob = " ".join((r.get("weakness") or "") + " " + (r.get("recommended_fix") or "") for r in rows)
    assert "SMB" in blob or "445" in blob
    assert "RDP" in blob or "3389" in blob
    assert "TLS" in blob or "cipher" in blob.lower()
    assert "C$" in blob or "ADMIN$" in blob or "admin share" in blob.lower()
    for row in rows:
        assert row.get("owner") == ""
        assert row.get("due") == ""
        refs = row.get("framework_refs") or ""
        assert "cpg_" in refs and "csf_" in refs
    assert (out / "ciso-assistant" / "findings.csv").is_file()
    assert not (ROOT / "in" / "nmap" / "dropbox-inventory.gnmap").exists()
