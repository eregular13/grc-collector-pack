"""FARM_LAB_ALIGN: farm fixture seed vs LAB dest_in stay honest.

farm_drop_to_sor seeds SAMPLE fixtures/pack_drop (Brick 5 dual-net).
lab_drop_to_sor keeps operator dest_in (--use-existing-in; no reseed).
Both emit a risk register + POA&M. LAB != SAMPLE != client.
The SAMPLE nmap 172.16.10.0/24 "lab" segment is not fixtures/lab-drop
(192.168.64.0/24). Docs + meta labels only — no new public entrypoint.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FARM_NMAP = ROOT / "fixtures" / "pack_drop" / "nmap"
LAB_PACK = ROOT / "fixtures" / "lab-drop" / "nmap" / "pack_drop"
SAMPLE_NETS = ("10.0.0.", "172.16.10.")
LAB_NET = "192.168.64."
ALIGN_DOCS = (
    ROOT / "docs" / "FARM_SHIP_GATE.md",
    ROOT / "docs" / "PROVE_CISO.md",
    ROOT / "docs" / "COVEY_PACK_DROP.md",
)


def _jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        row = json.loads(text)
        assert isinstance(row, dict)
        rows.append(row)
    return rows


def _ips(path: Path) -> set[str]:
    out: set[str] = set()
    for row in _jsonl(path):
        ip = str(row.get("ip") or "")
        if ip:
            out.add(ip)
        extra = row.get("extra") if isinstance(row.get("extra"), dict) else {}
        extra_ip = str(extra.get("ip") or "")
        if extra_ip:
            out.add(extra_ip)
    return out


def test_farm_and_lab_nmap_meta_do_not_share_claim_class_labels() -> None:
    farm = json.loads((FARM_NMAP / "meta.json").read_text(encoding="utf-8"))
    lab = json.loads((LAB_PACK / "meta.json").read_text(encoding="utf-8"))
    for meta in (farm, lab):
        assert meta["schema"] == "covey.pack_drop.v1"
        assert meta["adapter"] == "nmap"
        assert meta["demo"] is True
        assert meta.get("client") is False
        note = str(meta.get("note") or "").lower()
        assert "not a client" in note
        assert "exposure" in note or "not a cve" in note
        assert "cve-" not in note
    assert farm.get("sample") is True
    assert farm.get("lab") is False
    assert lab.get("sample") is False
    assert lab.get("lab") is True
    farm_note = str(farm.get("note") or "")
    assert "172.16.10.0/24" in farm_note
    assert "192.168.64.0/24" in farm_note
    assert "lab-drop" in farm_note.lower() or "dest_in" in farm_note.lower()
    assert "SAMPLE" in farm_note
    lab_note = str(lab.get("note") or "").lower()
    assert "192.168.64.0/24" in str(lab.get("note") or "")
    assert "not sample" in lab_note
    assert "10.0.0.0/24" not in str(lab.get("note") or "")


def test_sample_lab_prefix_is_not_lab_dest_in() -> None:
    farm_ips = _ips(FARM_NMAP / "assets.jsonl") | _ips(FARM_NMAP / "findings.jsonl")
    lab_ips = _ips(LAB_PACK / "assets.jsonl") | _ips(LAB_PACK / "findings.jsonl")
    assert any(ip.startswith(SAMPLE_NETS[0]) for ip in farm_ips)
    assert any(ip.startswith(SAMPLE_NETS[1]) for ip in farm_ips)
    assert all(ip.startswith(LAB_NET) for ip in lab_ips), lab_ips
    for ip in farm_ips:
        assert not ip.startswith(LAB_NET), ip
    for ip in lab_ips:
        assert not any(ip.startswith(net) for net in SAMPLE_NETS), ip
    farm_blob = (FARM_NMAP / "assets.jsonl").read_text(encoding="utf-8")
    lab_blob = (LAB_PACK / "assets.jsonl").read_text(encoding="utf-8")
    assert "CVE-" not in farm_blob
    assert "CVE-" not in lab_blob
    assert "SAMPLE" in farm_blob
    assert "LAB" in lab_blob
    sample = (FARM_NMAP / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "172.16.10.0/24" in sample
    assert "192.168.64.0/24" in sample
    assert "farm_drop_to_sor" in sample
    assert "lab_drop_to_sor" in sample
    assert "LAB != SAMPLE != client" in sample
    sample.encode("cp1252")
    assert "\u2260" not in sample


def test_operator_docs_align_farm_seed_and_lab_dest_in() -> None:
    for path in ALIGN_DOCS:
        blob = path.read_text(encoding="utf-8")
        assert "farm_drop_to_sor" in blob, path.name
        assert "lab_drop_to_sor" in blob, path.name
        assert "fixtures/pack_drop" in blob, path.name
        assert "192.168.64.0/24" in blob, path.name
        assert "172.16.10.0/24" in blob, path.name
        low = blob.lower()
        assert "lab != sample != client" in low or "lab ≠ sample ≠ client" in low
        assert "risk register" in low or "risk-register" in low
        assert "poam" in low or "poa&m" in low
        assert "paying_day" in blob and "FAIL" in blob
        assert "not a client" in low or "!= client" in low or "≠ client" in low
    farm_gate = (ROOT / "docs" / "FARM_SHIP_GATE.md").read_text(encoding="utf-8")
    assert "out of scope here" not in farm_gate
    assert "Brick 5" in farm_gate
    assert "no fixture reseed" in farm_gate.lower() or "--use-existing-in" in farm_gate
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "lab-drop-to-sor:" not in makefile
    readme_head = "".join((ROOT / "README.md").read_text(encoding="utf-8").splitlines()[:12])
    assert "lab_drop_to_sor" not in readme_head
