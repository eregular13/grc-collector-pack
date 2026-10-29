"""Fail-before/pass-after: risk-scenario control refs must match imported control names.

CISO Assistant's RiskAssessment Data Wizard import splits ``additional_controls``
and ``existing_applied_controls`` on newline, pipe, semicolon or comma, then
resolves each token to an AppliedControl in the target folder:

- older wizard (``_create_or_find_controls``): ``AppliedControl.objects.filter(
  name=token, folder=domain)``. Exact, case-sensitive name only.
- newer wizard (``_resolve_named_objects``): ``ref_id=token`` first, then
  ``name__iexact=token``.

A token that matches nothing is CREATED as a new AppliedControl (status to_do).
map_ciso_csvs imports controls as ``title [CTL-ref]``. Before this fix the
risk scenarios referenced the suffix-stripped ``title``, so every row created a
second, ref_id-less control, doubling the imported control count.
Synthetic 192.0.2.x (RFC 5737) data only.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from shared.ciso_wizard_map import map_ciso_csvs

# Same split as CISO Assistant data_wizard ``_split_multi_separator``.
_CISO_SPLIT = re.compile(r"[\n|;,]")

_CONTROLS = [
    ("CTL-nmap-192-0-2-10-8080-tcp", "Reduce unnecessary network exposure (Open port 8080/http-alt (example (v2)))"),
    ("CTL-vuln-nikto-000001-192-0-2-10-80-admin", "Reduce unnecessary network exposure (Nikto: File/dir '/admin/' in robots.txt returned a non-forbidden or redirect HTTP code (200))"),
    ("CTL-ssh-lock", "Lock down SSH"),
]


def _split(cell: str) -> list[str]:
    return [t.strip() for t in _CISO_SPLIT.split(cell or "") if t.strip()]


def _write_pack_ciso(tmp: Path) -> Path:
    ciso = tmp / "ciso-assistant"
    ciso.mkdir(parents=True)
    (ciso / "assets.csv").write_text(
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n"
        "AST-1,192.0.2.10,desc,Global,Server,,,,\n",
        encoding="utf-8",
    )
    with (ciso / "applied_controls.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["ref_id", "name", "description", "domain", "status", "category", "priority", "csf_function"])
        for rid, title in _CONTROLS:
            # Pack SoR names carry " [ref_id]"; one raw title checks the mapper-added suffix too.
            name = title if rid == "CTL-ssh-lock" else f"{title} [{rid}]"
            w.writerow([rid, name, "desc", "Global", "to_do", "technical", "3", "protect"])
    (ciso / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\nF-1,Open SSH,desc,high,open,\n",
        encoding="utf-8",
    )
    (ciso / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,assets,applied_controls\n", encoding="utf-8"
    )
    hdr = (
        "ref_id;assets;threats;name;description;existing_controls;current_impact;current_proba;"
        "current_risk;additional_controls;residual_impact;residual_proba;residual_risk;treatment\n"
    )
    rows = "".join(
        f"RSK-{i};192.0.2.10;exposure;Scenario {i};desc;;Moderate;Moderate;Moderate;{rid};Low;Low;Low;mitigate\n"
        for i, (rid, _t) in enumerate(_CONTROLS)
    )
    (ciso / "risk_scenarios.csv").write_text(hdr + rows, encoding="utf-8")
    return ciso


def _mapped(tmp_path: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    ciso = _write_pack_ciso(tmp_path)
    dest = tmp_path / "mapped"
    map_ciso_csvs(ciso, dest, domain="LAB-TEST")
    with (dest / "applied_controls.csv").open(newline="", encoding="utf-8") as fh:
        controls = list(csv.DictReader(fh))
    text = (dest / "risk_scenarios.csv").read_text(encoding="utf-8")
    header = text.splitlines()[0]
    delim = ";" if header.count(";") > header.count(",") else ","
    scen = list(csv.DictReader(text.splitlines(True), delimiter=delim))
    return controls, scen


def test_every_risk_control_ref_exactly_matches_an_imported_control_name(tmp_path: Path) -> None:
    controls, scen = _mapped(tmp_path)
    imported = {(c.get("name") or "").strip() for c in controls}
    assert len(imported) == len(_CONTROLS)
    assert len(scen) == len(_CONTROLS)
    refs = 0
    for row in scen:
        for col in ("additional_controls", "existing_applied_controls"):
            for tok in _split(row.get(col) or ""):
                refs += 1
                assert tok in imported, (
                    f"{row.get('ref_id')} {col} token {tok!r} matches no imported "
                    f"applied_controls name; CISO would create a duplicate control"
                )
    assert refs == len(_CONTROLS)


def test_wizard_resolution_creates_no_extra_controls(tmp_path: Path) -> None:
    """Simulate both CISO resolution rules over the exported rows; count creations."""
    controls, scen = _mapped(tmp_path)
    by_name = {(c.get("name") or "").strip() for c in controls}
    by_name_ci = {n.casefold() for n in by_name}
    by_ref = {(c.get("ref_id") or "").strip() for c in controls}
    created_old: set[str] = set()
    created_new: set[str] = set()
    for row in scen:
        for tok in _split(row.get("additional_controls") or "") + _split(
            row.get("existing_applied_controls") or ""
        ):
            if tok not in by_name:  # older wizard: exact name in folder
                created_old.add(tok)
            if tok not in by_ref and tok.casefold() not in by_name_ci:  # newer wizard
                created_new.add(tok)
    assert created_old == set(), f"older wizard would create {len(created_old)}: {sorted(created_old)[:3]}"
    assert created_new == set(), f"newer wizard would create {len(created_new)}: {sorted(created_new)[:3]}"


def test_control_name_with_wizard_separator_falls_back_to_ref_id(tmp_path: Path) -> None:
    """A name containing , ; | or newline would be split by the wizard; use ref_id."""
    ciso = _write_pack_ciso(tmp_path)
    p = ciso / "applied_controls.csv"
    rows = list(csv.DictReader(p.open(newline="", encoding="utf-8")))
    rows[2]["name"] = "Lock down SSH, Telnet and rsh"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    dest = tmp_path / "mapped"
    map_ciso_csvs(ciso, dest, domain="LAB-TEST")
    scen = list(csv.DictReader((dest / "risk_scenarios.csv").open(newline="", encoding="utf-8")))
    ssh = [r for r in scen if r["ref_id"] == "RSK-2"][0]
    assert _split(ssh["additional_controls"]) == ["CTL-ssh-lock"], ssh["additional_controls"]
