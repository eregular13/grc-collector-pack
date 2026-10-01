"""Packaged product-lab/drop must match a fresh host-lab generator run.

Argus cold-review: a Sep-4 drop (61 POA&M, no estate banner/column) is what
repo browsers and console fallback see. This test fails when the committed
drop drifts from collectors + grc_loader + refresh on HEAD.

Compares masked content (not just IDs/counts) for CISO CSVs, poam.csv,
poam.md, FedRAMP, excluded.csv, and the POA&M ledger. Masks status_date,
run stamps, pack/commit lines, and ledger clocks so the check stays TZ-
and date-proof. The drop has no simplerisk/ folder — that surface is not
locked here.

DEMO/SAMPLE fixtures. Never client KEEP. No POST /api/risks.
"""

from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from shared.ciso_shape import CISO_HEADERS, POAM_HEADER, csv_rows
from shared.poam_fedramp import FEDRAMP_CSV_HEADERS
from shared.poam_fields import SLA_NOTE

ROOT = Path(__file__).resolve().parents[1]
DROP = ROOT / "product-lab" / "drop"
COLLECTORS = (
    "cloud_prowler",
    "inventory_nmap",
    "vuln_scan",
    "host_wazuh",
    "identity_ad",
    "easm",
    "k8s_kubescape",
    "code_secrets",
    "saas_idp",
    "dns_email",
    "honeypot",
    "grc_loader",
)
CISO_FILES = (
    "applied_controls.csv",
    "assets.csv",
    "evidences.csv",
    "findings.csv",
    "risk_scenarios.csv",
    "vulnerabilities.csv",
)
# Host-lab empty-in snapshot after master #192 slim register + #203–#218.
# Sep-4 drop was 62/62/15/61; pre-#192 lock was 79/107/22/34/129 / poam 124.
# filesrv.corp.local is NMAP-asset-10-0-0-50 (alias collapsed).
PACKAGED_COUNTS = {
    "assets.csv": 79,
    "findings.csv": 103,
    "vulnerabilities.csv": 22,
    "evidences.csv": 34,
    "applied_controls.csv": 119,
    "risk_scenarios.csv": 125,
}
PACKAGED_POAM = 119
PACKAGED_EXCLUDED = 6
# IDs that exist in both packaged drop and a fresh generator run.
KEY_ASSET_IDS = {
    "NMAP-asset-10-0-0-50",
    "NMAP-asset-dc-corp-local",
    "K8S-asset-prod-cluster",
    "CLD-asset-iam-admin-breakglass",
    "WAZ-asset-web-01",
    "HPOT-asset-ssh-canary-01",
}
EGP_RE = re.compile(r"EGP-[0-9A-F]{10}")
# Run clocks / pack SHA only. Do not mask SLA scheduled dates or artifact days.
_ISO_Z_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_STAMP_RE = re.compile(
    r"generated \d{4}-\d{2}-\d{2} \d{2}:\d{2}(?: \S+)? · pack `?[0-9a-f]+`?",
    re.IGNORECASE,
)
_STAMP_ALT_RE = re.compile(
    r"pack `?[0-9a-f]+`?, generated \d{4}-\d{2}-\d{2} \d{2}:\d{2}(?: \S+)?",
    re.IGNORECASE,
)
LEDGER_CLOCK_KEYS = frozenset(
    {"first_seen", "last_seen", "run_at", "status_date", "sha256", "at"}
)


def _hermetic_env(out: Path, inn: Path) -> dict[str, str]:
    """Empty-in demo lab. Do not inherit a leaked LAB/FIXTURES_DIR from pytest."""
    keep = (
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "SYSTEMROOT",
        "TMPDIR",
        "TMP",
        "TEMP",
        "TZ",
    )
    env = {key: os.environ[key] for key in keep if os.environ.get(key)}
    env["PYTHONPATH"] = str(ROOT)
    env["OUT_DIR"] = str(out)
    env["IN_DIR"] = str(inn)
    env["FIXTURES_DIR"] = str(ROOT / "fixtures" / "demo")
    env["DRY_RUN"] = "1"
    env["GRC_LIVE_SCAN"] = "0"
    env["CISO_PUSH"] = "0"
    env["RISKREADY_PUSH"] = "0"
    env["DROPBOX_LIVE"] = "0"
    return env


def _run_fresh_lab(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    inn = tmp_path / "in"
    inn.mkdir()
    out.mkdir()
    env = _hermetic_env(out, inn)
    for name in COLLECTORS:
        subprocess.run(
            [sys.executable, str(ROOT / "collectors" / f"{name}.py")],
            cwd=str(ROOT),
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
    return out


def _ids(path: Path, header: str, key: str) -> set[str]:
    delim = ";" if path.name == "risk_scenarios.csv" else ","
    rows = csv_rows(path, delimiter=delim)
    assert rows or path.stat().st_size > 0
    first = path.read_text(encoding="utf-8").splitlines()[0].strip()
    assert first == header, (path.name, first, header)
    return {str(row.get(key) or "") for row in rows if str(row.get(key) or "")}


def _fedramp_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    first = path.read_text(encoding="utf-8").splitlines()[0].strip()
    assert first == ",".join(FEDRAMP_CSV_HEADERS), (path.name, first)
    return rows


def _is_status_date_key(key: str) -> bool:
    return key.strip().lower().replace("_", " ") == "status date"


def _mask_run_stamps(text: str) -> str:
    text = _ISO_Z_RE.sub("<RUN_ISO>", text)
    text = _STAMP_RE.sub("generated <STAMP> · pack <PACK>", text)
    text = _STAMP_ALT_RE.sub("pack <PACK>, generated <STAMP>", text)
    return text


def _mask_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    masked: list[dict[str, str]] = []
    for row in rows:
        out: dict[str, str] = {}
        for key, value in row.items():
            cell = str(value or "")
            if _is_status_date_key(str(key or "")):
                out[str(key)] = "<STATUS_DATE>"
            else:
                out[str(key)] = _mask_run_stamps(cell)
        masked.append(out)
    return masked


def _mask_ledger(obj: object) -> object:
    if isinstance(obj, dict):
        out: dict[str, object] = {}
        for key, value in obj.items():
            if key in LEDGER_CLOCK_KEYS:
                out[key] = "<CLOCK>"
            else:
                out[key] = _mask_ledger(value)
        return out
    if isinstance(obj, list):
        return [_mask_ledger(item) for item in obj]
    return obj


def _first_row_diff(left: list[dict[str, str]], right: list[dict[str, str]]) -> object:
    if len(left) != len(right):
        return ("len", len(left), len(right))
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            keys = sorted(set(a) | set(b))
            cells = [(k, a.get(k), b.get(k)) for k in keys if a.get(k) != b.get(k)]
            return (index, cells[:8])
    return ()


def test_product_lab_drop_matches_fresh_generator(tmp_path: Path) -> None:
    fresh = _run_fresh_lab(tmp_path)
    drop_ciso = DROP / "ciso"
    fresh_ciso = fresh / "ciso-assistant"

    for name in CISO_FILES:
        header = CISO_HEADERS[name]
        key = "name" if name == "evidences.csv" else "ref_id"
        delim = ";" if name == "risk_scenarios.csv" else ","
        packaged_rows = csv_rows(drop_ciso / name, delimiter=delim)
        generated_rows = csv_rows(fresh_ciso / name, delimiter=delim)
        packaged = _ids(drop_ciso / name, header, key)
        generated = _ids(fresh_ciso / name, header, key)
        if name in PACKAGED_COUNTS:
            assert len(packaged) == PACKAGED_COUNTS[name], (name, len(packaged))
        assert generated, name
        assert packaged == generated, (name, sorted(packaged ^ generated)[:20])
        assert _mask_rows(packaged_rows) == _mask_rows(generated_rows), (
            name,
            _first_row_diff(_mask_rows(packaged_rows), _mask_rows(generated_rows)),
        )
        if name == "assets.csv":
            assert KEY_ASSET_IDS <= packaged, packaged
            assert KEY_ASSET_IDS <= generated, generated

    findings = csv_rows(drop_ciso / "findings.csv")
    assert findings
    assert all("estate_demo" in (row.get("filtering_labels") or "") for row in findings)
    assert all("CLIENT" not in (row.get("filtering_labels") or "").upper() for row in findings)

    poam_drop = DROP / "poam" / "poam.csv"
    poam_fresh = fresh / "poam" / "poam.csv"
    assert poam_drop.read_text(encoding="utf-8").splitlines()[0].strip() == POAM_HEADER
    assert poam_fresh.read_text(encoding="utf-8").splitlines()[0].strip() == POAM_HEADER
    drop_poam = csv_rows(poam_drop)
    fresh_poam = csv_rows(poam_fresh)
    drop_excluded = csv_rows(DROP / "poam" / "excluded.csv")
    fresh_excluded = csv_rows(fresh / "poam" / "excluded.csv")
    drop_ids = {str(r.get("poam_id") or "") for r in drop_poam if r.get("poam_id")}
    fresh_ids = {str(r.get("poam_id") or "") for r in fresh_poam if r.get("poam_id")}
    assert drop_ids == fresh_ids, sorted(drop_ids ^ fresh_ids)[:20]
    assert len(drop_poam) == PACKAGED_POAM
    assert len(fresh_poam) == PACKAGED_POAM
    assert len(drop_excluded) == PACKAGED_EXCLUDED
    assert len(fresh_excluded) == PACKAGED_EXCLUDED
    assert _mask_rows(drop_poam) == _mask_rows(fresh_poam), _first_row_diff(
        _mask_rows(drop_poam), _mask_rows(fresh_poam)
    )
    assert _mask_rows(drop_excluded) == _mask_rows(fresh_excluded), _first_row_diff(
        _mask_rows(drop_excluded), _mask_rows(fresh_excluded)
    )
    assert {str(r.get("excluded_reason") or "") for r in drop_excluded} >= {
        "honeypot",
        "telemetry",
        "superseded_by_specific",
    }
    assert "estate" in POAM_HEADER
    estates = {str(r.get("estate") or "") for r in drop_poam}
    assert estates
    assert all("CLIENT" not in e.upper() or "NOT A CLIENT" in e.upper() for e in estates)
    assert any("DEMO" in e.upper() or "SAMPLE" in e.upper() for e in estates)
    assert all((r.get("owner") or "") == "" and (r.get("due") or "") == "" for r in drop_poam)
    for row in drop_poam + fresh_poam:
        day = str(row.get("status_date") or "")
        assert len(day) == 10 and day[4] == "-" and day[7] == "-", day

    md_drop = (DROP / "poam" / "poam.md").read_text(encoding="utf-8")
    md_fresh = (fresh / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "status_date is the UTC" not in md_drop
    assert "status_date is the UTC" not in md_fresh
    assert "status_date is the UTC" not in SLA_NOTE
    assert "host-local" in md_drop
    assert "host-local" in md_fresh
    assert "host-local" in SLA_NOTE
    assert EGP_RE.findall(md_drop)
    assert set(EGP_RE.findall(md_drop)) == drop_ids
    assert set(EGP_RE.findall(md_fresh)) == fresh_ids
    assert _mask_run_stamps(md_drop) == _mask_run_stamps(md_fresh)

    fed_drop = DROP / "poam" / "poam_fedramp.csv"
    fed_fresh = fresh / "poam" / "poam_fedramp.csv"
    assert fed_drop.is_file()
    assert fed_fresh.is_file()
    drop_fed = _fedramp_rows(fed_drop)
    fresh_fed = _fedramp_rows(fed_fresh)
    assert {str(r.get("POAM ID") or "") for r in drop_fed if r.get("POAM ID")} == drop_ids
    assert {str(r.get("POAM ID") or "") for r in fresh_fed if r.get("POAM ID")} == fresh_ids
    assert _mask_rows(drop_fed) == _mask_rows(fresh_fed), _first_row_diff(
        _mask_rows(drop_fed), _mask_rows(fresh_fed)
    )

    ledger_drop = DROP / "poam" / "poam-ledger.json"
    ledger_fresh = fresh / "poam" / "poam-ledger.json"
    assert ledger_drop.is_file()
    assert ledger_fresh.is_file()
    drop_ledger = json.loads(ledger_drop.read_text(encoding="utf-8"))
    fresh_ledger = json.loads(ledger_fresh.read_text(encoding="utf-8"))
    assert _mask_ledger(drop_ledger) == _mask_ledger(fresh_ledger)

    # Fresh SimpleRisk is an internal consistency check only. The packaged
    # drop has no simplerisk/ folder, so that surface is not hashed or locked.
    sr_fresh = fresh / "simplerisk" / "poam.csv"
    assert sr_fresh.is_file()
    sr_fresh_ids = _ids(sr_fresh, POAM_HEADER, "poam_id")
    assert sr_fresh_ids == fresh_ids
    assert not (DROP / "simplerisk").exists()

    for rel in (
        "ciso/ESTATE.txt",
        "poam/ESTATE.txt",
        "EXECUTIVE_SUMMARY.md",
        "SCOPE_AND_TRUST.md",
    ):
        text = (DROP / rel).read_text(encoding="utf-8")
        assert "DEMO: NOT A CLIENT" in text or "SAMPLE DATA: NOT A CLIENT" in text, rel
        assert "not a client" in text.lower()
        # Honesty copy may say "never client KEEP"; a CLIENT KEEP banner would not.
        first = text.splitlines()[0]
        assert first.startswith(">") or first.startswith("DEMO") or first.startswith("SAMPLE")
        assert "CLIENT KEEP:" not in text.upper()

    assert not (DROP / "riskready").exists()
    # findings + vulns == poam + excluded when no kind_excluded / merge remainder.
    # After #192 slim register, packaged and fresh must still agree with each other.
    drop_vulns = csv_rows(drop_ciso / "vulnerabilities.csv")
    fresh_findings = csv_rows(fresh_ciso / "findings.csv")
    fresh_vulns = csv_rows(fresh_ciso / "vulnerabilities.csv")
    assert len(findings) + len(drop_vulns) == len(fresh_findings) + len(fresh_vulns)
    assert len(drop_poam) + len(drop_excluded) == len(fresh_poam) + len(fresh_excluded)
