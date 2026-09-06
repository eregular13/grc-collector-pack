from __future__ import annotations

import json
import os
from pathlib import Path

from tests.scope_clock import LAB_EXTERNAL, LAB_SCOPE, closed_stamps

ROOT = Path(__file__).resolve().parents[1]


def _product_lab_drop() -> Path:
    raw = os.environ.get("PRODUCT_LAB_DROP")
    return Path(raw).resolve() if raw else (ROOT.parent / "product-lab" / "drop")


def test_plan_without_binaries() -> None:
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    plan = build_plan(scope)
    assert plan["signed"] is True
    assert plan["brakes"]["refuse_live"] is None
    assert plan["brakes"]["deepen_batch_size"] == 3
    assert plan["discover_cidr_shards"]
    assert plan["discover_cidr_shards"][0]["shard_count"] >= 1
    assert "discover" in plan["stages"]


def test_unsigned_scope_refuses_live(monkeypatch) -> None:
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(nmap_byo.subprocess, "run", lambda *a, **k: called.append(1))
    scope = load_scope(ROOT / "dropbox" / "SCOPE.unsigned.yaml")
    assert scope.refuse_live() == "unsigned_or_consent_false"
    payload = run(ROOT / "dropbox" / "SCOPE.unsigned.yaml", "discover")
    assert payload.get("refused") == "unsigned_or_consent_false"
    payload2 = run(ROOT / "dropbox" / "SCOPE.unsigned.yaml", "deepen")
    assert payload2.get("refused") == "unsigned_or_consent_false"
    assert called == []


def test_empty_targets_refuses_live() -> None:
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(ROOT / "dropbox" / "SCOPE.empty.yaml")
    assert scope.refuse_live() == "empty_targets"
    payload = run(ROOT / "dropbox" / "SCOPE.empty.yaml", "discover")
    assert payload.get("refused") == "empty_targets"
    all_payload = run(ROOT / "dropbox" / "SCOPE.empty.yaml", "all")
    assert all_payload.get("refused") == "empty_targets"
    assert all_payload["ingest"].get("drop_copied") is False
    assert all_payload["grc_export"]["client_facing_ready"] is False


def test_refuse_if_unsigned_false_cannot_bypass(tmp_path, monkeypatch) -> None:
    """SCOPE cannot toggle off the unsigned live brake."""
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(nmap_byo.subprocess, "run", lambda *a, **k: called.append(1))
    path = tmp_path / "SCOPE.bypass.yaml"
    path.write_text(
        """
client_legal_name: "Bypass Lab"
named_contact: "Pat"
consent_attested: false
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  refuse_if_unsigned: false
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.integrity.refuse_if_unsigned is True
    assert scope.refuse_live() == "unsigned_or_consent_false"
    payload = run(path, "discover")
    assert payload.get("refused") == "unsigned_or_consent_false"
    assert called == []


def test_refuse_if_empty_targets_false_cannot_bypass(tmp_path) -> None:
    """SCOPE cannot toggle off the empty-target live brake."""
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.notargets.yaml"
    path.write_text(
        """
client_legal_name: "No Target Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: []
  hosts: []
external:
  hostnames: []
  urls: []
allow_tools: [nmap]
profiles: [internal]
integrity:
  refuse_if_empty_targets: false
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.integrity.refuse_if_empty_targets is True
    assert scope.refuse_live() == "empty_targets"
    payload = run(path, "discover")
    assert payload.get("refused") == "empty_targets"


def test_yaml_yes_cannot_attest_consent(tmp_path, monkeypatch) -> None:
    """Only lowercase true attests. yes/True cannot unlock live stages."""
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(nmap_byo.subprocess, "run", lambda *a, **k: called.append(1))
    path = tmp_path / "SCOPE.yes.yaml"
    path.write_text(
        """
client_legal_name: "Yes Lab"
named_contact: "Pat"
consent_attested: yes
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: yes
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.consent_attested is False
    assert scope.integrity.allow_live_exec is False
    assert scope.refuse_live() == "unsigned_or_consent_false"
    payload = run(path, "discover")
    assert payload.get("refused") == "unsigned_or_consent_false"
    assert called == []


def test_evergreen_orch_live_true_does_not_exec(tmp_path, monkeypatch) -> None:
    """EVERGREEN_ORCH_LIVE must be 1. true/yes do not enable BYO exec."""
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.run import run

    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "true")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(
        nmap_byo.subprocess,
        "run",
        lambda *a, **k: called.append(1) or (_ for _ in ()).throw(AssertionError("nmap ran")),
    )
    path = tmp_path / "SCOPE.live.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    payload = run(path, "discover")
    assert called == []
    assert payload["discover"]["label"] == "fixture"


def test_deepen_batch_size_capped() -> None:
    from dropbox.orchestrator.plan import deepen_batches

    hosts = [f"h{i}.lab" for i in range(11)]
    batches = deepen_batches(hosts, 3)
    assert all(len(b) <= 3 for b in batches)
    assert sum(len(b) for b in batches) == 11
    huge = deepen_batches(hosts, 99)
    assert all(len(b) <= 5 for b in huge)


def test_concurrency_caps_cannot_hail_mary(tmp_path) -> None:
    """SCOPE cannot raise deepen/discover concurrency into a spray."""
    from dropbox.orchestrator.plan import build_plan, concurrent_waves
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.spray.yaml"
    path.write_text(
        """
client_legal_name: "Spray Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap, nessus]
profiles: [internal]
batch:
  discover_shard_size: 9999
  deepen_batch_size: 99
  max_concurrent_discover: 99
  max_concurrent_deepen: 99
integrity:
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.batch.discover_shard_size == 256
    assert scope.batch.deepen_batch_size == 5
    assert scope.batch.max_concurrent_discover == 4
    assert scope.batch.max_concurrent_deepen == 2
    plan = build_plan(scope)
    assert plan["brakes"]["discover_shard_size"] == 256
    assert plan["brakes"]["deepen_batch_size"] == 5
    assert plan["brakes"]["max_concurrent_discover"] == 4
    assert plan["brakes"]["max_concurrent_deepen"] == 2
    waves = concurrent_waves(list(range(20)), scope.batch.max_concurrent_deepen)
    assert waves
    assert all(len(wave) <= 2 for wave in waves)


def test_nmap_adapter_plan_only_without_live_flag() -> None:
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    desc = nmap_byo.describe(scope, ["10.0.0.1"])
    assert desc["would_exec"] is False
    assert desc["command"][0] == "nmap"
    assert "-sn" in desc["command"]
    assert "-sV" not in desc["command"]
    assert "embed" in desc["note"].lower() or "BYO" in desc["note"]
    executed = nmap_byo.execute(scope, ["10.0.0.1"])
    assert executed["executed"] is False
    assert executed["hosts"] == []


def test_fixture_quiet_loud_ingest_poam() -> None:
    from dropbox.orchestrator.run import run

    payload = run(LAB_SCOPE, "all")
    assert payload.get("refused") is None
    dest = ROOT / "dropbox" / "out"
    assert (dest / "discover.json").is_file()
    assert (dest / "deepen.json").is_file()
    assert (dest / "poam.csv").is_file()
    csv_text = (dest / "poam.csv").read_text(encoding="utf-8")
    assert "SMBv1" in csv_text
    assert "CPG" in csv_text
    assert "open" in csv_text
    mapped = json.loads((dest / "control_map.json").read_text(encoding="utf-8"))
    assert any(r.get("mapped") for r in mapped["rows"])
    assert (ROOT / "out" / "poam" / "poam.csv").is_file()
    ciso = ROOT / "out" / "ciso-assistant" / "assets.csv"
    # prior lab or ingest preview; smoke: pack CISO path exists after a lab, not required here
    assert payload["ingest"]["label"] == "fixture"


def test_smb_v1_golden_maps() -> None:
    from dropbox.orchestrator.poam import map_finding

    row = map_finding("SMBv1 enabled", "file01.corp.local", "critical")
    assert row["mapped"] is True
    assert "CPG 2.H" in row["control_refs"]
    assert row["status"] == "open"
    assert row["owner"] == ""
    unknown = map_finding("weird-obscure-thing", "x", "low")
    assert unknown["mapped"] is False
    assert "UNMAPPED" in unknown["control_refs"]


def test_cleartext_http_and_headers_map() -> None:
    from dropbox.orchestrator.poam import map_finding

    http = map_finding("Cleartext HTTP", "127.0.0.1", "medium")
    assert http["mapped"] is True
    assert "CPG 2.W" in http["control_refs"]
    assert "PR.DS-02" in http["csf"]
    assert "UNMAPPED" not in http["control_refs"]
    hsts = map_finding("Missing HSTS", "127.0.0.1", "medium")
    assert hsts["mapped"] is True
    xfo = map_finding("Missing X-Frame-Options", "127.0.0.1", "low")
    assert xfo["mapped"] is True
    csp = map_finding("Missing CSP", "127.0.0.1", "low")
    assert csp["mapped"] is True
    banner = map_finding("Server banner disclosure", "127.0.0.1", "low")
    assert banner["mapped"] is True
    # Do not invent SMBv1 from HTTP.
    assert "SMBv1" not in http["weakness"]
    assert "445" not in http["recommended_action"]
    tls = map_finding("Untrusted TLS certificate", "127.0.0.1", "medium")
    assert tls["mapped"] is True
    assert "UNMAPPED" not in tls["control_refs"]
    assert "SMBv1" not in tls["weakness"]


def test_destroy_workers_after_discover() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "workers").mkdir(exist_ok=True)
    leftover = dest / "workers" / "crashed-discover.alive"
    leftover.write_text("alive\n", encoding="utf-8")
    run(LAB_SCOPE, "discover")
    destroy = json.loads((dest / "destroy_discover.json").read_text(encoding="utf-8"))
    assert destroy["destroyed"]
    alive = list((dest / "workers").glob("*.alive"))
    assert alive == []
    assert leftover.is_file() is False
    discover = json.loads((dest / "discover.json").read_text(encoding="utf-8"))
    cap = int(discover["max_concurrent"])
    assert cap >= 1
    assert all(len(wave) <= cap for wave in discover.get("waves") or [])
    assert "printer-down.corp.local" not in {
        row.get("host") for row in discover.get("hosts") or []
    }


def test_external_fixture_ingest_skips_internal_pack_demo() -> None:
    """External-only fixture ingest must not dump internal pack SMBv1/Telnet into POA&M."""
    from dropbox.orchestrator.run import run

    payload = run(LAB_EXTERNAL, "all")
    assert payload.get("refused") is None
    assert payload["ingest"]["label"] == "fixture"
    preview = json.loads((ROOT / "in" / "_dropbox_preview" / "findings.json").read_text(encoding="utf-8"))
    hosts = {str(r.get("host") or r.get("asset") or "") for r in preview.get("findings") or []}
    names = {str(r.get("name") or r.get("weakness") or "") for r in preview.get("findings") or []}
    assert "file01.corp.local" not in hosts
    assert "inside.corp.local" not in hosts
    assert "SMBv1 enabled" not in names
    assert "Telnet exposed" not in names
    poam = (ROOT / "dropbox" / "out" / "poam.csv").read_text(encoding="utf-8")
    assert "file01.corp.local" not in poam
    assert "inside.corp.local" not in poam


def test_internal_fixture_ingest_skips_external_pack_demo(tmp_path) -> None:
    """Internal-only fixture ingest must not dump vpn/TLS pack demo into POA&M."""
    from dropbox.orchestrator.run import run

    path = tmp_path / "SCOPE.internal.yaml"
    path.write_text(
        """
client_legal_name: "Inside Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local", "smb-legacy.corp.local"]
external:
  hostnames: ["vpn.example-corp.com"]
  urls: ["https://vpn.example-corp.com"]
allow_tools: [nmap, nessus]
profiles: [internal]
integrity:
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    dest = tmp_path / "out"
    payload = run(path, "all", dest=dest)
    assert payload.get("refused") is None
    assert payload["ingest"]["label"] == "fixture"
    preview = json.loads((dest / "in-preview" / "findings.json").read_text(encoding="utf-8"))
    hosts = {str(r.get("host") or r.get("asset") or "") for r in preview.get("findings") or []}
    assert "vpn.example-corp.com" not in hosts
    poam = (dest / "poam.csv").read_text(encoding="utf-8")
    assert "vpn.example-corp.com" not in poam
    if _product_lab_drop().is_dir():
        assert payload["ingest"].get("drop_copied") is True


def test_external_profile_ignores_internal_cidrs() -> None:
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_EXTERNAL)
    assert scope.uses_external() is True
    assert scope.uses_internal() is False
    assert scope.discover_cidrs() == []
    assert "vpn.example-corp.com" in scope.discover_hosts()
    assert "inside.corp.local" not in scope.discover_hosts()
    plan = build_plan(scope)
    assert plan["discover_cidr_shards"] == []
    assert plan["external"]["hostnames"] == ["vpn.example-corp.com"]
    assert plan["tool_gates"]["nmap"].startswith("nmap_needs_")
    assert plan["tool_gates"]["testssl"] == "ok"
    assert plan["brakes"]["refuse_live"] is None


def test_internal_profile_does_not_spray_external(tmp_path) -> None:
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.internal.yaml"
    path.write_text(
        """
client_legal_name: "Inside Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
external:
  hostnames: ["vpn.example-corp.com"]
  urls: ["https://vpn.example-corp.com"]
allow_tools: [nmap]
profiles: [internal]
batch:
  deepen_batch_size: 3
integrity:
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    plan = build_plan(scope)
    assert plan["profile_isolation"]["uses_external"] is False
    assert plan["external"]["hostnames"] == []
    assert plan["external"]["urls"] == []
    assert "vpn.example-corp.com" not in scope.discover_hosts()
    assert plan["discover_cidr_shards"][0]["cidr"] == "10.0.0.0/24"


def test_cidr_only_does_not_unlock_testssl(tmp_path) -> None:
    from dropbox.orchestrator.adapters import testssl_byo
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.cidr.yaml"
    path.write_text(
        """
client_legal_name: "CIDR Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: []
external:
  hostnames: []
  urls: []
allow_tools: [testssl]
profiles: [internal]
integrity:
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.tool_gate("testssl")
    assert scope.refuse_live() == "no_tool_matches_target_kind"
    desc = testssl_byo.describe(scope, ["10.0.0.0/24"])
    assert desc["would_exec"] is False
    assert desc["cidr_refused"] == ["10.0.0.0/24"]
    assert desc["target_kind_gate"]


def test_entra_only_does_not_unlock_lynis(tmp_path) -> None:
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.entra.yaml"
    path.write_text(
        """
client_legal_name: "Entra Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: []
  hosts: []
  endpoints: []
entra:
  tenants: ["litware.onmicrosoft.com"]
allow_tools: [lynis]
profiles: [internal]
integrity:
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert "entra" in scope.kinds_present()
    assert "endpoint" not in scope.kinds_present()
    assert scope.tool_gate("lynis") == "lynis_needs_endpoint"
    assert scope.refuse_live() == "no_tool_matches_target_kind"


def test_window_closed_refuses_live(tmp_path) -> None:
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.window.yaml"
    path.write_text(
        """
client_legal_name: "Expired Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2020-01-01T00:00:00-07:00"
window_end: "2020-01-02T00:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  refuse_if_unsigned: true
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.refuse_live() == "window_closed"
    payload = run(path, "discover")
    assert payload.get("refused") == "window_closed"


def test_example_scope_documents_window_closed() -> None:
    """Historic SCOPE.example.yaml may expire. That is not live-eligible."""
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(ROOT / "dropbox" / "SCOPE.example.yaml")
    assert scope.integrity.allow_live_exec is False
    assert scope.refuse_live() == "window_closed"


def test_relative_past_window_refuses_live(tmp_path) -> None:
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    start, end = closed_stamps()
    path = tmp_path / "SCOPE.closed-relative.yaml"
    path.write_text(
        f"""
client_legal_name: "Closed Relative Lab"
named_contact: "Pat"
consent_attested: true
window_start: "{start}"
window_end: "{end}"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.refuse_live() == "window_closed"
    payload = run(path, "discover")
    assert payload.get("refused") == "window_closed"


def test_lab_scope_is_not_live_eligible() -> None:
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    assert scope.integrity.allow_live_exec is False
    assert scope.refuse_live() is None
    assert scope.signed is True


def test_window_unparseable_refuses_live(tmp_path) -> None:
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.badwindow.yaml"
    path.write_text(
        """
client_legal_name: "Bad Window Lab"
named_contact: "Pat"
consent_attested: true
window_start: "not-a-date"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.refuse_live() == "window_unparseable"
    payload = run(path, "discover")
    assert payload.get("refused") == "window_unparseable"


def test_deepen_without_discover_is_brake() -> None:
    from dropbox.orchestrator.run import BrakeError, run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    discover = dest / "discover.json"
    backup = discover.read_text(encoding="utf-8") if discover.is_file() else None
    if discover.is_file():
        discover.unlink()
    try:
        try:
            run(LAB_SCOPE, "deepen")
            raise AssertionError("expected BrakeError")
        except BrakeError as exc:
            assert "discover.json" in str(exc)
    finally:
        if backup is not None:
            discover.write_text(backup, encoding="utf-8")


def test_unparseable_discover_is_brake() -> None:
    from dropbox.orchestrator.run import BrakeError, run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    discover = dest / "discover.json"
    backup = discover.read_text(encoding="utf-8") if discover.is_file() else None
    discover.write_text("not-json{", encoding="utf-8")
    try:
        try:
            run(LAB_SCOPE, "deepen")
            raise AssertionError("expected BrakeError")
        except BrakeError as exc:
            assert "unparseable" in str(exc)
    finally:
        if backup is not None:
            discover.write_text(backup, encoding="utf-8")
        elif discover.is_file():
            discover.unlink()


def test_unparseable_deepen_ingest_stays_fixture() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    deepen = dest / "deepen.json"
    backup = deepen.read_text(encoding="utf-8") if deepen.is_file() else None
    deepen.write_text("not-json{", encoding="utf-8")
    try:
        payload = run(LAB_SCOPE, "ingest")
        assert payload["ingest"]["label"] == "fixture"
        ignored = payload["ingest"].get("leftover_ignored") or {}
        assert ignored.get("reason") == "deepen_unparseable"
    finally:
        if backup is not None:
            deepen.write_text(backup, encoding="utf-8")
        elif deepen.is_file():
            deepen.unlink()


def test_lab_scope_ignores_leftover_live_byo_ingest() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    deepen = dest / "deepen.json"
    backup = deepen.read_text(encoding="utf-8") if deepen.is_file() else None
    deepen.write_text(
        json.dumps(
            {
                "label": "live-byo",
                "client": "Litware Lab LLC",
                "findings": [{"host": "file01.corp.local", "name": "should-not-ingest", "severity": "critical"}],
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "ingest")
        assert payload["ingest"]["label"] == "fixture"
        ignored = payload["ingest"].get("leftover_ignored") or {}
        assert ignored.get("reason") == "live_exec_not_allowed"
        preview = json.loads((ROOT / "in" / "_dropbox_preview" / "findings.json").read_text(encoding="utf-8"))
        names = {str(r.get("name") or r.get("weakness") or "") for r in preview.get("findings") or []}
        assert "should-not-ingest" not in names
        if _product_lab_drop().is_dir():
            assert payload["ingest"].get("drop_copied") is True
    finally:
        if backup is not None:
            deepen.write_text(backup, encoding="utf-8")
        elif deepen.is_file():
            deepen.unlink()


def test_leftover_plan_only_deepen_ingest_stays_fixture() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    deepen = dest / "deepen.json"
    backup = deepen.read_text(encoding="utf-8") if deepen.is_file() else None
    deepen.write_text(
        json.dumps(
            {
                "label": "plan-only",
                "refused": True,
                "reason": "live_exec_not_allowed",
                "client": "Litware Lab LLC",
                "findings": [{"host": "file01.corp.local", "name": "should-not-ingest", "severity": "critical"}],
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "ingest")
        assert payload["ingest"]["label"] == "fixture"
        ignored = payload["ingest"].get("leftover_ignored") or {}
        assert ignored.get("reason") == "deepen_refused"
        preview = json.loads((ROOT / "in" / "_dropbox_preview" / "findings.json").read_text(encoding="utf-8"))
        names = {str(r.get("name") or r.get("weakness") or "") for r in preview.get("findings") or []}
        assert "should-not-ingest" not in names
    finally:
        if backup is not None:
            deepen.write_text(backup, encoding="utf-8")
        elif deepen.is_file():
            deepen.unlink()


def test_leftover_other_client_fixture_deepen_is_ignored() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    deepen = dest / "deepen.json"
    backup = deepen.read_text(encoding="utf-8") if deepen.is_file() else None
    deepen.write_text(
        json.dumps(
            {
                "label": "fixture",
                "client": "Other Corp",
                "findings": [{"host": "file01.corp.local", "name": "other-client-finding", "severity": "critical"}],
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "ingest")
        assert payload["ingest"]["label"] == "fixture"
        ignored = payload["ingest"].get("leftover_ignored") or {}
        assert ignored.get("reason") == "client_mismatch"
        preview = json.loads((ROOT / "in" / "_dropbox_preview" / "findings.json").read_text(encoding="utf-8"))
        names = {str(r.get("name") or r.get("weakness") or "") for r in preview.get("findings") or []}
        assert "other-client-finding" not in names
    finally:
        if backup is not None:
            deepen.write_text(backup, encoding="utf-8")
        elif deepen.is_file():
            deepen.unlink()


def test_leftover_deepen_missing_client_is_ignored() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    deepen = dest / "deepen.json"
    backup = deepen.read_text(encoding="utf-8") if deepen.is_file() else None
    deepen.write_text(
        json.dumps(
            {
                "label": "fixture",
                "findings": [{"host": "file01.corp.local", "name": "should-not-ingest", "severity": "critical"}],
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "ingest")
        assert payload["ingest"]["label"] == "fixture"
        ignored = payload["ingest"].get("leftover_ignored") or {}
        assert ignored.get("reason") == "deepen_client_missing"
        preview = json.loads((ROOT / "in" / "_dropbox_preview" / "findings.json").read_text(encoding="utf-8"))
        names = {str(r.get("name") or r.get("weakness") or "") for r in preview.get("findings") or []}
        assert "should-not-ingest" not in names
    finally:
        if backup is not None:
            deepen.write_text(backup, encoding="utf-8")
        elif deepen.is_file():
            deepen.unlink()


def test_external_ingest_filters_leftover_internal_hosts(tmp_path) -> None:
    """External-only SCOPE must not ingest leftover internal SMBv1 even from the same client."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    deepen = dest / "deepen.json"
    backup = deepen.read_text(encoding="utf-8") if deepen.is_file() else None
    deepen.write_text(
        json.dumps(
            {
                "label": "live-byo",
                "client": "Litware External Lab LLC",
                "findings": [
                    {"host": "file01.corp.local", "name": "SMBv1 enabled", "severity": "critical"},
                    {"host": "vpn.example-corp.com", "name": "TLSv1.0 offered", "severity": "medium"},
                ],
            }
        ),
        encoding="utf-8",
    )
    path = tmp_path / "SCOPE.ext.yaml"
    path.write_text(
        """
client_legal_name: "Litware External Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/16"]
  hosts: ["inside.corp.local"]
external:
  hostnames: ["vpn.example-corp.com"]
  urls: ["https://vpn.example-corp.com"]
allow_tools: [testssl]
profiles: [external]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    try:
        payload = run(path, "ingest")
        assert payload["ingest"]["label"] == "live-byo"
        assert payload["ingest"].get("leftover_ignored") is None
        preview = json.loads((ROOT / "in" / "_dropbox_preview" / "findings.json").read_text(encoding="utf-8"))
        hosts = {str(r.get("host") or r.get("asset") or "") for r in preview.get("findings") or []}
        names = {str(r.get("name") or r.get("weakness") or "") for r in preview.get("findings") or []}
        assert "file01.corp.local" not in hosts
        assert "inside.corp.local" not in hosts
        assert "vpn.example-corp.com" in hosts
        assert "SMBv1 enabled" not in names
        assert "TLSv1.0 offered" in names
        assert payload["ingest"].get("drop_copied") is False
    finally:
        if backup is not None:
            deepen.write_text(backup, encoding="utf-8")
        elif deepen.is_file():
            deepen.unlink()


def test_poam_manifest_wired_into_drop() -> None:
    from dropbox.orchestrator.run import run

    payload = run(LAB_SCOPE, "all")
    assert payload["ingest"]["label"] == "fixture"
    drop_root = _product_lab_drop()
    if drop_root.is_dir():
        assert payload["ingest"].get("drop_copied") is True
    manifest_path = ROOT / "out" / "poam" / "MANIFEST.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["kind"] == "poam-control-map"
    assert manifest["rows"] >= 1
    drop = drop_root / "poam" / "poam.csv"
    if drop_root.is_dir():
        assert drop.is_file()
        assert "SMBv1" in drop.read_text(encoding="utf-8")
        assert (drop_root / "poam" / "MANIFEST.json").is_file()


def test_console_binds_localhost_only() -> None:
    from dropbox.orchestrator import console

    assert console.HOST == "127.0.0.1"
    src = (ROOT / "dropbox" / "orchestrator" / "console.py").read_text(encoding="utf-8")
    assert "0.0.0.0" not in src
    assert "ThreadingHTTPServer((HOST, PORT)" in src


def test_console_localhost_get_status() -> None:
    import json
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer

    from dropbox.orchestrator import console

    server = ThreadingHTTPServer((console.HOST, 0), console.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=2) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
        assert "not an exploit dashboard" in body["note"]
        assert str(body.get("bind") or "").startswith("127.0.0.1:")
    finally:
        server.shutdown()
        server.server_close()


def test_console_post_is_not_an_attack_api() -> None:
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer

    from dropbox.orchestrator import console

    server = ThreadingHTTPServer((console.HOST, 0), console.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/status",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=2)
            raise AssertionError("expected HTTP 405")
        except urllib.error.HTTPError as exc:
            assert exc.code == 405
            body = json.loads(exc.read().decode("utf-8"))
            assert body.get("error") == "method not allowed"
    finally:
        server.shutdown()
        server.server_close()
    src = (ROOT / "dropbox" / "orchestrator" / "console.py").read_text(encoding="utf-8")
    assert "def do_POST" in src
    assert "def do_PUT" in src
    assert "def do_DELETE" in src
    assert "def do_PATCH" in src
    assert "def do_OPTIONS" in src


def test_console_status_shows_brakes() -> None:
    from dropbox.orchestrator.console import status_payload
    from dropbox.orchestrator.run import run

    run(LAB_SCOPE, "plan")
    payload = status_payload()
    assert payload["bind"].startswith("127.0.0.1:")
    assert payload["deepen_batch_size"] == 3
    assert payload["stage"] in {"plan", "discover", "deepen", "ingest", "grc_export"}
    assert "not an exploit dashboard" in payload["note"]
    assert payload["profile_isolation"]["uses_internal"] is True
    assert "discover_label" in payload
    assert "deepen_label" in payload
    assert "ingest_label" in payload


def test_ingest_lands_in_labeled_preview_not_sensor_dirs() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    nmap_dir = ROOT / "in" / "nmap"
    before = {p.name for p in nmap_dir.glob("*")} if nmap_dir.is_dir() else set()
    payload = run(LAB_SCOPE, "ingest")
    assert payload["ingest"]["label"] == "fixture"
    preview = ROOT / "in" / "_dropbox_preview"
    assert (preview / "findings.json").is_file()
    readme = (preview / "README.md").read_text(encoding="utf-8").lower()
    assert "not a client estate" in readme
    after = {p.name for p in nmap_dir.glob("*")} if nmap_dir.is_dir() else set()
    assert after == before
    evidence = ROOT / "dropbox" / "out" / "EVIDENCE.md"
    assert evidence.is_file()
    trail = evidence.read_text(encoding="utf-8").lower()
    assert "fixture" in trail
    assert "paying-day" in trail


def test_unsigned_all_is_not_client_facing() -> None:
    from dropbox.orchestrator.run import run

    payload = run(ROOT / "dropbox" / "SCOPE.unsigned.yaml", "all")
    assert payload.get("refused") == "unsigned_or_consent_false"
    assert payload["grc_export"]["client_facing_ready"] is False
    assert payload["ingest"]["label"] == "fixture"
    assert payload["ingest"].get("drop_copied") is False


def test_unsigned_all_ignores_leftover_live_byo_deepen() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps(
            {
                "label": "live-byo",
                "client": "Other Corp",
                "findings": [
                    {
                        "host": "neighbor.example.net",
                        "asset": "neighbor.example.net",
                        "name": "should-not-ingest",
                        "weakness": "should-not-ingest",
                        "severity": "critical",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    payload = run(ROOT / "dropbox" / "SCOPE.unsigned.yaml", "all")
    assert payload.get("refused") == "unsigned_or_consent_false"
    assert payload["ingest"]["label"] == "fixture"
    assert payload["ingest"].get("leftover_ignored")
    preview = json.loads((ROOT / "in" / "_dropbox_preview" / "findings.json").read_text(encoding="utf-8"))
    names = {str(r.get("name") or r.get("weakness") or "") for r in preview.get("findings") or []}
    assert "should-not-ingest" not in names
    assert preview.get("label") == "fixture"
    trail = (dest / "EVIDENCE.md").read_text(encoding="utf-8").lower()
    assert "leftover_ignored" in trail


def test_deepen_refuses_other_client_discover() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "discover.json").write_text(
        json.dumps(
            {
                "label": "live-byo",
                "client": "Other Corp",
                "hosts": [
                    {"host": "neighbor.example.net", "live": True, "in_scope": True},
                    {"host": "file01.corp.local", "live": True, "in_scope": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    payload = run(LAB_SCOPE, "deepen")
    deepen = payload.get("deepen") or {}
    rec = deepen.get("deepen") if isinstance(deepen.get("deepen"), dict) else deepen
    assert rec.get("refused") is True or rec.get("reason") == "discover_client_mismatch"
    assert rec.get("reason") == "discover_client_mismatch"
    assert payload.get("refused") == "discover_client_mismatch"
    blob = json.loads((dest / "deepen.json").read_text(encoding="utf-8"))
    assert blob.get("reason") == "discover_client_mismatch"
    assert blob.get("label") == "plan-only"


def test_lab_scope_refuses_leftover_live_byo_discover() -> None:
    """Fixture lab SCOPE must not deepen from leftover live-byo discover.json."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "discover.json").write_text(
        json.dumps(
            {
                "label": "live-byo",
                "client": "Litware Lab LLC",
                "hosts": [
                    {"host": "file01.corp.local", "live": True, "in_scope": True},
                    {"host": "neighbor.example.net", "live": True, "in_scope": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    payload = run(LAB_SCOPE, "deepen")
    deepen = payload.get("deepen") or {}
    rec = deepen.get("deepen") if isinstance(deepen.get("deepen"), dict) else deepen
    assert rec.get("refused") is True
    assert rec.get("reason") == "live_exec_not_allowed"
    assert payload.get("refused") == "live_exec_not_allowed"
    blob = json.loads((dest / "deepen.json").read_text(encoding="utf-8"))
    assert blob.get("reason") == "live_exec_not_allowed"
    assert blob.get("label") == "plan-only"


def test_leftover_discover_missing_client_is_brake() -> None:
    """Unstamped leftover discover.json cannot drive deepen (fixture or live-byo)."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    backup = (dest / "discover.json").read_text(encoding="utf-8") if (dest / "discover.json").is_file() else None
    (dest / "discover.json").write_text(
        json.dumps(
            {
                "label": "fixture",
                "hosts": [{"host": "file01.corp.local", "live": True, "in_scope": True}],
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "deepen")
        assert payload.get("refused") == "discover_client_missing"
        blob = json.loads((dest / "deepen.json").read_text(encoding="utf-8"))
        assert blob.get("reason") == "discover_client_missing"
        assert blob.get("label") == "plan-only"
    finally:
        if backup is not None:
            (dest / "discover.json").write_text(backup, encoding="utf-8")


def test_leftover_plan_only_discover_is_brake() -> None:
    """A prior refused/plan-only discover.json is not a live host set."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    backup = (dest / "discover.json").read_text(encoding="utf-8") if (dest / "discover.json").is_file() else None
    (dest / "discover.json").write_text(
        json.dumps(
            {
                "label": "plan-only",
                "refused": True,
                "reason": "unsigned_or_consent_false",
                "client": "Litware Lab LLC",
                "hosts": [{"host": "file01.corp.local", "live": True, "in_scope": True}],
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "deepen")
        assert payload.get("refused") == "discover_refused"
        blob = json.loads((dest / "deepen.json").read_text(encoding="utf-8"))
        assert blob.get("reason") == "discover_refused"
    finally:
        if backup is not None:
            (dest / "discover.json").write_text(backup, encoding="utf-8")


def test_leftover_discover_refuse_cli_and_mcp_exit_2() -> None:
    """CLI/MCP must fail-closed (exit 2) when leftover discover is refused — not nested-only."""
    from dropbox.orchestrator.__main__ import main
    from dropbox.orchestrator.console import status_payload
    from dropbox.orchestrator.mcp_hook import dispatch
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    backup = (dest / "discover.json").read_text(encoding="utf-8") if (dest / "discover.json").is_file() else None
    (dest / "discover.json").write_text(
        json.dumps(
            {
                "label": "live-byo",
                "client": "Litware Lab LLC",
                "hosts": [{"host": "file01.corp.local", "live": True, "in_scope": True}],
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "deepen")
        assert payload.get("refused") == "live_exec_not_allowed"
        trail = (dest / "EVIDENCE.md").read_text(encoding="utf-8")
        assert "live_exec_not_allowed" in trail
        code = main(
            [
                "run",
                "--scope",
                str(LAB_SCOPE),
                "--stage",
                "deepen",
            ]
        )
        assert code == 2
        mcp = dispatch("run", LAB_SCOPE, stage="deepen")
        assert mcp.get("ok") is False
        assert mcp.get("exit") == 2
        assert mcp.get("payload", {}).get("refused") == "live_exec_not_allowed"
        status = status_payload()
        assert status.get("integrity_stop") == "live_exec_not_allowed"
    finally:
        if backup is not None:
            (dest / "discover.json").write_text(backup, encoding="utf-8")


def test_deepen_filters_leftover_hosts_to_scope() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "discover.json").write_text(
        json.dumps(
            {
                "label": "fixture",
                "client": "Litware Lab LLC",
                "hosts": [
                    {"host": "file01.corp.local", "live": True, "in_scope": True},
                    {"host": "neighbor.example.net", "live": True, "in_scope": True},
                    {"host": "printer-down.corp.local", "live": True, "in_scope": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    payload = run(LAB_SCOPE, "deepen")
    deepen = payload["deepen"]["deepen"]
    assert deepen.get("refused") is not True
    batches = deepen.get("batches") or []
    flat = {h for batch in batches for h in batch}
    assert "file01.corp.local" in flat
    assert "neighbor.example.net" not in flat
    assert "printer-down.corp.local" not in flat


def test_mcp_hook_is_not_an_attack_api() -> None:
    from dropbox.orchestrator.mcp_hook import dispatch

    denied = dispatch("exploit")
    assert denied["ok"] is False
    assert denied["error"] == "not_an_attack_api"
    assert denied["exit"] == 2
    spray = dispatch("scan_internet")
    assert spray["ok"] is False
    plan = dispatch("plan", LAB_SCOPE)
    assert plan["ok"] is True
    assert plan["payload"]["brakes"]["deepen_batch_size"] == 3
    unsigned = dispatch(
        "run",
        ROOT / "dropbox" / "SCOPE.unsigned.yaml",
        stage="discover",
    )
    assert unsigned["exit"] == 2
    assert unsigned["payload"].get("refused") == "unsigned_or_consent_false"
    staged = dispatch("run", LAB_SCOPE, stage="exploit")
    assert staged["ok"] is False
    assert staged["error"] == "not_an_attack_api"
    assert staged["exit"] == 2
    nuclei = dispatch("run", LAB_SCOPE, stage="nuclei")
    assert nuclei["error"] == "not_an_attack_api"
    src = (ROOT / "dropbox" / "orchestrator" / "mcp_hook.py").read_text(encoding="utf-8")
    assert "0.0.0.0" not in src
    assert "ThreadingHTTPServer" not in src


def test_cloud_entra_tools_stay_gated_without_named_targets() -> None:
    from dropbox.orchestrator.adapters import hardeningkitty_byo, maester_byo, prowler_byo
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    plan = build_plan(scope)
    assert plan["tool_gates"]["prowler"].startswith("prowler_needs_")
    assert plan["tool_gates"]["maester"].startswith("maester_needs_")
    assert plan["tool_gates"]["hardeningkitty"] == "ok"
    prowler = prowler_byo.describe(scope)
    assert prowler["would_exec"] is False
    assert "same-day revoke" in prowler["note"].lower()
    maester = maester_byo.describe(scope)
    assert maester["would_exec"] is False
    kitty = hardeningkitty_byo.describe(scope)
    assert kitty["would_exec"] is False
    assert kitty["command"][0] == "powershell"
    assert prowler_byo.execute(scope)["executed"] is False
    assert maester_byo.execute(scope)["executed"] is False
    assert maester_byo.describe(scope, ["evil; Invoke-WebRequest x"])["shard_brake"] == "unsafe_target"
    src = (ROOT / "dropbox" / "orchestrator" / "adapters" / "maester_byo.py").read_text(encoding="utf-8")
    assert "tenant={tenant}" not in src
    assert "f\"Invoke-Maester" not in src


def test_prowler_maester_never_exec_without_named_live(monkeypatch) -> None:
    from dropbox.orchestrator.adapters import maester_byo, prowler_byo
    from dropbox.orchestrator.run import run

    called: list[str] = []
    monkeypatch.setattr(prowler_byo, "on_path", lambda: True)
    monkeypatch.setattr(maester_byo, "on_path", lambda: True)
    monkeypatch.delenv("EVERGREEN_ORCH_LIVE", raising=False)
    monkeypatch.setattr(
        prowler_byo.subprocess,
        "run",
        lambda *a, **k: called.append("prowler") or (_ for _ in ()).throw(AssertionError("prowler ran")),
    )
    monkeypatch.setattr(
        maester_byo.subprocess,
        "run",
        lambda *a, **k: called.append("maester") or (_ for _ in ()).throw(AssertionError("maester ran")),
    )
    payload = run(LAB_SCOPE, "discover")
    assert called == []
    assert payload["discover"]["label"] == "fixture"


def test_prowler_record_seen_not_poam(tmp_path, monkeypatch) -> None:
    from dropbox.orchestrator.adapters import maester_byo, nmap_byo, prowler_byo, ss_byo
    from dropbox.orchestrator.run import run

    class _Proc:
        returncode = 0
        stdout = "FAIL s3_bucket_default_encryption\n"
        stderr = ""

    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: False)
    monkeypatch.setattr(ss_byo, "on_path", lambda: False)
    monkeypatch.setattr(maester_byo, "on_path", lambda: False)
    monkeypatch.setattr(prowler_byo, "on_path", lambda: True)
    monkeypatch.setattr(prowler_byo.subprocess, "run", lambda *a, **k: _Proc())

    path = tmp_path / "SCOPE.cloud.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
cloud:
  accounts: ["123456789012"]
allow_tools: [prowler]
profiles: [internal]
batch:
  deepen_batch_size: 3
integrity:
  timeouts_seconds: 30
  max_runtime_seconds: 14400
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    payload = run(path, "all")
    disc = payload["discover"]
    assert disc["label"] == "fixture"
    prowler = (disc.get("prowler") or [{}])[0]
    assert prowler.get("executed") is True
    assert prowler.get("findings") == []
    assert "same-day revoke" in str(prowler.get("revoke") or "").lower()
    names = {
        str(r.get("name") or r.get("weakness") or "")
        for r in (payload["deepen"]["deepen"].get("findings") or [])
    }
    assert "s3_bucket_default_encryption" not in names


def test_lynis_and_ss_adapters_plan_only() -> None:
    from dropbox.orchestrator.adapters import lynis_byo, ss_byo
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    lynis = lynis_byo.describe(scope, scope.internal_endpoints)
    assert lynis["would_exec"] is False
    assert lynis["target_kind_gate"] is None
    assert lynis["command"][0] == "lynis"
    ss = ss_byo.describe(scope, scope.internal_hosts)
    assert ss["would_exec"] is False
    assert ss["command"][0] in {"ss", "powershell"}
    assert lynis_byo.execute(scope, scope.internal_endpoints)["executed"] is False
    assert ss_byo.execute(scope, scope.internal_hosts)["findings"] == []


def test_endpoint_adapters_never_exec_without_live_env(monkeypatch) -> None:
    from dropbox.orchestrator.adapters import hardeningkitty_byo, lynis_byo, ss_byo
    from dropbox.orchestrator.run import run

    called: list[str] = []
    monkeypatch.setattr(lynis_byo, "on_path", lambda: True)
    monkeypatch.setattr(ss_byo, "on_path", lambda: True)
    monkeypatch.setattr(hardeningkitty_byo, "on_path", lambda: True)
    monkeypatch.delenv("EVERGREEN_ORCH_LIVE", raising=False)

    def boom(name):
        def _run(*a, **k):
            called.append(name)
            raise AssertionError(f"{name} ran")

        return _run

    monkeypatch.setattr(lynis_byo.subprocess, "run", boom("lynis"))
    monkeypatch.setattr(ss_byo.subprocess, "run", boom("ss"))
    monkeypatch.setattr(hardeningkitty_byo.subprocess, "run", boom("hardeningkitty"))
    payload = run(LAB_SCOPE, "discover")
    assert called == []
    assert payload["discover"]["label"] == "fixture"


def test_lynis_record_seen_is_not_a_finding(tmp_path, monkeypatch) -> None:
    from dropbox.orchestrator.adapters import hardeningkitty_byo, lynis_byo, nmap_byo, ss_byo
    from dropbox.orchestrator.run import run

    class _Proc:
        returncode = 0
        stdout = "  Warning: SSH protocol 1 enabled\n  Suggestion: disable telnet\n"
        stderr = ""

    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: False)
    monkeypatch.setattr(ss_byo, "on_path", lambda: False)
    monkeypatch.setattr(hardeningkitty_byo, "on_path", lambda: False)
    monkeypatch.setattr(lynis_byo, "on_path", lambda: True)
    monkeypatch.setattr(lynis_byo.subprocess, "run", lambda *a, **k: _Proc())

    path = tmp_path / "SCOPE.lynis.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
  endpoints: ["file01.corp.local"]
allow_tools: [lynis]
profiles: [internal]
batch:
  deepen_batch_size: 3
integrity:
  timeouts_seconds: 30
  max_runtime_seconds: 14400
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    payload = run(path, "all")
    disc = payload["discover"]
    assert disc["label"] == "fixture"
    lynis = (disc.get("lynis") or [{}])[0]
    assert lynis.get("executed") is True
    assert lynis.get("findings") == []
    assert any("ssh" in str(r.get("text") or "").lower() for r in lynis.get("record_seen") or [])
    deepen = payload["deepen"]["deepen"]
    names = {str(r.get("name") or r.get("weakness") or "") for r in deepen.get("findings") or []}
    assert "SSH protocol 1 enabled" not in names


def test_nmap_binary_missing_is_plan_only(monkeypatch) -> None:
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.scope import load_scope

    monkeypatch.setattr(nmap_byo, "on_path", lambda: False)
    scope = load_scope(LAB_SCOPE)
    desc = nmap_byo.describe(scope, ["10.0.0.1"])
    assert desc["would_exec"] is False
    assert desc["on_path"] is False
    assert "binary missing" in desc["note"].lower()
    assert nmap_byo.execute(scope, ["10.0.0.1"])["executed"] is False


def test_parse_nmap_xml_host_up() -> None:
    from dropbox.orchestrator.adapters import nmap_byo

    xml = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="file01.corp.local" type="user"/></hostnames>
  </host>
</nmaprun>
"""
    rows = nmap_byo.parse_nmap_xml(xml)
    assert rows[0]["host"] == "file01.corp.local"
    assert rows[0]["ip"] == "10.0.0.5"
    assert rows[0]["live"] is True
    text_rows = nmap_byo.parse_nmap_text(
        "Nmap scan report for file01.corp.local (10.0.0.5)\nHost is up (0.001s latency).\n"
    )
    assert text_rows[0]["live"] is True
    assert text_rows[0]["ip"] == "10.0.0.5"


def test_cidr_ip_shards_stay_small() -> None:
    from dropbox.orchestrator.plan import cidr_ip_shards

    shards = cidr_ip_shards("10.0.0.0/24", 32)
    assert len(shards) == 8
    assert all(len(s) <= 32 for s in shards)
    assert sum(len(s) for s in shards) == 256
    assert all("/" not in ip for s in shards for ip in s)
    huge = cidr_ip_shards("10.0.0.0/16", 32)
    assert huge
    assert all(s == ["10.0.0.0/16"] for s in huge)


def test_nmap_refuses_slash16_one_worker() -> None:
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    desc = nmap_byo.describe(scope, ["10.0.0.0/16"])
    assert desc["would_exec"] is False
    assert desc["shard_brake"] == "cidr_too_large_for_one_worker"
    assert nmap_byo.execute(scope, ["10.0.0.0/16"])["executed"] is False


def test_nmap_never_execs_without_live_env(monkeypatch) -> None:
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.run import run

    called: list[object] = []
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.delenv("EVERGREEN_ORCH_LIVE", raising=False)
    monkeypatch.setattr(
        nmap_byo.subprocess,
        "run",
        lambda *a, **k: called.append((a, k)) or (_ for _ in ()).throw(AssertionError("nmap ran")),
    )
    payload = run(LAB_SCOPE, "discover")
    assert called == []
    assert payload["discover"]["label"] == "fixture"
    assert "printer-down.corp.local" not in {
        row.get("host") for row in payload["discover"].get("hosts") or []
    }


def test_nmap_live_exec_mocked_does_not_mix_fixtures(tmp_path, monkeypatch) -> None:
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.run import run

    xml = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="file01.corp.local" type="user"/></hostnames>
  </host>
  <host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="203.0.113.9" addrtype="ipv4"/>
    <hostnames><hostname name="neighbor.example.net" type="PTR"/></hostnames>
  </host>
</nmaprun>
"""

    class _Proc:
        returncode = 0
        stdout = xml
        stderr = ""

    def fake_run(cmd, **kwargs):
        assert cmd[0] == "nmap"
        assert "-sn" in cmd
        assert kwargs.get("shell") is False
        assert "<shard>" not in cmd
        for arg in cmd[1:]:
            assert not str(arg).startswith("-sV")
        return _Proc()

    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(nmap_byo.subprocess, "run", fake_run)

    path = tmp_path / "SCOPE.live.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
batch:
  discover_shard_size: 32
  deepen_batch_size: 3
  max_concurrent_discover: 2
integrity:
  timeouts_seconds: 30
  max_runtime_seconds: 14400
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    payload = run(path, "discover")
    disc = payload["discover"]
    assert disc["label"] == "live-byo"
    names = {row.get("host") for row in disc.get("hosts") or []}
    assert "file01.corp.local" in names
    assert "10.0.0.6" in names
    assert "printer-down.corp.local" not in names
    assert "neighbor.example.net" not in names
    assert "203.0.113.9" not in names
    assert any(row.get("executed") for row in disc.get("nmap") or [])
    live = [row for row in disc["hosts"] if row.get("live")]
    assert any(row.get("host") == "file01.corp.local" for row in live)


def test_nessus_refuses_cidr_and_oversize_batch() -> None:
    from dropbox.orchestrator.adapters import nessus_byo
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    cidr = nessus_byo.describe(scope, ["10.0.0.0/16"])
    assert cidr["would_exec"] is False
    assert cidr["shard_brake"] == "cidr_refused"
    assert nessus_byo.execute(scope, ["10.0.0.0/16"])["executed"] is False
    huge = nessus_byo.describe(scope, [f"h{i}.lab" for i in range(6)])
    assert huge["would_exec"] is False
    assert huge["shard_brake"] == "batch_too_large"
    ok_plan = nessus_byo.describe(scope, ["file01.corp.local", "smb-legacy.corp.local"])
    assert ok_plan["would_exec"] is False
    assert ok_plan["command"][0] in {"nessuscli", "nessus"}
    assert ok_plan["batch_size"] == 2


def test_parse_nessus_xml_skips_severity_zero() -> None:
    from dropbox.orchestrator.adapters import nessus_byo

    xml = (ROOT / "in" / "vuln" / "nessus.xml").read_text(encoding="utf-8")
    rows = nessus_byo.parse_nessus_xml(xml)
    names = {r["name"] for r in rows}
    assert "MS-NRPC Zerologon" in names
    assert "Windows Print Spooler RCE" in names
    assert "Nessus Scan Information" not in names
    assert all(r["severity"] != "info" for r in rows)


def test_nessus_never_execs_without_live_env(monkeypatch) -> None:
    from dropbox.orchestrator.adapters import nessus_byo
    from dropbox.orchestrator.run import run

    called: list[object] = []
    monkeypatch.setattr(nessus_byo, "on_path", lambda: True)
    monkeypatch.delenv("EVERGREEN_ORCH_LIVE", raising=False)
    monkeypatch.setattr(
        nessus_byo.subprocess,
        "run",
        lambda *a, **k: called.append(1) or (_ for _ in ()).throw(AssertionError("nessus ran")),
    )
    payload = run(LAB_SCOPE, "all")
    assert called == []
    assert payload["deepen"]["deepen"]["label"] == "fixture"
    csv_text = (ROOT / "dropbox" / "out" / "poam.csv").read_text(encoding="utf-8")
    assert "SMBv1" in csv_text


def test_nessus_live_exec_mocked_does_not_mix_fixtures(tmp_path, monkeypatch) -> None:
    from dropbox.orchestrator.adapters import nmap_byo, nessus_byo
    from dropbox.orchestrator.run import run

    xml = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="lab">
    <ReportHost name="file01.corp.local">
      <HostProperties>
        <tag name="host-fqdn">file01.corp.local</tag>
      </HostProperties>
      <ReportItem port="445" severity="4" pluginName="SMBv1 enabled">
        <description>SMBv1</description>
      </ReportItem>
      <ReportItem port="0" severity="0" pluginName="Nessus Scan Information"/>
    </ReportHost>
    <ReportHost name="neighbor.example.net">
      <ReportItem port="22" severity="3" pluginName="OpenSSH out of date"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

    class _Proc:
        returncode = 0
        stdout = xml
        stderr = ""

    def fake_run(cmd, **kwargs):
        assert cmd[0] in {"nessuscli", "nessus"}
        assert kwargs.get("shell") is False
        targets = ",".join(cmd[cmd.index("--targets") + 1 : cmd.index("--targets") + 2])
        assert "/" not in targets
        assert len(targets.split(",")) <= 5
        return _Proc()

    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: False)
    monkeypatch.setattr(nessus_byo, "on_path", lambda: True)
    monkeypatch.setattr(nessus_byo.subprocess, "run", fake_run)

    path = tmp_path / "SCOPE.nessus.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local", "smb-legacy.corp.local"]
allow_tools: [nessus]
profiles: [internal]
batch:
  deepen_batch_size: 3
  max_concurrent_deepen: 1
integrity:
  timeouts_seconds: 30
  max_runtime_seconds: 14400
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    payload = run(path, "all")
    deepen = payload["deepen"]["deepen"]
    assert deepen["label"] == "live-byo"
    hosts = {row.get("host") for row in deepen.get("findings") or []}
    assert "file01.corp.local" in hosts
    assert "neighbor.example.net" not in hosts
    names = {row.get("name") for row in deepen.get("findings") or []}
    assert "SMBv1 enabled" in names
    assert "Nessus Scan Information" not in names
    assert any(row.get("executed") for row in deepen.get("nessus") or [])
    assert payload["ingest"]["label"] == "live-byo"
    assert payload["ingest"].get("pack_canonical_merged") == 0
    assert payload["ingest"]["pack_mapped"] >= 1
    preview = (ROOT / "in" / "_dropbox_preview" / "README.md").read_text(encoding="utf-8").lower()
    assert "live-byo" in preview
    assert "not a paying-day" in preview
    assert payload["ingest"].get("drop_copied") is False


def test_runtime_budget_refuses_huge_prefix(tmp_path) -> None:
    from dropbox.orchestrator.plan import estimated_discover_seconds, runtime_over_budget
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.huge.yaml"
    path.write_text(
        """
client_legal_name: "Huge Prefix Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/16"]
  hosts: []
allow_tools: [nmap]
profiles: [internal]
batch:
  discover_shard_size: 32
  max_concurrent_discover: 2
  deepen_batch_size: 3
integrity:
  timeouts_seconds: 600
  max_runtime_seconds: 60
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert estimated_discover_seconds(scope) > 60
    assert runtime_over_budget(scope) == "prefix_too_large"
    payload = run(path, "discover")
    assert payload.get("refused") == "prefix_too_large"


def test_timeout_one_cannot_game_slash16(tmp_path) -> None:
    """timeouts_seconds: 1 must not make a /16 look in-budget."""
    from dropbox.orchestrator.plan import runtime_over_budget
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.game.yaml"
    path.write_text(
        """
client_legal_name: "Game Budget Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/16"]
  hosts: []
allow_tools: [nmap]
profiles: [internal]
batch:
  discover_shard_size: 256
  max_concurrent_discover: 4
  deepen_batch_size: 5
integrity:
  timeouts_seconds: 1
  max_runtime_seconds: 14400
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert runtime_over_budget(scope) == "prefix_too_large"
    payload = run(path, "discover")
    assert payload.get("refused") == "prefix_too_large"


def test_slash24_is_not_prefix_too_large() -> None:
    from dropbox.orchestrator.plan import runtime_over_budget
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    assert runtime_over_budget(scope) is None


def test_quote_stub_hours_blank() -> None:
    from dropbox.orchestrator.run import run

    payload = run(LAB_SCOPE, "all")
    assert payload["ingest"]["label"] == "fixture"
    quote = ROOT / "out" / "quote" / "quote.csv"
    assert quote.is_file()
    text = quote.read_text(encoding="utf-8")
    assert "SMBv1" in text
    assert "draft" in text
    header = text.splitlines()[0]
    assert "hours" in header and "rate_usd" in header and "total_usd" in header
    for line in text.splitlines()[1:]:
        parts = line.split(",")
        assert parts, line
    import csv as csvmod

    with quote.open(encoding="utf-8", newline="") as handle:
        for row in csvmod.DictReader(handle):
            assert row["hours"] == ""
            assert row["rate_usd"] == ""
            assert row["total_usd"] == ""
            assert row["status"] == "draft"
    drop_q = _product_lab_drop() / "quote" / "quote.csv"
    if _product_lab_drop().is_dir():
        assert drop_q.is_file()


def test_curl_adapter_refuses_cidr() -> None:
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    desc = curl_byo.describe(scope, ["10.0.0.0/24"])
    assert desc["would_exec"] is False
    assert desc["cidr_refused"] == ["10.0.0.0/24"]
    assert desc["shard_brake"] == "cidr_refused"
    ok = curl_byo.describe(scope, ["https://vpn.example-corp.com"])
    assert ok["would_exec"] is False
    assert ok["command"][0] in {"curl", "curl.exe"}
    file_url = curl_byo.describe(scope, ["file:///etc/passwd"])
    assert file_url["would_exec"] is False
    assert file_url["shard_brake"] == "unsafe_target"
    huge = curl_byo.describe(scope, [f"https://h{i}.example" for i in range(6)])
    assert huge["shard_brake"] == "batch_too_large"
    assert curl_byo.execute(scope, ["https://vpn.example-corp.com"])["executed"] is False


def test_testssl_refuses_cidr_and_oversize_batch() -> None:
    from dropbox.orchestrator.adapters import testssl_byo
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(LAB_SCOPE)
    desc = testssl_byo.describe(scope, ["10.0.0.0/24"])
    assert desc["would_exec"] is False
    assert desc["cidr_refused"] == ["10.0.0.0/24"]
    huge = testssl_byo.describe(scope, [f"vpn{i}.example-corp.com" for i in range(6)])
    assert huge["would_exec"] is False
    assert huge["shard_brake"] == "batch_too_large"
    assert testssl_byo.execute(scope, ["vpn.example-corp.com"])["executed"] is False


def test_testssl_and_curl_never_exec_without_live_env(monkeypatch) -> None:
    from dropbox.orchestrator.adapters import curl_byo, testssl_byo
    from dropbox.orchestrator.run import run

    called: list[str] = []
    monkeypatch.setattr(testssl_byo, "on_path", lambda: True)
    monkeypatch.setattr(curl_byo, "on_path", lambda: True)
    monkeypatch.delenv("EVERGREEN_ORCH_LIVE", raising=False)

    def boom(name):
        def _run(*a, **k):
            called.append(name)
            raise AssertionError(f"{name} ran")

        return _run

    monkeypatch.setattr(testssl_byo.subprocess, "run", boom("testssl"))
    monkeypatch.setattr(curl_byo.subprocess, "run", boom("curl"))
    payload = run(LAB_SCOPE, "all")
    assert called == []
    assert payload["deepen"]["deepen"]["label"] == "fixture"


def test_testssl_live_exec_mocked_does_not_mix_fixtures(tmp_path, monkeypatch) -> None:
    from dropbox.orchestrator.adapters import curl_byo, nessus_byo, nmap_byo, testssl_byo
    from dropbox.orchestrator.run import run

    class _Proc:
        returncode = 0
        stdout = "Testing TLSv1.0  offered\nSSLv3 not offered\n"
        stderr = ""

    def fake_run(cmd, **kwargs):
        assert cmd[0] in {"testssl.sh", "testssl"}
        assert kwargs.get("shell") is False
        assert "--fast" in cmd
        assert all("/" not in str(a) or str(a).startswith("https://") for a in cmd[1:])
        assert "10.0.0.0/16" not in cmd
        return _Proc()

    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: False)
    monkeypatch.setattr(nessus_byo, "on_path", lambda: False)
    monkeypatch.setattr(curl_byo, "on_path", lambda: False)
    monkeypatch.setattr(testssl_byo, "on_path", lambda: True)
    monkeypatch.setattr(testssl_byo.subprocess, "run", fake_run)

    path = tmp_path / "SCOPE.ext.yaml"
    path.write_text(
        """
client_legal_name: "Litware External Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/16"]
  hosts: ["inside.corp.local"]
external:
  hostnames: ["vpn.example-corp.com"]
  urls: ["https://vpn.example-corp.com"]
allow_tools: [testssl]
profiles: [external]
batch:
  deepen_batch_size: 3
integrity:
  timeouts_seconds: 30
  max_runtime_seconds: 14400
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    payload = run(path, "all", dest=tmp_path / "out")
    deepen = payload["deepen"]["deepen"]
    assert deepen["label"] == "live-byo"
    hosts = {row.get("host") for row in deepen.get("findings") or []}
    assert "vpn.example-corp.com" in hosts
    assert "inside.corp.local" not in hosts
    assert "file01.corp.local" not in hosts
    names = {row.get("name") for row in deepen.get("findings") or []}
    assert "TLSv1.0 offered" in names
    assert "SSLv3 offered" not in names
    assert any(row.get("executed") for row in deepen.get("testssl") or [])
    assert payload["ingest"]["label"] == "live-byo"
    assert payload["ingest"].get("pack_canonical_merged") == 0
    assert payload["ingest"]["pack_mapped"] >= 1
    assert payload["ingest"].get("drop_copied") is False


def test_curl_cleartext_http_is_a_finding() -> None:
    from dropbox.orchestrator.adapters import curl_byo

    rows = curl_byo.parse_curl_headers("HTTP/1.1 200 OK\n", "http://vpn.example-corp.com")
    assert rows and rows[0]["name"] == "Cleartext HTTP"
    https_rows = curl_byo.parse_curl_headers("HTTP/1.1 200 OK\n", "https://vpn.example-corp.com")
    assert all(r["name"] != "Cleartext HTTP" for r in https_rows)


def test_curl_live_shaped_nginx_headers_not_smb() -> None:
    """Live-shaped HEAD from estate-web. Not a new nginx cycle. Not SMBv1."""
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    blob = (
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.31.5\n"
        "Date: Sat, 05 Sep 2026 17:28:31 GMT\n"
        "Content-Type: text/html\n"
        "Content-Length: 896\n"
        "Connection: keep-alive\n"
        "ETag: \"6a985b9b-380\"\n"
        "Accept-Ranges: bytes\n"
        "\n"
    )
    rows = curl_byo.parse_curl_headers(blob, "http://127.0.0.1:18081/")
    names = {r["name"] for r in rows}
    assert "Cleartext HTTP" in names
    assert "Missing HSTS" in names
    assert "Missing X-Frame-Options" in names
    assert "Missing CSP" in names
    assert "Server banner disclosure" in names
    assert not any("smb" in n.lower() for n in names)
    for row in rows:
        mapped = map_finding(row["name"], row["asset"], row["severity"])
        assert mapped["mapped"] is True
        assert "UNMAPPED" not in mapped["control_refs"]


def test_curl_https_self_signed_and_missing_hsts() -> None:
    from dropbox.orchestrator.adapters import curl_byo
    from dropbox.orchestrator.poam import map_finding

    err = "curl: (60) SSL certificate problem: self signed certificate\n"
    tls_rows = curl_byo.parse_curl_tls(err, "https://127.0.0.1:18443/")
    assert tls_rows and tls_rows[0]["name"] == "Untrusted TLS certificate"
    win = "curl: (60) schannel: SEC_E_UNTRUSTED_ROOT (0x80090325) - The certificate chain was issued by an authority that is not trusted.\n"
    assert curl_byo.parse_curl_tls(win, "https://127.0.0.1:18443/")
    assert curl_byo.parse_curl_tls(err, "http://127.0.0.1:18081/") == []
    headers = curl_byo.parse_curl_headers(
        "HTTP/1.1 200 OK\nServer: nginx/1.31.5\n\n",
        "https://127.0.0.1:18443/",
    )
    names = {r["name"] for r in headers}
    assert "Cleartext HTTP" not in names
    assert "Missing HSTS" in names
    assert not any("smb" in n.lower() for n in names)
    mapped = map_finding("Untrusted TLS certificate", "127.0.0.1", "medium")
    assert mapped["mapped"] is True
    headers_named = map_finding("Missing web security headers", "127.0.0.1", "low")
    assert headers_named["mapped"] is True
    assert "UNMAPPED" not in headers_named["control_refs"]


def test_curl_empty_head_does_not_invent_missing_headers() -> None:
    """Cycle 5: python http.server empty HEAD is not a header sample."""
    from dropbox.orchestrator.adapters import curl_byo

    rows = curl_byo.parse_curl_headers("curl: (52) Empty reply from server\n", "http://127.0.0.1:18210/")
    names = [r["name"] for r in rows]
    assert names == ["Cleartext HTTP"]


def test_hitl_gate_default_not_client_facing() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    hitl = dest / "HITL.json"
    if hitl.exists():
        hitl.unlink()
    (dest / "deepen.json").write_text(
        json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "fixture", "findings": []}),
        encoding="utf-8",
    )
    payload = run(LAB_SCOPE, "grc_export")
    assert payload["grc_export"]["client_facing_ready"] is False
    hitl.write_text(
        '{"attested": true, "reviewer": "Pat Lab", "client": "Litware Lab LLC"}',
        encoding="utf-8",
    )
    try:
        payload2 = run(LAB_SCOPE, "grc_export")
        assert payload2["grc_export"]["client_facing_ready"] is False
        assert payload2["grc_export"]["hitl"].get("blocked_by") == "fixture_not_client_estate"
        assert payload2["grc_export"]["label"] == "fixture-or-prior-lab"
    finally:
        if hitl.exists():
            hitl.unlink()


def test_unsigned_hitl_leftover_is_not_client_facing() -> None:
    """Leftover HITL.json attested=true must not make unsigned SCOPE client-facing."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    hitl = dest / "HITL.json"
    hitl.write_text(
        '{"attested": true, "reviewer": "Pat Lab", "client": "Unsigned Example"}',
        encoding="utf-8",
    )
    try:
        payload = run(ROOT / "dropbox" / "SCOPE.unsigned.yaml", "all")
        assert payload.get("refused") == "unsigned_or_consent_false"
        assert payload["grc_export"]["client_facing_ready"] is False
        assert payload["grc_export"]["hitl"].get("blocked_by") == "unsigned_or_consent_false"
        assert payload["ingest"].get("drop_copied") is False
    finally:
        if hitl.exists():
            hitl.unlink()


def test_live_byo_hitl_matching_client_is_ready(tmp_path) -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    path = tmp_path / "SCOPE.live.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    hitl = dest / "HITL.json"
    hitl.write_text(
        '{"attested": true, "reviewer": "Pat Lab", "client": "Litware Lab LLC"}',
        encoding="utf-8",
    )
    try:
        payload = run(path, "grc_export")
        assert payload["grc_export"]["client_facing_ready"] is True
        assert payload["grc_export"]["evidence_label"] == "live-byo"
        assert payload["grc_export"]["evidence_client"] == "Litware Lab LLC"
        assert payload["grc_export"]["hitl"].get("blocked_by") is None
    finally:
        if hitl.exists():
            hitl.unlink()
        (dest / "normalized" / "findings.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )
        (dest / "deepen.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )


def test_lab_scope_leftover_live_byo_is_not_ready() -> None:
    """Lab SCOPE keep allow_live_exec false; leftover live-byo is not a client estate."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    hitl = dest / "HITL.json"
    hitl.write_text(
        '{"attested": true, "reviewer": "Pat Lab", "client": "Litware Lab LLC"}',
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "grc_export")
        assert payload["grc_export"]["client_facing_ready"] is False
        assert payload["grc_export"]["hitl"].get("blocked_by") == "live_exec_not_allowed"
    finally:
        if hitl.exists():
            hitl.unlink()
        (dest / "normalized" / "findings.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )
        (dest / "deepen.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )


def test_hitl_other_client_is_not_ready(tmp_path) -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    path = tmp_path / "SCOPE.live.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    hitl = dest / "HITL.json"
    hitl.write_text(
        '{"attested": true, "reviewer": "Pat Lab", "client": "Other Corp"}',
        encoding="utf-8",
    )
    try:
        payload = run(path, "grc_export")
        assert payload["grc_export"]["client_facing_ready"] is False
        assert payload["grc_export"]["hitl"].get("blocked_by") == "hitl_client_mismatch"
    finally:
        if hitl.exists():
            hitl.unlink()
        (dest / "normalized" / "findings.json").write_text(
            json.dumps({"label": "fixture", "findings": []}),
            encoding="utf-8",
        )
        (dest / "deepen.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )


def test_lab_sim_hitl_is_not_client_facing(tmp_path) -> None:
    """Attested lab-sim HITL + live-byo is a real workflow, not a paying client."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    path = tmp_path / "SCOPE.live.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    hitl = dest / "HITL.json"
    hitl.write_text(
        json.dumps(
            {
                "attested": True,
                "reviewer": "Pat Lab",
                "client": "Litware Lab LLC",
                "slug": "docker-estate-product",
                "evidence_label": "lab-sim",
                "timestamp": "2026-09-05T21:50:00-07:00",
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(path, "grc_export")
        assert payload["grc_export"]["client_facing_ready"] is False
        assert payload["grc_export"]["hitl"].get("blocked_by") == "lab_sim_not_client_estate"
    finally:
        if hitl.exists():
            hitl.unlink()
        (dest / "normalized" / "findings.json").write_text(
            json.dumps({"label": "fixture", "findings": []}),
            encoding="utf-8",
        )
        (dest / "deepen.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )


def test_docker_estate_client_is_not_paying(tmp_path) -> None:
    """Evergreen Docker Estate LLC is lab-sim even if HITL omits evidence_label."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps({"label": "live-byo", "client": "Evergreen Docker Estate LLC", "findings": []}),
        encoding="utf-8",
    )
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "live-byo", "client": "Evergreen Docker Estate LLC", "findings": []}),
        encoding="utf-8",
    )
    path = tmp_path / "SCOPE.estate.yaml"
    path.write_text(
        """
client_legal_name: "Evergreen Docker Estate LLC"
named_contact: "Reid Schram"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["172.28.90.0/24"]
  hosts: ["172.28.90.10"]
external:
  hostnames: ["127.0.0.1"]
  urls: ["http://127.0.0.1:18081/"]
allow_tools: [curl]
profiles: [both]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    hitl = dest / "HITL.json"
    hitl.write_text(
        '{"attested": true, "reviewer": "Reid Schram", "client": "Evergreen Docker Estate LLC"}',
        encoding="utf-8",
    )
    try:
        payload = run(path, "grc_export")
        assert payload["grc_export"]["client_facing_ready"] is False
        assert payload["grc_export"]["hitl"].get("blocked_by") == "lab_sim_not_client_estate"
    finally:
        if hitl.exists():
            hitl.unlink()
        (dest / "normalized" / "findings.json").write_text(
            json.dumps({"label": "fixture", "findings": []}),
            encoding="utf-8",
        )
        (dest / "deepen.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )


def test_leftover_other_client_live_byo_is_not_ready() -> None:
    """Leftover live-byo from another client cannot be HITL-ready for this SCOPE."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps({"label": "live-byo", "client": "Other Corp", "findings": []}),
        encoding="utf-8",
    )
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "live-byo", "client": "Other Corp", "findings": []}),
        encoding="utf-8",
    )
    hitl = dest / "HITL.json"
    hitl.write_text(
        '{"attested": true, "reviewer": "Pat Lab", "client": "Litware Lab LLC"}',
        encoding="utf-8",
    )
    try:
        payload = run(LAB_SCOPE, "grc_export")
        assert payload["grc_export"]["client_facing_ready"] is False
        assert payload["grc_export"]["hitl"].get("blocked_by") == "evidence_client_mismatch"
        assert payload["grc_export"]["evidence_client"] == "Other Corp"
    finally:
        if hitl.exists():
            hitl.unlink()
        (dest / "normalized" / "findings.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )
        (dest / "deepen.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )


def test_stale_live_byo_ingest_vs_fixture_deepen_is_not_ready(tmp_path) -> None:
    """Leftover live-byo normalized cannot outrank a current fixture/plan-only deepen."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "live-byo", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    (dest / "deepen.json").write_text(
        json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    path = tmp_path / "SCOPE.live.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    hitl = dest / "HITL.json"
    hitl.write_text(
        '{"attested": true, "reviewer": "Pat Lab", "client": "Litware Lab LLC"}',
        encoding="utf-8",
    )
    try:
        payload = run(path, "grc_export")
        assert payload["grc_export"]["client_facing_ready"] is False
        assert payload["grc_export"]["hitl"].get("blocked_by") == "evidence_label_mismatch"
        assert payload["grc_export"]["evidence_label"] == "fixture"
    finally:
        if hitl.exists():
            hitl.unlink()
        (dest / "normalized" / "findings.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )
        (dest / "deepen.json").write_text(
            json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
            encoding="utf-8",
        )


def test_live_scope_fixture_ingest_does_not_stamp_drop(tmp_path) -> None:
    """Live-eligible SCOPE must not stamp product-lab/drop with leftover fixture ingest."""
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    deepen = dest / "deepen.json"
    backup = deepen.read_text(encoding="utf-8") if deepen.is_file() else None
    deepen.write_text(
        json.dumps(
            {
                "label": "fixture",
                "client": "Litware Lab LLC",
                "findings": [{"host": "file01.corp.local", "name": "SMBv1 enabled", "severity": "critical"}],
            }
        ),
        encoding="utf-8",
    )
    path = tmp_path / "SCOPE.live.yaml"
    path.write_text(
        """
client_legal_name: "Litware Lab LLC"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    try:
        payload = run(path, "ingest")
        assert payload["ingest"]["label"] == "fixture"
        assert payload["ingest"].get("drop_copied") is False
    finally:
        if backup is not None:
            deepen.write_text(backup, encoding="utf-8")
        elif deepen.is_file():
            deepen.unlink()


def test_console_html_is_brakes_not_exploit() -> None:
    from dropbox.orchestrator.console import html_page
    from dropbox.orchestrator.run import run

    run(LAB_SCOPE, "plan")
    page = html_page().lower()
    assert "127.0.0.1" in page
    assert "deepen batch" in page
    assert "integrity stop" in page
    assert "exploit dashboard" in page
    assert "nmap -sV" not in page


def test_simplerisk_leavebehind_and_pack_map() -> None:
    from dropbox.orchestrator.poam import canonical_mapped_findings
    from dropbox.orchestrator.run import run

    payload = run(LAB_SCOPE, "all")
    assert payload["ingest"]["label"] == "fixture"
    sr = ROOT / "out" / "simplerisk" / "risks_import.csv"
    assert sr.is_file()
    text = sr.read_text(encoding="utf-8")
    assert "Subject" in text
    assert "SMBv1" in text
    assert "No API wrap" in text
    drop_sr = _product_lab_drop() / "simplerisk" / "risks_import.csv"
    if _product_lab_drop().is_dir():
        assert drop_sr.is_file()
    mapped = canonical_mapped_findings(ROOT / "out" / "canonical")
    if mapped:
        assert payload["ingest"]["pack_mapped"] >= 1
        poam = (ROOT / "dropbox" / "out" / "poam.csv").read_text(encoding="utf-8")
        assert "Telnet" in poam or "RDP" in poam or "SMBv1" in poam


def test_empty_allow_tools_refuses_live(tmp_path, monkeypatch) -> None:
    """P1: empty allow_tools refuses live stages even when signed + live flags."""
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(nmap_byo.subprocess, "run", lambda *a, **k: called.append(1))
    path = tmp_path / "SCOPE.notools.yaml"
    path.write_text(
        """
client_legal_name: "No Tools Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: []
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.refuse_live() == "empty_allow_tools"
    plan = build_plan(scope)
    assert plan["brakes"]["refuse_live"] == "empty_allow_tools"
    assert plan["label"] == "plan-only"
    payload = run(path, "discover")
    assert payload.get("refused") == "empty_allow_tools"
    deepen = run(path, "deepen")
    assert deepen.get("refused") == "empty_allow_tools"
    assert called == []


def test_unsigned_scope_plan_only_ok() -> None:
    """Northstar: unsigned SCOPE is plan-only (print shards) but never live."""
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.scope import load_scope

    scope = load_scope(ROOT / "dropbox" / "SCOPE.unsigned.yaml")
    plan = build_plan(scope)
    assert plan["signed"] is False
    assert plan["brakes"]["refuse_live"] == "unsigned_or_consent_false"
    assert plan["label"] == "plan-only"
    assert "discover" in plan["stages"]
    assert plan["brakes"]["deepen_batch_size"] == 3


def test_destroy_workers_after_deepen() -> None:
    from dropbox.orchestrator.run import run

    run(LAB_SCOPE, "discover")
    payload = run(LAB_SCOPE, "deepen")
    dest = ROOT / "dropbox" / "out"
    destroy = json.loads((dest / "destroy_deepen.json").read_text(encoding="utf-8"))
    assert destroy["destroyed"]
    alive = list((dest / "workers").glob("*.alive"))
    assert alive == []
    deepen = payload.get("deepen") or {}
    rec = deepen.get("deepen") if isinstance(deepen.get("deepen"), dict) else deepen
    cap = int(rec.get("max_concurrent") or 1)
    assert cap >= 1
    assert all(len(wave) <= cap for wave in rec.get("waves") or [])
    assert rec.get("label") in {"fixture", "live-byo"}


def test_blank_named_contact_refuses_live(tmp_path, monkeypatch) -> None:
    """Schema requires named_contact. Consent without a contact is unsigned."""
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.plan import build_plan
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(nmap_byo.subprocess, "run", lambda *a, **k: called.append(1))
    path = tmp_path / "SCOPE.nocontact.yaml"
    path.write_text(
        """
client_legal_name: "No Contact Lab"
named_contact: ""
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.signed is False
    assert scope.refuse_live() == "unsigned_or_consent_false"
    plan = build_plan(scope)
    assert plan["label"] == "plan-only"
    payload = run(path, "discover")
    assert payload.get("refused") == "unsigned_or_consent_false"
    assert called == []


def test_tool_not_in_allow_tools_does_not_exec(tmp_path, monkeypatch) -> None:
    """nmap is not implied by nessus. Adapter refuse, not a hail-mary discover."""
    from dropbox.orchestrator.adapters import nmap_byo, nessus_byo
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    called: list[str] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(nessus_byo, "on_path", lambda: True)
    monkeypatch.setattr(
        nmap_byo.subprocess,
        "run",
        lambda *a, **k: called.append("nmap") or (_ for _ in ()).throw(AssertionError("nmap ran")),
    )
    path = tmp_path / "SCOPE.nessus-only.yaml"
    path.write_text(
        """
client_legal_name: "Nessus Only Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nessus]
profiles: [internal]
batch:
  deepen_batch_size: 3
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.tool_allowed("nmap") is False
    assert scope.tool_allowed("nessus") is True
    assert scope.refuse_live() is None
    desc = nmap_byo.describe(scope, ["10.0.0.1"])
    assert desc["would_exec"] is False
    assert desc["allow_tools"] is False
    payload = run(path, "discover", dest=tmp_path / "out")
    assert called == []
    assert payload.get("refused") is None
    assert payload["discover"]["label"] == "fixture"


def test_window_missing_refuses_live(tmp_path, monkeypatch) -> None:
    from dropbox.orchestrator.adapters import nmap_byo
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    called: list[int] = []
    monkeypatch.setenv("EVERGREEN_ORCH_LIVE", "1")
    monkeypatch.setattr(nmap_byo, "on_path", lambda: True)
    monkeypatch.setattr(nmap_byo.subprocess, "run", lambda *a, **k: called.append(1))
    path = tmp_path / "SCOPE.nowindow.yaml"
    path.write_text(
        """
client_legal_name: "No Window Lab"
named_contact: "Pat"
consent_attested: true
window_start: ""
window_end: ""
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.refuse_live() == "window_missing"
    payload = run(path, "discover")
    assert payload.get("refused") == "window_missing"
    assert called == []


def test_window_not_open_refuses_live(tmp_path) -> None:
    from dropbox.orchestrator.run import run
    from dropbox.orchestrator.scope import load_scope

    path = tmp_path / "SCOPE.future.yaml"
    path.write_text(
        """
client_legal_name: "Future Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2099-01-01T00:00:00-07:00"
window_end: "2099-01-02T00:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["file01.corp.local"]
allow_tools: [nmap]
profiles: [internal]
integrity:
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    scope = load_scope(path)
    assert scope.refuse_live() == "window_not_open"
    payload = run(path, "discover")
    assert payload.get("refused") == "window_not_open"


def test_empty_live_set_is_not_hail_mary_deepen(tmp_path) -> None:
    """Discover with no live in-scope hosts must not dump fixture SMBv1."""
    from dropbox.orchestrator.run import run

    path = tmp_path / "SCOPE.lonely.yaml"
    path.write_text(
        """
client_legal_name: "Lonely Host Lab"
named_contact: "Pat"
consent_attested: true
window_start: "2026-09-03T00:00:00-07:00"
window_end: "2026-09-05T09:00:00-07:00"
internal:
  cidrs: ["10.0.0.0/24"]
  hosts: ["lonely.corp.local"]
allow_tools: [nmap, nessus]
profiles: [internal]
batch:
  deepen_batch_size: 3
integrity:
  allow_live_exec: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    shared = ROOT / "dropbox" / "out" / "discover.json"
    prior = shared.read_text(encoding="utf-8") if shared.is_file() else None
    try:
        payload = run(path, "all", dest=tmp_path / "out")
        assert payload.get("refused") is None
        hosts = {row.get("host") for row in payload["discover"].get("hosts") or []}
        assert "file01.corp.local" not in hosts
        assert "lonely.corp.local" not in hosts
        deepen = payload["deepen"]["deepen"]
        names = {str(r.get("name") or r.get("weakness") or "") for r in deepen.get("findings") or []}
        assert "SMBv1 enabled" not in names
        assert deepen.get("findings") == []
        isolated = json.loads((tmp_path / "out" / "discover.json").read_text(encoding="utf-8"))
        assert isolated.get("client") == "Lonely Host Lab"
        if prior is not None:
            assert shared.read_text(encoding="utf-8") == prior
    finally:
        if prior is None:
            shared.unlink(missing_ok=True)
        else:
            shared.write_text(prior, encoding="utf-8")
