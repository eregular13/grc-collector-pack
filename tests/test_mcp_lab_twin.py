"""MCP lab_drop twin: prove --use-existing-in with honest LAB≠SAMPLE≠client.

Callable MCP surface beside keep_status / keep_ciso / farm_drop hints.
Requires populated dest_in. Never reseeds fixtures/pack_drop.
Empty in/ is EXISTING_IN_FAIL. LAB.txt + DEMO trees is LAB_SHAPE_FAIL.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from dropbox.mcp_stub import (
    OPERATOR_TOOLS,
    console_cli_twin,
    console_hint,
    dispatch,
    handle_jsonrpc,
    keep_tool_fail_text,
    lab_drop_to_sor_cli_twin,
    tools_list_entries,
)
from dropbox.scope import GateError
from scripts.prove_ciso import LAB_SHAPE_FAIL
from tests.test_lab_prove_lock import MIN_LAB_FINDINGS, MIN_LAB_POAM, stage_lab_drop_dest_in

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
HONEYPOT_FIXTURE = ROOT / "fixtures" / "demo" / "honeypot"
RUSTSCAN_FIXTURE = ROOT / "fixtures" / "pack_drop" / "rustscan"


def _copy_tree(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        target = dest / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def _fingerprint(folder: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    if not folder.is_dir():
        return out
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name in {".gitkeep", ".DS_Store"}:
            continue
        out[str(path.relative_to(folder)).replace("\\", "/")] = path.read_bytes()
    return out


def test_tools_list_advertises_lab_drop_honestly() -> None:
    assert "lab_drop" in OPERATOR_TOOLS
    assert OPERATOR_TOOLS[-1] == "lab_drop"
    listed = handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [row["name"] for row in listed["result"]["tools"]]
    assert names == list(OPERATOR_TOOLS)
    entries = {row["name"]: row for row in tools_list_entries()}
    desc = entries["lab_drop"]["description"]
    assert "use-existing-in" in desc
    assert "lab_drop_to_sor" in desc
    assert "EXISTING_IN_FAIL" in desc
    assert "LAB_SHAPE_FAIL" in desc
    assert "LAB" in desc and "SAMPLE" in desc
    assert "reseed" in desc.lower()
    assert "paying_day FAIL" in desc
    assert "python -m product" in desc
    assert "OUT_DIR" in desc
    assert "console_cli_twin" in desc or "console_hint" in desc
    props = entries["lab_drop"]["inputSchema"]["properties"]
    assert props["work"]["type"] == "string"
    assert "populated" in props["work"]["description"]
    assert props["dest_in"]["type"] == "string"
    assert "EXISTING_IN_FAIL" in props["dest_in"]["description"]
    assert "LAB_SHAPE_FAIL" in props["dest_in"]["description"]
    iface = (ROOT / "dropbox" / "operator_mcp_interface.md").read_text(encoding="utf-8")
    assert "`lab_drop`" in iface
    assert "lab_drop_cli_twin" in iface
    assert "EXISTING_IN_FAIL" in iface
    assert "LAB_SHAPE_FAIL" in iface
    assert "--use-existing-in" in iface
    assert "LAB≠SAMPLE" in iface or "LAB≠SAMPLE≠client" in iface
    assert "console_cli_twin" in iface
    assert "console_hint" in iface
    assert "OUT_DIR=" in iface
    assert "python -m product" in iface
    assert "set OUT_DIR" in iface
    assert "PROVE_WORK_ROOT" in iface
    assert "127.0.0.1" in iface
    assert "/api/risks" in iface
    assert "scan-to-console" in iface
    assert "lab_drop_to_sor" in iface
    prove = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "lab_drop" in prove
    assert "lab_drop_to_sor" in prove
    assert "OUT_DIR=" in prove
    assert "python -m product" in prove
    assert "set OUT_DIR" in prove
    assert "scan-to-console" in prove
    assert "no DEMO reseed" in prove
    assert "PROVE_WORK_ROOT" in prove


def test_keep_status_and_keep_ciso_advertise_lab_drop_twin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    for sensor in ("identity", "saas", "vuln", "cloud"):
        (pack_in / sensor).mkdir(parents=True)
        (pack_in / sensor / ".gitkeep").write_text("", encoding="utf-8")
    work = tmp_path / "work"
    monkeypatch.setenv("IN_DIR", str(pack_in))
    status = dispatch("keep_status", scope_path=SCOPE, arguments={"pack_in": str(pack_in)})
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    twin = lab_drop_to_sor_cli_twin(ROOT)
    assert twin["name"] == "lab_drop_to_sor"
    assert twin["kind"] == "lab_dest_in"
    assert twin["command"] == "./scripts/lab_drop_to_sor.sh"
    assert twin["make"] == ""
    assert twin["ps1"] == ".\\scripts\\lab_drop_to_sor.ps1"
    for payload in (status, data):
        lab = payload["lab_drop_cli_twin"]
        assert lab["command"] == "./scripts/lab_drop_to_sor.sh"
        assert lab["make"] == ""
        assert lab["ps1"] == ".\\scripts\\lab_drop_to_sor.ps1"
        assert lab["kind"] == "lab_dest_in"
        assert "use-existing-in" in lab["note"]
        assert "LAB_SHAPE_FAIL" in lab["note"]
        assert payload["farm_drop_cli_twin"]["command"] == "./scripts/farm_drop_to_sor.sh"
        assert payload["paying_day"] == "FAIL"


def test_lab_drop_uses_existing_in_and_returns_paths(tmp_path: Path) -> None:
    work = tmp_path / "lab-work"
    dest_in = work / "in"
    pack_in = tmp_path / "pack-in"
    pack_in.mkdir()
    marker = stage_lab_drop_dest_in(dest_in)
    before = _fingerprint(dest_in)
    data = dispatch(
        "lab_drop",
        scope_path=SCOPE,
        arguments={"work": str(work), "pack_in": str(pack_in)},
    )
    assert data["tool"] == "lab_drop"
    assert data["ok"] is True, data.get("stderr") or data.get("error")
    assert data["scope_gated"] is True
    assert data["lab"] is True
    assert data["sample"] is False
    assert data["seeded"] is False
    assert data["use_existing_in"] is True
    assert data["client_keep"] is False
    assert data["stamp"]["client"] is False
    assert data["demo"] is True
    assert data["paying_day"] == "FAIL"
    assert data["posted"] is False
    assert data["http"] is False
    assert data["dest_in_written"] is False
    assert data["pack_in_written"] is False
    assert data["lab_stamp"] is True
    assert data["unexpected_demo_adapters"] == []
    assert "LAB" in data["estate"]
    assert "SAMPLE" not in data["estate"]
    assert "LAB≠SAMPLE" in data["banners"]
    assert "LAB≠client" in data["banners"]
    assert data["cli_twin"]["command"] == "./scripts/lab_drop_to_sor.sh"
    assert data["cli_twin"]["make"] == ""
    out_dir = (work / "out").resolve()
    assert data["out"] == str(out_dir)
    twin = data["console_cli_twin"]
    assert twin["name"] == "product_console"
    assert twin["kind"] == "loopback_console"
    assert twin["out_dir"] == str(out_dir)
    assert twin["command"] == f"OUT_DIR={out_dir} python -m product"
    assert twin["posix"] == twin["command"]
    assert twin["windows"] == f"set OUT_DIR={out_dir} && python -m product"
    assert "python -m product" in twin["posix"]
    assert "OUT_DIR" in twin["posix"]
    assert "set OUT_DIR" in twin["windows"]
    assert "python -m product" in twin["windows"]
    assert twin["bind"] == "127.0.0.1"
    assert twin["http"] is False
    assert twin["posted"] is False
    assert twin["client"] is False
    assert twin["lab"] is True
    assert twin["sample"] is False
    assert twin["paying_day"] == "FAIL"
    assert "127.0.0.1" in twin["note"]
    assert "/api/risks" in twin["note"]
    assert "LAB≠SAMPLE" in twin["note"] or "LAB≠SAMPLE≠client" in twin["note"]
    assert "PROVE_WORK_ROOT" in twin["note"]
    hint = data["console_hint"]
    assert "OUT_DIR" in hint
    assert "python -m product" in hint
    assert str(out_dir) in hint
    assert "set OUT_DIR" in hint
    assert "127.0.0.1" in hint
    assert "/api/risks" in hint
    assert "LAB≠SAMPLE" in hint or "LAB≠SAMPLE≠client" in hint
    assert Path(data["ciso_dir"]).is_dir()
    assert data["ciso_files"]
    assert all(p.endswith(".csv") and "ciso-assistant" in p for p in data["ciso_files"])
    assert Path(data["poam"]).is_file()
    assert Path(data["prove"]).is_file()
    stamp = data["stamp"]
    assert stamp["status"] == "pass"
    assert stamp["lab"] is True
    assert stamp["seeded"] is False
    assert stamp["use_existing_in"] is True
    assert stamp["sample"] is False
    assert stamp["client"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["counts"]["findings"] >= MIN_LAB_FINDINGS
    assert stamp["counts"]["poam"] >= MIN_LAB_POAM
    assert _fingerprint(dest_in) == before
    assert marker.is_file()
    assert (dest_in / "LAB.txt").is_file()
    assert not (dest_in / "nmap" / "pack_drop" / "rustscan").exists()
    assert not (dest_in / "honeypot").exists()
    assert not (dest_in / "SAMPLE.txt").exists()
    assert list(pack_in.iterdir()) == []


def test_lab_drop_fail_closed_on_empty_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LAB_ESTATE_OUT", raising=False)
    monkeypatch.delenv("LAST_LAB_PROVE", raising=False)
    monkeypatch.delenv("PROVE_WORK_ROOT", raising=False)
    work = tmp_path / "empty"
    dest_in = work / "in"
    dest_in.mkdir(parents=True)
    (dest_in / "SAMPLE.txt").write_text("banner only\n", encoding="utf-8")
    data = dispatch("lab_drop", scope_path=SCOPE, arguments={"work": str(work)})
    assert data["tool"] == "lab_drop"
    assert data["ok"] is False
    assert data["fail_code"] == "EXISTING_IN_FAIL"
    assert "EXISTING_IN_FAIL" in data["stderr"]
    assert data["sample"] is False
    assert data["lab"] is True
    assert data["seeded"] is False
    assert data["paying_day"] == "FAIL"
    assert data["posted"] is False
    assert keep_tool_fail_text(data)
    assert list(dest_in.iterdir()) == [dest_in / "SAMPLE.txt"]
    assert not (work / "prove-ciso.json").exists()
    missing = dispatch("lab_drop", scope_path=SCOPE, arguments={})
    assert missing["ok"] is False
    assert missing["fail_code"] == "EXISTING_IN_FAIL"
    assert missing.get("auto_hint") is not True
    assert missing.get("ran") is not True
    body = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "lab_drop", "arguments": {"work": str(work)}},
        }
    )
    assert body.get("error")
    assert "EXISTING_IN_FAIL" in body["error"]["message"]


def test_lab_drop_fail_closed_on_lab_shape_honeypot(tmp_path: Path) -> None:
    work = tmp_path / "prove"
    dest_in = work / "in"
    marker = stage_lab_drop_dest_in(dest_in)
    _copy_tree(HONEYPOT_FIXTURE, dest_in / "honeypot")
    before = _fingerprint(dest_in)
    data = dispatch("lab_drop", scope_path=SCOPE, arguments={"work": str(work)})
    assert data["ok"] is False
    assert data["fail_code"] == LAB_SHAPE_FAIL
    assert LAB_SHAPE_FAIL in data["stderr"]
    assert "honeypot" in data["stderr"]
    assert data["sample"] is False
    assert data["lab"] is True
    assert data["paying_day"] == "FAIL"
    assert keep_tool_fail_text(data)
    assert _fingerprint(dest_in) == before
    assert marker.is_file()
    assert (dest_in / "LAB.txt").is_file()
    assert not (work / "prove-ciso.json").exists()
    body = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "lab_drop", "arguments": {"dest_in": str(dest_in)}},
        }
    )
    assert body.get("error")
    assert LAB_SHAPE_FAIL in body["error"]["message"]
    data["stderr"].encode("cp1252")
    assert "\u2260" not in data["stderr"]


def test_lab_drop_fail_closed_on_lab_shape_rustscan_sibling(tmp_path: Path) -> None:
    work = tmp_path / "prove"
    dest_in = work / "in"
    stage_lab_drop_dest_in(dest_in)
    _copy_tree(RUSTSCAN_FIXTURE, dest_in / "nmap" / "pack_drop" / "rustscan")
    data = dispatch(
        "lab_drop",
        scope_path=SCOPE,
        arguments={"work": str(work), "dest_in": str(dest_in)},
    )
    assert data["ok"] is False
    assert data["fail_code"] == LAB_SHAPE_FAIL
    assert LAB_SHAPE_FAIL in data["stderr"]
    assert "rustscan" in data["stderr"]
    assert (dest_in / "LAB.txt").is_file()
    assert (dest_in / "nmap" / "pack_drop" / "rustscan" / "meta.json").is_file()
    assert not (work / "prove-ciso.json").exists()


def test_lab_drop_refuses_unsigned_scope(tmp_path: Path) -> None:
    empty = tmp_path / "SCOPE.yaml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(GateError, match="SCOPE"):
        dispatch("lab_drop", scope_path=empty, arguments={"work": str(tmp_path / "w")})


def test_lab_drop_cli_twin_helper() -> None:
    twin = lab_drop_to_sor_cli_twin(ROOT)
    assert twin["present"] is True
    assert twin["command"] == "./scripts/lab_drop_to_sor.sh"
    assert twin["make"] == ""
    assert twin["ps1"] == ".\\scripts\\lab_drop_to_sor.ps1"
    assert twin["kind"] == "lab_dest_in"
    assert "LAB_SHAPE_FAIL" in twin["note"]
    assert "use-existing-in" in twin["note"]
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "lab-drop-to-sor:" not in makefile


def test_console_cli_twin_helper(tmp_path: Path) -> None:
    work = tmp_path / "lab-work"
    work.mkdir()
    twin = console_cli_twin(work)
    out_dir = (work / "out").resolve()
    assert twin["out_dir"] == str(out_dir)
    assert twin["command"] == f"OUT_DIR={out_dir} python -m product"
    assert "python -m product" in twin["posix"]
    assert "OUT_DIR" in twin["posix"]
    assert "set OUT_DIR" in twin["windows"]
    assert "python -m product" in twin["windows"]
    assert twin["client"] is False
    assert twin["http"] is False
    assert twin["posted"] is False
    assert twin["bind"] == "127.0.0.1"
    hint = console_hint(work)
    assert str(out_dir) in hint
    assert "python -m product" in hint
    assert "OUT_DIR" in hint
    assert "set OUT_DIR" in hint
    assert "127.0.0.1" in hint
    assert "/api/risks" in hint


def test_console_cli_twin_explicit_out_is_the_stamp_not_nested_out(
    tmp_path: Path,
) -> None:
    stamp = tmp_path / "lab-prove-20260922-213632"
    stamp.mkdir()
    twin = console_cli_twin(out=stamp)
    dest = stamp.resolve()
    assert twin["out_dir"] == str(dest)
    assert twin["command"] == f"OUT_DIR={dest} python -m product"
    assert twin["windows"] == f"set OUT_DIR={dest} && python -m product"
    assert (stamp / "out") != Path(twin["out_dir"])
    hint = console_hint(out=stamp)
    assert str(dest) in hint
    assert "python -m product" in hint
    assert "set OUT_DIR" in hint


def _stage_last_lab_prove(tmp_path: Path) -> dict[str, Path]:
    lab_root = tmp_path / "lab-estate"
    lab_out = lab_root / "out"
    stamp = lab_out / "lab-prove-20260922-213632"
    stamp.mkdir(parents=True)
    (stamp / "summary.json").write_text(
        json.dumps(
            {
                "lab": True,
                "sample": False,
                "demo": True,
                "client": False,
                "seeded": False,
                "use_existing_in": True,
                "assets": 48,
                "findings": 104,
                "poam": 22,
            }
        ),
        encoding="utf-8",
    )
    (stamp / "LAB.txt").write_text(
        "LAB Docker estate — not a client KEEP. paying_day FAIL.\n",
        encoding="utf-8",
    )
    (stamp / "prove-ciso.json").write_text(
        json.dumps(
            {
                "lab": True,
                "sample": False,
                "client": False,
                "seeded": False,
                "posted": False,
                "paying_day": "FAIL",
                "use_existing_in": True,
            }
        ),
        encoding="utf-8",
    )
    marker = lab_out / "LAST_LAB_PROVE.txt"
    marker.write_bytes((str(stamp) + "\n").encode("utf-8"))
    work = lab_root / "prove-work" / "20260922-213632"
    dest_in = work / "in"
    dest_in.mkdir(parents=True)
    (dest_in / "LAB.txt").write_text("LAB dest_in\n", encoding="utf-8")
    return {
        "lab_out": lab_out,
        "stamp": stamp,
        "marker": marker,
        "work": work,
        "dest_in": dest_in,
    }


def test_lab_drop_auto_hints_last_lab_prove_without_rerunning_prove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = _stage_last_lab_prove(tmp_path)
    monkeypatch.delenv("LAB_ESTATE_OUT", raising=False)
    monkeypatch.delenv("LAST_LAB_PROVE", raising=False)
    monkeypatch.delenv("PROVE_WORK_ROOT", raising=False)

    def boom(*_args, **_kwargs):
        raise AssertionError("auto-hint must not re-run prove_ciso")

    monkeypatch.setattr("scripts.prove_ciso.prove_ciso", boom)
    data = dispatch(
        "lab_drop",
        scope_path=SCOPE,
        arguments={"lab_out": str(staged["lab_out"])},
    )
    assert data["tool"] == "lab_drop"
    assert data["ok"] is True, data.get("stderr") or data.get("error")
    assert data["auto_hint"] is True
    assert data["ran"] is False
    assert data["seeded"] is False
    assert data["use_existing_in"] is True
    assert data["lab"] is True
    assert data["sample"] is False
    assert data["client"] is False
    assert data["client_keep"] is False
    assert data["paying_day"] == "FAIL"
    assert data["posted"] is False
    assert data["http"] is False
    assert data["live"] is False
    assert Path(data["out"]).resolve() == staged["stamp"].resolve()
    assert data["stamp"] == "lab-prove-20260922-213632"
    assert Path(data["work"]).resolve() == staged["work"].resolve()
    assert Path(data["dest_in"]).resolve() == staged["dest_in"].resolve()
    twin = data["console_cli_twin"]
    assert twin["out_dir"] == str(staged["stamp"].resolve())
    assert twin["command"] == f"OUT_DIR={staged['stamp'].resolve()} python -m product"
    assert twin["windows"] == f"set OUT_DIR={staged['stamp'].resolve()} && python -m product"
    assert twin["bind"] == "127.0.0.1"
    assert twin["client"] is False
    assert twin["posted"] is False
    assert "/api/risks" in twin["note"]
    hint = data["console_hint"]
    assert str(staged["stamp"].resolve()) in hint
    assert "python -m product" in hint
    assert "set OUT_DIR" in hint
    assert "Did not re-run prove" in data["note"] or "did not re-run prove" in data["note"].lower()
    body = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "lab_drop",
                "arguments": {"lab_out": str(staged["lab_out"])},
            },
        }
    )
    assert "error" not in body
    assert body["result"]["auto_hint"] is True
    assert body["result"]["ok"] is True


def test_lab_drop_auto_hint_from_lab_estate_out_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = _stage_last_lab_prove(tmp_path)
    monkeypatch.setenv("LAB_ESTATE_OUT", str(staged["lab_out"]))
    monkeypatch.delenv("LAST_LAB_PROVE", raising=False)
    monkeypatch.delenv("PROVE_WORK_ROOT", raising=False)
    data = dispatch("lab_drop", scope_path=SCOPE, arguments={})
    assert data["ok"] is True
    assert data["auto_hint"] is True
    assert data["ran"] is False
    assert Path(data["out"]).resolve() == staged["stamp"].resolve()


def test_tools_list_lab_drop_advertises_auto_hint() -> None:
    entries = {row["name"]: row for row in tools_list_entries()}
    desc = entries["lab_drop"]["description"]
    assert "LAST_LAB_PROVE" in desc
    assert "auto-hint" in desc.lower() or "auto_hint" in desc
    props = entries["lab_drop"]["inputSchema"]["properties"]
    assert props["lab_out"]["type"] == "string"
    assert "LAST_LAB_PROVE" in props["lab_out"]["description"]
    iface = (ROOT / "dropbox" / "operator_mcp_interface.md").read_text(encoding="utf-8")
    assert "LAST_LAB_PROVE" in iface
    assert "lab_out" in iface
    prove = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "LAST_LAB_PROVE" in prove
    assert "lab_out" in prove
