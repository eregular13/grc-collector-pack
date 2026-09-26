"""MCP scan_to_sor: SCOPE fail-closed before scan, then LAB pack → SoR.

Refusal cases never invoke the scan entry and never write risk register / POA&M.
Happy path uses fixtures/lab-drop (no network, no live scan).
LAB != SAMPLE != client. Never pack in/. Never POST /api/risks.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from dropbox.mcp_stub import (
    LAB_ESTATE_NETWORKS,
    OPERATOR_TOOLS,
    allows_lab_estate_target,
    dispatch,
    scan_to_sor_cli_twin,
    tools_list_entries,
)
from shared.ciso_shape import assert_risk_register_and_poam

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "dropbox" / "SCOPE.yaml"


def _consent(tmp_path: Path, text: str = "ok\n") -> tuple[Path, str]:
    att = tmp_path / "consent.md"
    att.write_text(text, encoding="utf-8")
    return att, hashlib.sha256(att.read_bytes()).hexdigest()


def _write_scope(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "SCOPE.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _signed_scope(
    tmp_path: Path,
    *,
    start: str = "2026-09-01",
    end: str = "2026-12-31",
    digest: str | None = None,
    cidrs: str | None = None,
) -> Path:
    att, real = _consent(tmp_path)
    hashed = digest if digest is not None else real
    nets = cidrs if cidrs is not None else "    - 10.20.30.0/23\n"
    return _write_scope(
        tmp_path,
        "client:\n  name: DEMO — not a client estate\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {hashed}\nengagement:\n  start: {start}\n"
        f"  end: {end}\ninternal:\n  cidrs:\n{nets}"
        "  hosts:\n    - 127.0.0.1\nexternal:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - nmap\n",
    )


def _patch_scan_raise(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    calls = {"n": 0}

    def boom(*_a, **_k):
        calls["n"] += 1
        raise AssertionError("scan_and_pack invoked after SCOPE refusal")

    monkeypatch.setattr("dropbox.mcp_stub.scan_and_pack", boom)
    return calls


def _sor_artifacts(out: Path) -> list[Path]:
    return [
        out / "ciso-assistant" / "risk_scenarios.csv",
        out / "ciso-assistant" / "findings.csv",
        out / "poam" / "poam.csv",
        out / "poam" / "poam.md",
    ]


def _assert_out_untouched(out: Path) -> None:
    for path in _sor_artifacts(out):
        assert not path.is_file(), path


def test_scan_to_sor_refuses_missing_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_scan_raise(monkeypatch)
    missing = tmp_path / "no-such-SCOPE.yaml"
    out = tmp_path / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=missing,
        arguments={"targets": ["127.0.0.1"], "out": str(out), "work": str(tmp_path / "w")},
    )
    assert result["ok"] is False
    assert result["refused"] is True
    assert result["scanned"] is False
    assert result["wrote_out"] is False
    reason = result["reason"]
    assert "SCOPE gate" in reason
    assert "no SCOPE file" in reason
    assert result["fail_code"] == "SCOPE_MISSING"
    assert calls["n"] == 0
    _assert_out_untouched(out)


def test_scan_to_sor_refuses_unsigned_or_invalid_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_scan_raise(monkeypatch)
    scope = _signed_scope(tmp_path, digest="00" * 32)
    out = tmp_path / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=scope,
        arguments={"targets": ["127.0.0.1"], "out": str(out), "work": str(tmp_path / "w")},
    )
    assert result["ok"] is False
    assert result["refused"] is True
    assert result["scanned"] is False
    reason = result["reason"]
    assert "SCOPE gate" in reason
    assert "hash mismatch" in reason or "attestation" in reason
    assert result["fail_code"] == "SCOPE_UNSIGNED"
    assert calls["n"] == 0
    _assert_out_untouched(out)


def test_scan_to_sor_refuses_expired_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_scan_raise(monkeypatch)
    scope = _signed_scope(tmp_path, start="2020-01-01", end="2020-12-31")
    out = tmp_path / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=scope,
        arguments={"targets": ["127.0.0.1"], "out": str(out), "work": str(tmp_path / "w")},
    )
    assert result["ok"] is False
    assert result["refused"] is True
    assert result["scanned"] is False
    reason = result["reason"]
    assert "SCOPE gate" in reason
    assert "outside engagement window" in reason
    assert result["fail_code"] == "SCOPE_EXPIRED"
    assert calls["n"] == 0
    _assert_out_untouched(out)


def test_scan_to_sor_refuses_target_outside_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_scan_raise(monkeypatch)
    out = tmp_path / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=SCOPE,
        arguments={
            "targets": ["8.8.8.8"],
            "out": str(out),
            "work": str(tmp_path / "w"),
            "estate": "lab",
        },
    )
    assert result["ok"] is False
    assert result["refused"] is True
    assert result["scanned"] is False
    reason = result["reason"]
    assert "SCOPE gate" in reason
    assert "outside authorized SCOPE" in reason
    assert "8.8.8.8" in reason
    assert result["fail_code"] == "SCOPE_TARGET"
    assert calls["n"] == 0
    _assert_out_untouched(out)


def test_scan_to_sor_happy_path_lab_fixtures(tmp_path: Path) -> None:
    work = tmp_path / "scan-work"
    out = work / "out"
    pack_in = tmp_path / "pack-in"
    pack_in.mkdir()
    result = dispatch(
        "scan_to_sor",
        scope_path=SCOPE,
        arguments={
            "targets": ["127.0.0.1"],
            "out": str(out),
            "work": str(work),
            "estate": "lab",
            "pack_in": str(pack_in),
        },
    )
    assert result["tool"] == "scan_to_sor"
    assert result["ok"] is True, result.get("stderr") or result.get("reason")
    assert result["refused"] is False
    assert result["live"] is False
    assert result["scanned"] is True
    assert result["lab"] is True
    assert result["sample"] is False
    assert result["client"] is False
    assert result["client_keep"] is False
    assert result["paying_day"] == "FAIL"
    assert result["posted"] is False
    assert result["http"] is False
    assert result["targets"] == ["127.0.0.1"]
    register = Path(result["risk_register"])
    poam = Path(result["poam"])
    pack = Path(result["pack_drop"])
    assert register.is_file()
    assert poam.is_file()
    assert pack.is_dir()
    assert (pack / "meta.json").is_file()
    assert (pack / "LAB.txt").is_file()
    assert not (pack / "SAMPLE.txt").exists()
    assert "LAB" in result["estate"]
    assert "SAMPLE" not in result["estate"]
    twin = result["cli_twin"]
    assert twin["name"] == "scan_to_sor"
    assert twin["kind"] == "scan_pack_sor"
    assert "lab_drop_to_sor" in twin["command"]
    assert "python -m dropbox run" in twin["command"]
    shape = assert_risk_register_and_poam(out)
    assert shape["findings"] >= 1
    assert shape["risk_scenarios"] >= 1
    assert shape["poam_rows"] >= 1
    assert list(pack_in.rglob("*")) == []


def test_scan_to_sor_tools_list_and_docs() -> None:
    assert "scan_to_sor" in OPERATOR_TOOLS
    assert OPERATOR_TOOLS[-1] == "scan_to_sor"
    entries = {row["name"]: row for row in tools_list_entries()}
    desc = entries["scan_to_sor"]["description"]
    assert "scan" in desc.lower()
    assert "SCOPE" in desc
    assert "lab_drop" in desc or "lab_drop_to_sor" in desc
    props = entries["scan_to_sor"]["inputSchema"]["properties"]
    assert props["scope"]["type"] == "string"
    assert "SCOPE.yaml" in props["scope"]["description"]
    assert props["targets"]["type"] == "array"
    assert props["out"]["type"] == "string"
    assert props["estate"]["type"] == "string"
    twin = scan_to_sor_cli_twin(ROOT)
    assert twin["command"] == (
        "python -m dropbox run --profile all && ./scripts/lab_drop_to_sor.sh --work DIR"
    )
    assert twin["ps1"] == ".\\scripts\\lab_drop_to_sor.ps1"
    iface = (ROOT / "dropbox" / "operator_mcp_interface.md").read_text(encoding="utf-8")
    assert "`scan_to_sor`" in iface
    assert "scan_to_sor" in iface
    assert "outside authorized SCOPE" in iface or "outside" in iface
    assert "SCOPE_EXPIRED" in iface or "expired" in iface
    assert "lab_drop_to_sor" in iface
    assert "python -m dropbox run" in iface
    assert "GRC_LIVE_SCAN" in iface
    assert "LIVE_ESTATE" in iface
    assert "LIVE_LAB_NET" in iface
    assert "172.28.10.0/24" in iface
    assert "172.28.11.0/24" in iface
    assert "172.31.250.0/24" in iface
    assert "docker network inspect" in iface
    assert "192.168.64.0/24" not in iface


def _patch_collectors_raise(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    calls = {"scan_and_pack": 0, "run_live_collectors": 0}

    def boom_scan(*_a, **_k):
        calls["scan_and_pack"] += 1
        raise AssertionError("scan_and_pack invoked after refusal")

    def boom_live(*_a, **_k):
        calls["run_live_collectors"] += 1
        raise AssertionError("run_live_collectors invoked after refusal")

    monkeypatch.setattr("dropbox.mcp_stub.scan_and_pack", boom_scan)
    monkeypatch.setattr("dropbox.mcp_stub.run_live_collectors", boom_live)
    return calls


def _stage_lab_drop(dest_in: Path) -> Path:
    from scripts.prove_ciso import _copy_tree

    dest_in = Path(dest_in)
    _copy_tree(ROOT / "fixtures" / "lab-drop", dest_in)
    pack = dest_in / "nmap" / "pack_drop"
    assert pack.is_dir()
    return pack


def test_scan_to_sor_live_refuses_target_outside_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRC_LIVE_SCAN", "1")
    calls = _patch_collectors_raise(monkeypatch)
    out = tmp_path / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=SCOPE,
        arguments={
            "targets": ["8.8.8.8"],
            "out": str(out),
            "work": str(tmp_path / "w"),
            "estate": "lab",
        },
    )
    assert result["ok"] is False
    assert result["refused"] is True
    assert result["live"] is True
    assert result["scanned"] is False
    assert result["wrote_out"] is False
    reason = result["reason"]
    assert "SCOPE gate" in reason
    assert "outside authorized SCOPE" in reason
    assert "8.8.8.8" in reason
    assert result["fail_code"] == "SCOPE_TARGET"
    assert calls["scan_and_pack"] == 0
    assert calls["run_live_collectors"] == 0
    _assert_out_untouched(out)


@pytest.mark.parametrize(
    ("kind", "scope_factory", "fail_code", "needle"),
    [
        (
            "missing",
            lambda tmp: tmp / "no-such-SCOPE.yaml",
            "SCOPE_MISSING",
            "no SCOPE file",
        ),
        (
            "unsigned",
            lambda tmp: _signed_scope(tmp, digest="00" * 32),
            "SCOPE_UNSIGNED",
            "hash mismatch",
        ),
        (
            "expired",
            lambda tmp: _signed_scope(tmp, start="2020-01-01", end="2020-12-31"),
            "SCOPE_EXPIRED",
            "outside engagement window",
        ),
    ],
    ids=["missing", "unsigned", "expired"],
)
def test_scan_to_sor_live_refuses_missing_or_expired_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    scope_factory,
    fail_code: str,
    needle: str,
) -> None:
    monkeypatch.setenv("GRC_LIVE_SCAN", "1")
    calls = _patch_collectors_raise(monkeypatch)
    scope = scope_factory(tmp_path)
    out = tmp_path / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=scope,
        arguments={"targets": ["127.0.0.1"], "out": str(out), "work": str(tmp_path / "w")},
    )
    assert result["ok"] is False, kind
    assert result["refused"] is True
    assert result["live"] is True
    assert result["scanned"] is False
    assert result["wrote_out"] is False
    reason = result["reason"]
    assert "SCOPE gate" in reason
    assert needle in reason or (fail_code == "SCOPE_UNSIGNED" and "attestation" in reason)
    assert result["fail_code"] == fail_code
    assert calls["scan_and_pack"] == 0
    assert calls["run_live_collectors"] == 0
    _assert_out_untouched(out)


def test_scan_to_sor_live_refuses_non_lab_estate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRC_LIVE_SCAN", "1")
    calls = _patch_collectors_raise(monkeypatch)
    scope = _signed_scope(tmp_path)
    out = tmp_path / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=scope,
        arguments={
            "targets": ["127.0.0.1"],
            "out": str(out),
            "work": str(tmp_path / "w"),
            "estate": "keep",
        },
    )
    assert result["ok"] is False
    assert result["refused"] is True
    assert result["live"] is True
    assert result["scanned"] is False
    assert result["wrote_out"] is False
    reason = result["reason"]
    assert "SCOPE gate" in reason
    assert "live mode refuses estate" in reason
    assert "keep" in reason
    assert result["fail_code"] == "LIVE_ESTATE"
    assert calls["scan_and_pack"] == 0
    assert calls["run_live_collectors"] == 0
    _assert_out_untouched(out)


@pytest.mark.parametrize(
    ("target", "scope_kind"),
    [
        ("127.0.0.1", "repo"),
        ("192.168.64.10", "legacy"),
    ],
    ids=["loopback", "legacy-192-168-64"],
)
def test_scan_to_sor_live_refuses_target_outside_lab_estate_networks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    scope_kind: str,
) -> None:
    monkeypatch.setenv("GRC_LIVE_SCAN", "1")
    calls = _patch_collectors_raise(monkeypatch)
    if scope_kind == "legacy":
        scope = _signed_scope(
            tmp_path,
            cidrs="    - 10.20.30.0/23\n    - 192.168.64.0/24\n",
        )
    else:
        scope = SCOPE
    out = tmp_path / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=scope,
        arguments={
            "targets": [target],
            "out": str(out),
            "work": str(tmp_path / "w"),
            "estate": "lab",
        },
    )
    assert result["ok"] is False
    assert result["refused"] is True
    assert result["live"] is True
    assert result["scanned"] is False
    assert result["wrote_out"] is False
    reason = result["reason"]
    assert "SCOPE gate" in reason
    assert "outside lab-estate networks" in reason
    assert target in reason
    assert result["fail_code"] == "LIVE_LAB_NET"
    assert calls["scan_and_pack"] == 0
    assert calls["run_live_collectors"] == 0
    _assert_out_untouched(out)


LIVE_LAB_ALLOW_HOSTS = (
    ("172.28.10.10", "labnet"),
    ("172.28.11.10", "labnet2"),
    ("172.31.250.10", "misconfig"),
)
LIVE_LAB_ALLOW_CIDRS = (
    "    - 10.20.30.0/23\n"
    "    - 172.28.10.0/24\n"
    "    - 172.28.11.0/24\n"
    "    - 172.31.250.0/24\n"
)


def test_lab_estate_networks_are_desktop_compose_cidrs() -> None:
    assert LAB_ESTATE_NETWORKS == (
        "172.28.10.0/24",
        "172.28.11.0/24",
        "172.31.250.0/24",
    )
    assert "192.168.64.0/24" not in LAB_ESTATE_NETWORKS
    for host, _label in LIVE_LAB_ALLOW_HOSTS:
        assert allows_lab_estate_target(host) is True
    assert allows_lab_estate_target("127.0.0.1") is False
    assert allows_lab_estate_target("192.168.64.10") is False


@pytest.mark.parametrize(
    "target",
    [host for host, _label in LIVE_LAB_ALLOW_HOSTS],
    ids=[label for _host, label in LIVE_LAB_ALLOW_HOSTS],
)
def test_scan_to_sor_live_happy_path_mocked_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    monkeypatch.setenv("GRC_LIVE_SCAN", "1")
    calls: dict[str, object] = {"n": 0, "targets": None}

    def fake_live(*, scope, targets, dest_in, estate="lab"):
        calls["n"] = int(calls["n"]) + 1
        calls["targets"] = list(targets)
        calls["estate"] = estate
        return _stage_lab_drop(Path(dest_in))

    def boom_scan(*_a, **_k):
        raise AssertionError("fixture scan_and_pack invoked in live mode")

    monkeypatch.setattr("dropbox.mcp_stub.run_live_collectors", fake_live)
    monkeypatch.setattr("dropbox.mcp_stub.scan_and_pack", boom_scan)
    work = tmp_path / "scan-work"
    out = work / "out"
    pack_in = tmp_path / "pack-in"
    pack_in.mkdir()
    scope = _signed_scope(
        tmp_path,
        cidrs=LIVE_LAB_ALLOW_CIDRS,
    )
    result = dispatch(
        "scan_to_sor",
        scope_path=scope,
        arguments={
            "targets": [target],
            "out": str(out),
            "work": str(work),
            "estate": "lab",
            "pack_in": str(pack_in),
        },
    )
    assert result["tool"] == "scan_to_sor"
    assert result["ok"] is True, result.get("stderr") or result.get("reason")
    assert result["refused"] is False
    assert result["live"] is True
    assert result["scanned"] is True
    assert result["lab"] is True
    assert result["sample"] is False
    assert result["client"] is False
    assert result["client_keep"] is False
    assert result["paying_day"] == "FAIL"
    assert result["posted"] is False
    assert result["http"] is False
    assert result["targets"] == [target]
    assert calls["n"] == 1
    assert calls["targets"] == [target]
    register = Path(result["risk_register"])
    poam = Path(result["poam"])
    pack = Path(result["pack_drop"])
    assert register.is_file()
    assert poam.is_file()
    assert pack.is_dir()
    twin = result["cli_twin"]
    assert twin["live"] is True
    assert "GRC_LIVE_SCAN=1" in twin["command"]
    assert "--live" in twin["command"]
    shape = assert_risk_register_and_poam(out)
    assert shape["findings"] >= 1
    assert shape["risk_scenarios"] >= 1
    assert shape["poam_rows"] >= 1
    assert list(pack_in.rglob("*")) == []


def test_scan_to_sor_default_mode_live_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GRC_LIVE_SCAN", raising=False)
    live_calls = {"n": 0}

    def boom_live(*_a, **_k):
        live_calls["n"] += 1
        raise AssertionError("run_live_collectors invoked in default fixture mode")

    monkeypatch.setattr("dropbox.mcp_stub.run_live_collectors", boom_live)
    work = tmp_path / "scan-work"
    out = work / "out"
    result = dispatch(
        "scan_to_sor",
        scope_path=SCOPE,
        arguments={
            "targets": ["127.0.0.1"],
            "out": str(out),
            "work": str(work),
            "estate": "lab",
        },
    )
    assert result["ok"] is True, result.get("stderr") or result.get("reason")
    assert result["live"] is False
    assert result["lab"] is True
    assert result["sample"] is False
    assert result["client"] is False
    assert result["paying_day"] == "FAIL"
    assert result["posted"] is False
    assert result["http"] is False
    assert live_calls["n"] == 0
    twin = result["cli_twin"]
    assert twin.get("live") is False
    assert "GRC_LIVE_SCAN=1" not in twin["command"]
    assert Path(result["risk_register"]).is_file()
    assert Path(result["poam"]).is_file()
