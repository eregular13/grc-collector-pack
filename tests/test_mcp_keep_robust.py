"""MCP keep_status / keep_ciso fail text, one wipe retry, isolated work dirs."""

from __future__ import annotations

import argparse
import errno
from pathlib import Path

import pytest

from dropbox.mcp_stub import (
    atomic_keep_work,
    dispatch,
    handle_jsonrpc,
    keep_error_text,
    keep_fail_payload,
    keep_tool_fail_text,
    retryable_keep_error,
)
from dropbox.run import cmd_mcp
from keep.wipe import retryable_wipe_error

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "dropbox" / "SCOPE.yaml"


def _winerror_145() -> OSError:
    exc = OSError(145, "The directory is not empty")
    exc.winerror = 145
    return exc


def _pass_stamp(work: Path) -> dict:
    return {
        "status": "pass",
        "ciso_dir": str(work / "out" / "ciso-assistant"),
        "ciso_import": str(work / "out" / "ciso-assistant" / "IMPORT.json"),
        "opengrc": str(work / "out" / "opengrc"),
        "probo": str(work / "out" / "import_preview" / "probo.json"),
        "handoff": str(work / "out" / "eval" / "handoff.json"),
        "reason": "",
    }


def test_keep_error_text_and_retryable_markers() -> None:
    exc = _winerror_145()
    text = keep_error_text(exc, stderr="reset_dir failed")
    assert "reset_dir failed" in text
    assert "directory is not empty" in text.lower() or "WinError 145" in text
    assert retryable_keep_error(exc) is True
    assert retryable_wipe_error(exc) is True
    assert retryable_keep_error(OSError(errno.ENOTEMPTY, "Directory not empty")) is True
    wrapped = RuntimeError("OSError: [WinError 145] The directory is not empty")
    assert retryable_keep_error(wrapped) is True
    assert retryable_keep_error(ValueError("schema miss")) is False
    fail = keep_fail_payload("keep_ciso", exc, retried=True, isolate_work=True)
    assert fail["ok"] is False
    assert fail["retried"] is True
    assert fail["stderr"]
    assert keep_tool_fail_text(fail)
    assert keep_tool_fail_text({"tool": "keep_ciso", "ok": True}) == ""


def test_keep_ciso_fail_returns_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()
    work = tmp_path / "work"

    def boom(*_a, **_k):
        raise RuntimeError("collector exit 2: simulated stderr")

    monkeypatch.setattr("keep.lab.keep_lab", boom)
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    assert data["tool"] == "keep_ciso"
    assert data["ok"] is False
    assert data["retried"] is False
    blob = (data.get("stderr") or "") + (data.get("error") or "")
    assert "simulated stderr" in blob
    assert data["paying_day"] == "FAIL"
    assert data["client_keep"] is False

    rpc = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "keep_ciso",
                "arguments": {"pack_in": str(pack_in), "work": str(work)},
            },
        }
    )
    assert "error" in rpc
    assert rpc["error"]["code"] == 2
    assert "simulated stderr" in rpc["error"]["message"]
    assert rpc["error"]["data"]["ok"] is False

    monkeypatch.setenv("KEEP_WORK", str(work))
    monkeypatch.setenv("IN_DIR", str(pack_in))
    code = cmd_mcp(argparse.Namespace(tool="keep_ciso", scope=str(SCOPE)))
    assert code == 2


def test_keep_status_fail_returns_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()

    def boom(*_a, **_k):
        raise RuntimeError("scan_keep_dir failed: last error text")

    monkeypatch.setattr("dropbox.mcp_stub._keep_family_inventory", boom)
    data = dispatch(
        "keep_status",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in)},
    )
    assert data["tool"] == "keep_status"
    assert data["ok"] is False
    assert "last error text" in (data.get("stderr") or "")
    rpc = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {"name": "keep_status", "arguments": {"pack_in": str(pack_in)}},
        }
    )
    assert rpc["error"]["code"] == 2
    assert "last error text" in rpc["error"]["message"]

    monkeypatch.setenv("IN_DIR", str(pack_in))
    code = cmd_mcp(argparse.Namespace(tool="keep_status", scope=str(SCOPE)))
    assert code == 2


def test_keep_ciso_retries_once_on_winerror_145(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()
    work = tmp_path / "work"
    state = {"n": 0}

    def flaky_reset(path, **_k):
        state["n"] += 1
        if state["n"] == 1:
            raise _winerror_145()
        target = Path(path)
        target.mkdir(parents=True, exist_ok=True)
        return target

    def fake_lab(root, pack_in=None, work=None):
        return _pass_stamp(Path(work))

    monkeypatch.setattr("keep.wipe.reset_dir", flaky_reset)
    monkeypatch.setattr("keep.lab.keep_lab", fake_lab)
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    assert data["ok"] is True
    assert data["retried"] is True
    assert data["error"] == ""
    assert state["n"] >= 2


def test_keep_ciso_retry_still_fail_is_not_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()
    work = tmp_path / "work"
    state = {"n": 0}

    def always_145(path, **_k):
        state["n"] += 1
        raise _winerror_145()

    monkeypatch.setattr("keep.wipe.reset_dir", always_145)
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    assert data["ok"] is False
    assert data["retried"] is True
    assert "145" in data["stderr"] or "not empty" in data["stderr"].lower()
    assert state["n"] >= 2
    assert keep_tool_fail_text(data)


def test_keep_ciso_does_not_retry_non_wipe_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()
    work = tmp_path / "work"
    state = {"n": 0}

    def schema_boom(*_a, **_k):
        state["n"] += 1
        raise ValueError("findings header mismatch")

    monkeypatch.setattr("keep.lab.keep_lab", schema_boom)
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    assert data["ok"] is False
    assert data["retried"] is False
    assert "header mismatch" in data["stderr"]
    assert state["n"] == 1


def test_keep_ciso_isolate_work_unique_subdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()
    parent = tmp_path / "shared-work"
    parent.mkdir()
    seen: list[Path] = []

    def fake_lab(root, pack_in=None, work=None):
        work = Path(work)
        seen.append(work)
        (work / "out" / "ciso-assistant").mkdir(parents=True, exist_ok=True)
        return _pass_stamp(work)

    monkeypatch.setattr("keep.lab.keep_lab", fake_lab)
    first = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={
            "pack_in": str(pack_in),
            "work": str(parent),
            "isolate_work": True,
        },
    )
    second = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={
            "pack_in": str(pack_in),
            "work": str(parent),
            "isolate_work": True,
        },
    )
    assert first["ok"] is True and second["ok"] is True
    assert first["isolate_work"] is True
    assert Path(first["work"]) != Path(second["work"])
    assert Path(first["work"]).parent == parent
    assert Path(second["work"]).parent == parent
    assert Path(first["work"]).name.startswith("run-")
    assert Path(first["ciso_dir"]) != Path(second["ciso_dir"])
    assert seen[0] != seen[1]


def test_keep_ciso_explicit_work_not_isolated_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()
    work = tmp_path / "work"

    def fake_lab(root, pack_in=None, work=None):
        return _pass_stamp(Path(work))

    monkeypatch.setattr("keep.lab.keep_lab", fake_lab)
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    assert data["ok"] is True
    assert data["isolate_work"] is False
    assert Path(data["work"]) == work


def test_keep_ciso_default_shared_work_isolates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()
    shared = tmp_path / "keep" / "work"
    shared.mkdir(parents=True)
    monkeypatch.delenv("KEEP_WORK", raising=False)
    monkeypatch.setattr("dropbox.mcp_stub._repo_root", lambda: tmp_path)
    monkeypatch.setattr("dropbox.mcp_stub._require_keep_package", lambda root=None: tmp_path)

    def fake_lab(root, pack_in=None, work=None):
        return _pass_stamp(Path(work))

    monkeypatch.setattr("keep.lab.keep_lab", fake_lab)
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in)},
    )
    assert data["ok"] is True
    assert data["isolate_work"] is True
    work = Path(data["work"])
    assert work.parent == shared
    assert work.name.startswith("run-")
    assert work != shared


def test_atomic_keep_work_unique(tmp_path: Path) -> None:
    a = atomic_keep_work(tmp_path)
    b = atomic_keep_work(tmp_path)
    assert a != b
    assert a.is_dir() and b.is_dir()
    assert a.parent == tmp_path


def test_keep_ciso_stamp_fail_surfaces_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_in = tmp_path / "in"
    pack_in.mkdir()
    work = tmp_path / "work"

    def bad_stamp(root, pack_in=None, work=None):
        stamp = _pass_stamp(Path(work))
        stamp["status"] = "fail"
        stamp["reason"] = "CISO Assistant CSVs missing: ['findings.csv']"
        return stamp

    monkeypatch.setattr("keep.lab.keep_lab", bad_stamp)
    data = dispatch(
        "keep_ciso",
        scope_path=SCOPE,
        arguments={"pack_in": str(pack_in), "work": str(work)},
    )
    assert data["ok"] is False
    assert data["retried"] is False
    assert "CISO Assistant CSVs missing" in data["stderr"]
    rpc = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {
                "name": "keep_ciso",
                "arguments": {"pack_in": str(pack_in), "work": str(work)},
            },
        }
    )
    assert rpc["error"]["code"] == 2
    assert "CISO Assistant CSVs missing" in rpc["error"]["message"]
