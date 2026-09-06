"""Probe isolated Palisade Cowrie lab on loopback. Not 192.168.10.0/24. Not c11."""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dropbox.orchestrator.poam import map_finding

PT = timezone(timedelta(hours=-7))
PACK = Path(__file__).resolve().parents[1]
HP = PACK.parent / "_24h" / "llm-honeypot"
OUT = PACK.parent / "product-lab" / "24h" / "honeypot"
SSH_HOST = "127.0.0.1"
SSH_PORT = 12222
DASH = "http://127.0.0.1:18088/"


def _banner() -> dict[str, object]:
    sock = socket.create_connection((SSH_HOST, SSH_PORT), timeout=8)
    try:
        data = sock.recv(256)
    finally:
        sock.close()
    text = data.decode("utf-8", errors="replace")
    return {"banner": text.strip(), "raw_hex": data.hex()}


def _curl_dash() -> dict[str, object]:
    exe = "curl.exe" if sys.platform.startswith("win") else "curl"
    proc = subprocess.run(
        [exe, "-sS", "-I", "--max-time", "8", "--max-redirs", "0", "--", DASH],
        capture_output=True,
        text=True,
        timeout=14,
        check=False,
        shell=False,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    return {"returncode": proc.returncode, "head": blob[:4000]}


def _ssh_session() -> dict[str, object]:
    try:
        import paramiko
    except ImportError:
        return {"ok": False, "error": "paramiko_missing"}
    cmds = ["whoami", "pwd", "ls", "ps", "df", "id"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    rec: dict[str, object] = {"ok": False, "commands": []}
    try:
        client.connect(
            SSH_HOST,
            port=SSH_PORT,
            username="root",
            password="lab",
            allow_agent=False,
            look_for_keys=False,
            timeout=12,
            banner_timeout=12,
            auth_timeout=12,
        )
        rec["ok"] = True
        rec["transport"] = str(client.get_transport())
        chan = client.invoke_shell(width=80, height=24)
        time.sleep(0.6)
        boot = chan.recv(8000).decode("utf-8", errors="replace") if chan.recv_ready() else ""
        rec["motd"] = boot[:2000]
        rec["motd_repr"] = repr(boot[:500])
        rec["motd_has_ansi_hidden"] = "\x1b[8m" in boot
        for cmd in cmds:
            chan.send(cmd + "\n")
            time.sleep(0.5)
            out = ""
            if chan.recv_ready():
                out = chan.recv(8000).decode("utf-8", errors="replace")
            rec["commands"].append(
                {
                    "cmd": cmd,
                    "stdout": out[:4000],
                    "stdout_repr": repr(out[:800]),
                    "has_ansi_hidden": "\x1b[8m" in out,
                }
            )
        chan.close()
    except Exception as exc:  # noqa: BLE001
        rec["error"] = f"{type(exc).__name__}:{exc}"
    finally:
        client.close()
    return rec


def _cowrie_events() -> list[dict[str, object]]:
    log_dir = HP / "lab-logs"
    events: list[dict[str, object]] = []
    if not log_dir.is_dir():
        return events
    for path in sorted(log_dir.glob("*.json*")) + sorted(log_dir.glob("cowrie.json*")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                blob = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(blob, dict):
                events.append(blob)
    return events


def _findings(banner: str, dash: str, session: dict[str, object]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def add(name: str, severity: str) -> None:
        mapped = map_finding(name, "127.0.0.1", severity)
        mapped["asset"] = "127.0.0.1"
        mapped["name"] = name
        rows.append(mapped)

    if "SSH-2.0" in banner:
        add("SSH service banner disclosure", "low")
    if "OpenSSH_5" in banner or "OpenSSH_5.3" in banner:
        add("Outdated SSH server OpenSSH 5.x", "high")
    if "HTTP/" in dash.upper() or "HTTP/" in dash:
        add("Cleartext HTTP", "medium")
        if "strict-transport-security" not in dash.lower():
            add("Missing HSTS", "medium")
        if "x-frame-options" not in dash.lower() or "content-security-policy" not in dash.lower():
            add("Missing web security headers", "low")
        if "server:" in dash.lower():
            add("Server banner disclosure", "low")
    if session.get("ok"):
        add("Default or any-password SSH credentials on honeypot", "high")
    cmds = session.get("commands") or []
    ansi = bool(session.get("motd_has_ansi_hidden"))
    if isinstance(cmds, list) and any(isinstance(c, dict) and c.get("has_ansi_hidden") for c in cmds):
        ansi = True
    if ansi:
        add("ANSI hidden-channel honeypot trap (LLM prompt injection)", "medium")
    return rows


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    banner = _banner()
    dash = _curl_dash()
    session = _ssh_session()
    time.sleep(1)
    events = _cowrie_events()
    event_types = sorted({str(e.get("eventid") or "") for e in events if e.get("eventid")})
    findings = _findings(str(banner.get("banner") or ""), str(dash.get("head") or ""), session)
    mapped_n = sum(1 for r in findings if r.get("mapped"))
    unmapped = [r.get("weakness") or r.get("name") for r in findings if not r.get("mapped")]
    honeypot_cmds = []
    for e in events:
        if e.get("eventid") in {"cowrie.command.input", "cowrie.session.file_download"}:
            honeypot_cmds.append({"eventid": e.get("eventid"), "input": e.get("input"), "username": e.get("username")})
    tool_cmds = [c.get("cmd") for c in (session.get("commands") or []) if isinstance(c, dict)]
    compare = {
        "clock": datetime.now(PT).strftime("%Y-%m-%dT%H:%M:%S-07:00"),
        "note": "isolated Palisade Cowrie lab; not office LAN; not paying-day",
        "banner": banner,
        "dashboard": dash,
        "ssh_session": session,
        "cowrie_event_count": len(events),
        "cowrie_event_types": event_types,
        "honeypot_logged_commands": honeypot_cmds[:50],
        "tool_commands_sent": tool_cmds,
        "commands_logged_not_sent": [
            h.get("input") for h in honeypot_cmds if h.get("input") not in set(tool_cmds)
        ],
        "commands_sent_not_logged": [c for c in tool_cmds if c not in {h.get("input") for h in honeypot_cmds}],
        "findings": findings,
        "pack_mapped": mapped_n,
        "unmapped": unmapped,
        "facing": False,
    }
    (OUT / "COMPARE.json").write_text(json.dumps(compare, indent=2, default=str), encoding="utf-8")
    (OUT / "cowrie_events.json").write_text(json.dumps(events, indent=2, default=str)[:400000], encoding="utf-8")
    print(json.dumps({"ok": True, "path": str(OUT / "COMPARE.json"), "mapped": mapped_n, "events": len(events), "ssh_ok": session.get("ok")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
