"""Parse dropped fping text or JSON. No subprocess. No live ping."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shared.io_util import read_text

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
ALIVE_RE = re.compile(
    r"^\s*(\S+)\s+is\s+(alive|unreachable(?:\s+\([^)]+\))?|down)(?:\s+\([\d.]+\s*ms\))?\s*$",
    re.IGNORECASE,
)
# -c live replies look like: host : [0], 84 bytes, 0.12 ms (...). Timeouts do not.
LOOP_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*:\s*\[\d+\],\s*\d+\s+bytes,\s*",
    re.IGNORECASE,
)
TIMEOUT_RE = re.compile(r"^\s*(\S+)\s*:\s*\[\d+\],\s*timed out\b", re.IGNORECASE)


def _named(name: str) -> bool:
    return "fping" in name.lower()


def _has_banner(text: str) -> bool:
    low = text[:12000].lower()
    return (
        " is alive" in low
        or " is unreachable" in low
        or "fping statistics" in low
        or low.lstrip().startswith("# fping")
        or '"resp"' in low
        or bool(LOOP_RE.search(text))
    )


def _hostish(token: str) -> tuple[str, str]:
    raw = token.strip().strip(",")
    if not raw:
        return "", ""
    if IP_RE.match(raw):
        return raw, ""
    if any(c.isalpha() for c in raw):
        return "", raw
    return "", ""


def _looks_fping_json_row(row: dict[str, Any]) -> bool:
    resp = row.get("resp")
    if isinstance(resp, dict) and resp.get("host"):
        return True
    if row.get("mac") or row.get("mac_address") or row.get("hwaddr"):
        return False
    if row.get("port") not in (None, ""):
        return False
    ports = row.get("ports")
    if isinstance(ports, list) and ports:
        return False
    target = row.get("ip") or row.get("addr") or row.get("host") or row.get("hostname") or row.get("target")
    if not target:
        return False
    if any(k in row for k in ("alive", "reachable", "up", "status", "state")):
        return True
    return False


def _alive_token(row: dict[str, Any]) -> bool | None:
    if "alive" in row:
        return bool(row.get("alive"))
    if "reachable" in row:
        return bool(row.get("reachable"))
    if "up" in row:
        return bool(row.get("up"))
    state = str(row.get("status") or row.get("state") or "").strip().lower()
    if not state:
        return None
    if state in {"alive", "up", "reachable", "ok", "true", "1"}:
        return True
    if state in {"unreachable", "down", "dead", "false", "0", "timeout"}:
        return False
    return None


def _load_payload(text: str, *, path_name: str = "") -> Any:
    stripped = text.lstrip("\ufeff").lstrip()
    if not stripped:
        return []
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        rows: list[Any] = []
        skipped: list[int] = []
        for lineno, line in enumerate(stripped.split("\n"), 1):
            line = line.strip().rstrip(",")
            if not line or line in {"[", "]"}:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                skipped.append(lineno)
        if path_name and skipped:
            # Named fping export: a corrupt JSON line is a lost host, not noise.
            raise ValueError(
                f"{path_name}: corrupt JSON line(s) {', '.join(map(str, skipped))}; "
                "refusing silent drop"
            )
        return rows


def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    if payload.get("scanner") == "fping" or payload.get("tool") == "fping":
        raw = payload.get("hosts") or payload.get("data") or payload.get("results")
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
        if _looks_fping_json_row(payload):
            return [payload]
        return []
    for key in ("hosts", "data", "results"):
        raw = payload.get(key)
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
    if _looks_fping_json_row(payload):
        return [payload]
    return []


def _host_from_row(row: dict[str, Any]) -> dict[str, Any] | None:
    if not _looks_fping_json_row(row):
        return None
    resp = row.get("resp")
    if isinstance(resp, dict) and resp.get("host"):
        # -J reply object. A timeout has no size/rtt.
        if resp.get("size") in (None, "", 0) and resp.get("rtt") in (None, ""):
            return None
        token = str(resp.get("host") or "").strip()
        addr, hostname = _hostish(token)
        name = hostname or addr
        if not name:
            return None
        return {"name": name, "addr": addr, "hostname": hostname, "ports": []}
    flag = _alive_token(row)
    if flag is False:
        return None
    if flag is None and not (row.get("scanner") == "fping" or row.get("tool") == "fping"):
        return None
    addr = str(row.get("ip") or row.get("addr") or row.get("address") or "").strip()
    hostname = str(row.get("hostname") or row.get("host") or row.get("name") or row.get("target") or "").strip()
    if hostname and IP_RE.match(hostname):
        if not addr:
            addr = hostname
        hostname = ""
    if addr and not IP_RE.match(addr):
        if not hostname:
            hostname = addr
        addr = ""
    name = hostname or addr
    if not name:
        return None
    return {"name": name, "addr": addr, "hostname": hostname, "ports": []}


# Non-host lines fping itself writes (stats.c / output.c / fping.c). These are
# recognised so they are not mistaken for damage; they never create hosts.
_INFO_RES = [
    # -s global stats block
    re.compile(
        r"^\s*\d+\s+(?:targets|alive|unreachable|unknown addresses|"
        r"timeouts \(waiting for response\)|ICMP Echos sent|"
        r"ICMP Echo Replies received|other ICMP received)\s*$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^\s*[\d.]+(?:e[+-]?\d+)?\s+(?:ms \((?:min|avg|max) round trip time\)|"
        r"sec \(elapsed real time\))\s*$",
        re.IGNORECASE,
    ),
    # -c / -Q per-host summary: host : xmt/rcv/%loss = 1/1/0%, min/avg/max = ...
    re.compile(r"^\s*\S+(?:\s+\(\S+\))?\s*:\s*xmt/rcv/%(?:loss|return)\s*=", re.IGNORECASE),
    # -C per-host value list: host : 0.42 0.51 -
    re.compile(r"^\s*\S+(?:\s+\(\S+\))?\s*:(?:\s+(?:[\d.]+(?:e[+-]?\d+)?|-))+\s*$"),
    # duplicate reply notice
    re.compile(r"^\s*\S+(?:\s+\(\S+\))?\s*:\s*duplicate for \[\d+\]"),
    # ICMP error notices
    re.compile(r"^ICMP(?:v6)?\b.* from \S+ for ICMP(?:v6)? Echo(?: Request)? sent to \S+", re.IGNORECASE),
    # -Q interval header
    re.compile(r"^\[\d{2}:\d{2}:\d{2}\]\s*$"),
    # --reachable summary
    re.compile(r"^(?:Not )?[Ee]nough hosts reachable \(required: \d+, reachable: \d+\)\s*$"),
    # resolver / send warnings: name: <reason>
    re.compile(
        r"^\S+: (?:.*not known|.*name resolution|.*no address associated|"
        r"can't forward-lookup address|error while sending ping)",
        re.IGNORECASE,
    ),
    re.compile(r"^received packet too short for ICMP", re.IGNORECASE),
    re.compile(r"^fping[:,] ", re.IGNORECASE),
]
_ALIVE_STAT_RE = re.compile(r"^\s*(\d+)\s+alive\s*$", re.IGNORECASE)
# -D prefixes every output line with a timestamp in brackets.
# Formats: default "%.5f" epoch, ctime "%c", iso "%Y-%m-%dT%T%z", rfc3339.
_STAMP_RE = re.compile(
    r"^\[(?:\d+\.\d+|[A-Za-z]{3} [A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}|"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[+-]\d{4})?)\]\s+"
)
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$")


def _valid_ip(token: str) -> bool:
    return bool(IP_RE.match(token)) and all(int(o) <= 255 for o in token.split("."))


def _strict_host(token: str) -> tuple[str, str]:
    """(addr, hostname) for a well-formed IPv4 or DNS name, else ("", "")."""
    raw = token.strip()
    if _valid_ip(raw):
        return raw, ""
    if all(c.isdigit() or c == "." for c in raw):
        return "", ""  # digits/dots that are not a valid IPv4 address
    if HOSTNAME_RE.match(raw) and any(c.isalpha() for c in raw):
        return "", raw
    return "", ""


# Line kinds: host (alive), skip (understood, not a host), bare (bare IP/name,
# -a style), bad (could not be understood).
def _classify_line(line: str, named: bool) -> tuple[str, dict[str, Any] | None]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return "blank", None
    low = stripped.lower()
    if low.startswith("host:") or "ports:" in low:
        return "bad", None
    body = _STAMP_RE.sub("", stripped, count=1)
    match = ALIVE_RE.match(body)
    if match:
        token, state = match.group(1), match.group(2).lower()
        addr, hostname = _strict_host(token)
        name = hostname or addr
        if not name:
            return "bad", None
        if not state.startswith("alive"):
            return "verbose", None
        return "verbose", {"name": name, "addr": addr, "hostname": hostname, "ports": []}
    if TIMEOUT_RE.match(body):
        addr, hostname = _strict_host(TIMEOUT_RE.match(body).group(1))
        return ("verbose", None) if (addr or hostname) else ("bad", None)
    loop = LOOP_RE.match(body)
    if loop:
        addr = loop.group(1)
        if not _valid_ip(addr):
            return "bad", None
        return "verbose", {"name": addr, "addr": addr, "hostname": "", "ports": []}
    if any(rx.match(body) for rx in _INFO_RES):
        return "skip", None
    if named and _valid_ip(body):
        return "bare", {"name": body, "addr": body, "hostname": "", "ports": []}
    return "bad", None


def _host_from_line(line: str, named: bool) -> dict[str, Any] | None:
    kind, host = _classify_line(line, named)
    return host if kind in {"verbose", "bare"} else None


def _from_text(text: str, named: bool, *, path_name: str = "fping") -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    bad: list[int] = []
    bare: list[int] = []
    verbose = False
    alive_stat: tuple[int, int] | None = None
    # Split on newline only, so a control byte inside a line cannot turn one
    # damaged line into two plausible ones, and line numbers match the file.
    for lineno, line in enumerate(text.split("\n"), 1):
        kind, host = _classify_line(line.rstrip("\r"), named)
        if kind == "bad":
            bad.append(lineno)
            continue
        if kind == "skip":
            stat = _ALIVE_STAT_RE.match(_STAMP_RE.sub("", line.strip(), count=1))
            if stat and alive_stat is None:
                alive_stat = (lineno, int(stat.group(1)))
            continue
        if kind == "verbose":
            verbose = True
        elif kind == "bare":
            bare.append(lineno)
        if host is None:
            continue
        key = str(host["name"]).lower()
        grouped.setdefault(key, host)
    if alive_stat is not None and alive_stat[1] != len(grouped):
        # -s printed its own alive count; a different host count means lines
        # were lost or altered.
        bad.append(alive_stat[0])
    if verbose and bare:
        # With -a the tool prints bare names; -e/-c print "is alive" / reply lines.
        # One run never mixes them, so a bare address here is a damaged line
        # (e.g. "x is unreachable" cut down to "x") and must not become a host.
        bad.extend(bare)
    if bad:
        raise ValueError(
            f"{path_name}: unparseable fping line(s) "
            f"{', '.join(map(str, sorted(bad)))}; refusing silent drop"
        )
    if not grouped:
        # Named export with no host lines. A 0-byte file is not a clean empty
        # scan. A missing trailing newline means the file was cut mid-line —
        # often through a comment — which would otherwise look like a quiet
        # empty result after the host lines were lost. A genuinely empty
        # scan whose comment lines end with a newline stays a quiet 0-row
        # result. A cut exactly at a line boundary cannot be told apart
        # from that empty scan without guessing, so it is not flagged.
        if not text:
            raise ValueError(
                f"{path_name}: empty fping file (0 bytes); refusing silent zero"
            )
        if not text.endswith("\n"):
            last_lineno = text.count("\n") + 1
            raise ValueError(
                f"{path_name}: truncated fping text (no host lines, "
                f"line {last_lineno} has no trailing newline); "
                "refusing silent drop"
            )
    return list(grouped.values())


def parse_fping(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return alive hosts (asset-only), or None when the file is not fping."""
    text = raw if raw is not None else read_text(path)
    stripped = text.lstrip("\ufeff").lstrip()
    if stripped.startswith("<"):
        return None
    named = _named(path.name)
    is_jsonish = (
        stripped.startswith("{")
        # -D text lines start with "[<timestamp>] "; that is not a JSON array.
        or (stripped.startswith("[") and not _STAMP_RE.match(stripped))
        or path.suffix.lower() in {".json", ".jsonl"}
    )
    if is_jsonish:
        payload = _load_payload(text, path_name=path.name if named else "")
        rows = _rows_from_payload(payload)
        fping_rows = [r for r in rows if _looks_fping_json_row(r)]
        if named:
            out: list[dict[str, Any]] = []
            for row in fping_rows:
                host = _host_from_row(row)
                if host is not None:
                    out.append(host)
            return out
        if not fping_rows:
            return None
        if any(
            r.get("port") not in (None, "")
            or (isinstance(r.get("ports"), list) and r.get("ports"))
            or r.get("mac")
            or r.get("mac_address")
            for r in rows[:5]
            if isinstance(r, dict)
        ):
            return None
        out = []
        for row in fping_rows:
            host = _host_from_row(row)
            if host is not None:
                out.append(host)
        return out
    if named or _has_banner(text):
        if "Host:" in text and "Ports:" in text and not named:
            return None
        # -a is a bare IP per line; parse those once the file is known to be fping.
        return _from_text(text, True, path_name=path.name)
    return None
