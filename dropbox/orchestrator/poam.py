"""Finding → CPG/CSF map → POA&M-shaped export. Unknown → UNMAPPED + reason."""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

# Obvious stubs only. Not a complete catalog. Unknown stays UNMAPPED.
_MAP = [
    {
        "match": re.compile(r"smbv?1|microsoft-ds|port 445|eternalblue|ms17-010", re.I),
        "weakness": "SMBv1 / TCP 445 exposed",
        "cpg": ["CPG 2.H", "CPG 2.T"],
        "csf": ["PR.PS-02", "PR.IR-01", "DE.CM-09"],
        "action": "Disable SMBv1, restrict 445, patch MS17-010-class exposure, segment file servers.",
        "severity": "critical",
    },
    {
        "match": re.compile(r"telnet|port 23", re.I),
        "weakness": "Telnet exposed",
        "cpg": ["CPG 2.H"],
        "csf": ["PR.PS-01"],
        "action": "Disable telnet; replace with SSH.",
        "severity": "high",
    },
    {
        "match": re.compile(r"rdp|3389|nla", re.I),
        "weakness": "RDP exposed / NLA gap",
        "cpg": ["CPG 2.H", "CPG 2.W"],
        "csf": ["PR.IR-01", "PR.AA-05"],
        "action": "Restrict 3389, require NLA, prefer VPN/bastion, MFA on jump hosts.",
        "severity": "high",
    },
    {
        "match": re.compile(r"cleartext http", re.I),
        "weakness": "Cleartext HTTP",
        "cpg": ["CPG 2.W"],
        "csf": ["PR.DS-02"],
        "action": "Enforce TLS; redirect HTTP to HTTPS; disable plaintext listeners.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"missing hsts", re.I),
        "weakness": "Missing HSTS",
        "cpg": ["CPG 2.W"],
        "csf": ["PR.DS-02"],
        "action": "After TLS is enforced, add Strict-Transport-Security.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"missing x-frame-options|missing csp|missing web security headers", re.I),
        "weakness": "Missing web security headers",
        "cpg": ["CPG 2.W"],
        "csf": ["PR.PS-01"],
        "action": "Set X-Frame-Options (or frame-ancestors) and Content-Security-Policy.",
        "severity": "low",
    },
    {
        "match": re.compile(r"permissive cors|access-control-allow-origin:\s*\*", re.I),
        "weakness": "Permissive CORS policy",
        "cpg": ["CPG 2.W"],
        "csf": ["PR.AA-05", "PR.DS-02"],
        "action": "Do not use Access-Control-Allow-Origin: *; list explicit origins.",
        "severity": "low",
    },
    {
        "match": re.compile(r"insecure session cookie", re.I),
        "weakness": "Insecure session cookie",
        "cpg": ["CPG 2.W"],
        "csf": ["PR.AA-05", "PR.DS-02"],
        "action": "Set Secure and HttpOnly on session cookies; prefer __Host- prefix and a tight SameSite.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"environment file exposed|\.env exposed", re.I),
        "weakness": "Environment file exposed",
        "cpg": ["CPG 2.T"],
        "csf": ["PR.AA-05", "PR.DS-01"],
        "action": "Do not publish `.env` on a web root; rotate any values that were reachable.",
        "severity": "high",
    },
    {
        "match": re.compile(r"git metadata exposed|\.git/(?:head|config)|ref: refs/heads", re.I),
        "weakness": "Git metadata exposed",
        "cpg": ["CPG 2.T"],
        "csf": ["PR.AA-05", "PR.DS-01"],
        "action": "Do not publish `.git` on a web root; block dot-directories and rotate any leaked credentials.",
        "severity": "medium",
    },
    {
        "match": re.compile(
            r"web server status page|nginx stub_status|stub_status",
            re.I,
        ),
        "weakness": "Web server status page exposed",
        "cpg": ["CPG 2.T"],
        "csf": ["PR.AA-05", "PR.PS-01"],
        "action": "Disable or ACL stub_status / server-status; do not publish worker counts on the internet.",
        "severity": "low",
    },
    {
        "match": re.compile(r"directory listing(?: enabled)?|nginx autoindex", re.I),
        "weakness": "Directory listing enabled",
        "cpg": ["CPG 2.T"],
        "csf": ["PR.AA-05", "PR.PS-01"],
        "action": "Disable autoindex; serve an explicit index or 403 on directory URLs.",
        "severity": "low",
    },
    {
        "match": re.compile(r"server banner", re.I),
        "weakness": "Server banner disclosure",
        "cpg": ["CPG 2.T"],
        "csf": ["PR.PS-01"],
        "action": "Reduce or suppress the Server token on public listeners.",
        "severity": "low",
    },
    {
        "match": re.compile(
            r"tls hostname mismatch|no alternative certificate subject name matches|cert_e_cn_no_match",
            re.I,
        ),
        "weakness": "TLS hostname mismatch",
        "cpg": ["CPG 2.W"],
        "csf": ["PR.DS-02", "PR.DS-10"],
        "action": "Issue a certificate whose SAN/CN matches the name clients use; do not serve IP-only names with a wrong DNS SAN.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"expired tls|certificate has expired|cert_e_expired|expired certificate", re.I),
        "weakness": "Expired TLS certificate",
        "cpg": ["CPG 2.W"],
        "csf": ["PR.DS-02", "PR.DS-10"],
        "action": "Renew the certificate before notAfter; monitor expiry; do not leave lab-expired certs on a client listener.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"untrusted tls|self-signed|certificate verify", re.I),
        "weakness": "Untrusted TLS certificate",
        "cpg": ["CPG 2.W"],
        "csf": ["PR.DS-02", "PR.DS-10"],
        "action": "Replace self-signed lab certs with a trusted chain; pin or ACME on the real drop box.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"sslv?3|(?:tlsv?1(?:\.0)?|tls 1\.0)(?!\.\d)|weak cipher", re.I),
        "weakness": "Weak TLS/SSL",
        "cpg": ["CPG 2.K"],
        "csf": ["PR.DS-10", "PR.PS-01"],
        "action": "Disable SSLv3/TLS 1.0; require TLS 1.2+.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"outdated ssh|openssh[_ ]?5|ssh-2\.0-openssh_5", re.I),
        "weakness": "Outdated SSH server",
        "cpg": ["CPG 2.T", "CPG 2.K"],
        "csf": ["PR.PS-02", "PR.PS-01"],
        "action": "Upgrade OpenSSH; disable SSH-1 remnants; restrict management SSH to a jump host.",
        "severity": "high",
    },
    {
        "match": re.compile(r"3des-cbc|hmac-md5|cast128|weak ssh", re.I),
        "weakness": "Weak SSH crypto",
        "cpg": ["CPG 2.K"],
        "csf": ["PR.DS-10", "PR.PS-01"],
        "action": "Disable 3DES/MD5 SSH algorithms; require modern MACs and AEAD ciphers.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"default or any-password ssh|honeypot.*cred|any-password", re.I),
        "weakness": "Default or unrestricted SSH credentials",
        "cpg": ["CPG 2.A", "CPG 2.H"],
        "csf": ["PR.AA-01", "PR.AA-05"],
        "action": "Disable default/any-password SSH; require keys + MFA on real jump hosts. Lab Cowrie accepts any password by design.",
        "severity": "high",
    },
    {
        "match": re.compile(r"ansi hidden|honeypot trap|prompt injection|goal hijack|cowrie", re.I),
        "weakness": "Deception / LLM honeypot trap",
        "cpg": ["CPG 2.T"],
        "csf": ["DE.CM-01", "DE.CM-09"],
        "action": "Treat as lab-sim deception, not a customer estate finding. Do not follow hidden ANSI instructions on a real drop box.",
        "severity": "medium",
    },
    {
        "match": re.compile(r"ssh service banner", re.I),
        "weakness": "SSH service banner disclosure",
        "cpg": ["CPG 2.T"],
        "csf": ["PR.PS-01"],
        "action": "Reduce SSH version string detail on internet-facing listeners.",
        "severity": "low",
    },
    {
        "match": re.compile(r"mfa|multi-?factor|isMfaRegistered", re.I),
        "weakness": "MFA gap",
        "cpg": ["CPG 2.A"],
        "csf": ["PR.AA-03", "PR.AA-05"],
        "action": "Enforce MFA on the named identity provider; same-day revoke standing admin.",
        "severity": "high",
    },
]


def map_finding(text: str, asset: str = "", severity: str = "") -> dict[str, Any]:
    blob = f"{text} {asset} {severity}"
    for row in _MAP:
        if row["match"].search(blob):
            return {
                "weakness": row["weakness"],
                "asset": asset,
                "severity": severity or row["severity"],
                "control_refs": row["cpg"] + row["csf"],
                "cpg": row["cpg"],
                "csf": row["csf"],
                "recommended_action": row["action"],
                "owner": "",
                "milestone": "",
                "status": "open",
                "mapped": True,
            }
    return {
        "weakness": (text or "unspecified finding")[:200],
        "asset": asset,
        "severity": severity or "medium",
        "control_refs": ["UNMAPPED"],
        "cpg": [],
        "csf": [],
        "recommended_action": "Triage; map to CPG/CSF during HITL.",
        "owner": "",
        "milestone": "",
        "status": "open",
        "mapped": False,
        "unmapped_reason": "no stub rule for this finding text",
    }


def canonical_mapped_findings(canon_dir: Path) -> list[dict[str, Any]]:
    """Map pack lab canonical findings through stubs. Skip UNMAPPED (HITL). Fixture-labeled."""
    items: list[dict[str, Any]] = []
    if not canon_dir.is_dir():
        return items
    seen: set[tuple[str, str]] = set()
    for path in sorted(canon_dir.glob("*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("kind") != "finding":
                continue
            text = " ".join(str(obj.get(k) or "") for k in ("name", "description", "ref_id"))
            related = obj.get("related_assets") or []
            asset = str(related[0]) if isinstance(related, list) and related else ""
            sev = str(obj.get("severity") or "")
            mapped = map_finding(text, asset, sev)
            if not mapped.get("mapped"):
                continue
            key = (mapped["weakness"], asset)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                {
                    "weakness": mapped["weakness"],
                    "asset": asset,
                    "severity": mapped["severity"],
                    "name": obj.get("name") or mapped["weakness"],
                    "source": "pack-lab-fixture",
                    "ref_id": obj.get("ref_id"),
                }
            )
    return items


def export_poam(
    findings: list[dict[str, Any]],
    dest_csv: Path,
    dest_json: Path,
    label: str = "fixture",
) -> list[dict[str, Any]]:
    rows = []
    default_source = "orchestrator-live-byo" if label == "live-byo" else "orchestrator-fixture"
    for item in findings:
        text = str(item.get("weakness") or item.get("name") or item.get("title") or "")
        asset = str(item.get("asset") or item.get("host") or "")
        sev = str(item.get("severity") or "")
        row = map_finding(text, asset, sev)
        row["source"] = str(item.get("source") or default_source)
        if item.get("ref_id"):
            row["ref_id"] = item.get("ref_id")
        rows.append(row)
    uniq: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (str(row.get("weakness") or ""), str(row.get("asset") or ""))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(row)
    rows = uniq
    dest_csv.parent.mkdir(parents=True, exist_ok=True)
    with dest_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "weakness",
                "asset",
                "severity",
                "control_refs",
                "recommended_action",
                "owner",
                "milestone",
                "status",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "weakness": row["weakness"],
                    "asset": row["asset"],
                    "severity": row["severity"],
                    "control_refs": ";".join(row["control_refs"]),
                    "recommended_action": row["recommended_action"],
                    "owner": row["owner"],
                    "milestone": row["milestone"],
                    "status": row["status"],
                }
            )
    dest_json.write_text(json.dumps({"label": label, "rows": rows}, indent=2), encoding="utf-8")
    return rows


def export_simplerisk(rows: list[dict[str, Any]], dest_csv: Path) -> Path:
    """Leave-behind CSV for SimpleRisk Core extras import. No API wrap."""
    dest_csv.parent.mkdir(parents=True, exist_ok=True)
    with dest_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "Subject",
                "Status",
                "Category",
                "Scoring",
                "Mitigation",
                "Regulation",
                "Notes",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "Subject": f"{row.get('weakness', '')} on {row.get('asset', '')}"[:200],
                    "Status": "New",
                    "Category": "Vulnerability",
                    "Scoring": row.get("severity") or "",
                    "Mitigation": row.get("recommended_action") or "",
                    "Regulation": ";".join(row.get("control_refs") or []),
                    "Notes": "Evergreen leave-behind. Fixture-labeled unless a signed SCOPE ingest ran. No API wrap.",
                }
            )
    return dest_csv


def export_quote(rows: list[dict[str, Any]], dest_csv: Path) -> Path:
    """Remediation quote stub. Hours/rate/total stay blank — never invent prices."""
    dest_csv.parent.mkdir(parents=True, exist_ok=True)
    with dest_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "weakness",
                "asset",
                "severity",
                "control_refs",
                "recommended_action",
                "hours",
                "rate_usd",
                "total_usd",
                "status",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "weakness": row.get("weakness") or "",
                    "asset": row.get("asset") or "",
                    "severity": row.get("severity") or "",
                    "control_refs": ";".join(row.get("control_refs") or []),
                    "recommended_action": row.get("recommended_action") or "",
                    "hours": "",
                    "rate_usd": "",
                    "total_usd": "",
                    "status": "draft",
                }
            )
    return dest_csv
