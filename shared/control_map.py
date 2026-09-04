"""Finding → CISA CPG + NIST CSF stamps and a POA&M fix line.

Wizard-safe labels only (no colons). Honest: port-open is not a CVE.
"""

from __future__ import annotations

from typing import Any

from shared.schema import canon_severity, csf_function

# CISA CPG 2.x-style stamps already used on the CISO wire (underscore, not colon).
# 2_W = known-weak / unnecessary service posture. 1_E = asset/exposure inventory.
CPG_WEAK_SERVICE = "cpg_2_W"
CPG_EXPOSURE = "cpg_1_E"

# NIST CSF 2.0 function stamps (protect/identify/detect/respond).
CSF_STAMP = {
    "identify": "csf_ID",
    "protect": "csf_PR",
    "detect": "csf_DE",
    "respond": "csf_RS",
    "recover": "csf_RC",
}


def _blob(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    return " ".join(
        str(x or "")
        for x in (
            rec.get("name"),
            rec.get("description"),
            rec.get("category"),
            extra.get("port"),
            extra.get("service"),
        )
    ).lower()


def map_finding(rec: dict[str, Any]) -> dict[str, Any]:
    """Return stamps + a recommended fix. Does not invent CVEs or due dates."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    port = str(extra.get("port") or "")
    text = _blob(rec)
    sev = canon_severity(rec.get("severity"))
    fn = csf_function(sev)
    csf = [CSF_STAMP.get(fn, "csf_PR"), f"csf_{fn}"]
    cpg = [CPG_WEAK_SERVICE]
    key_medium = False

    if (
        "admin$" in text
        or "c$" in text
        or "ipc$" in text
        or "admin share" in text
        or "administrative share" in text
    ):
        name = "Restrict Windows admin shares"
        fix = (
            "Disable or ACL C$/ADMIN$/IPC$ so they are not reachable off the admin network. "
            "Confirm SMBv1 is disabled. This is a share-exposure finding, not a CVE."
        )
        key_medium = True
    elif port == "445" or "smb" in text or "microsoft-ds" in text:
        name = "Harden or restrict SMB file sharing"
        fix = (
            "Restrict TCP/445 (SMB) to required admin or file-share hosts. "
            "Confirm SMBv1 is disabled on the endpoint. "
            "This finding is an open-port exposure, not a dialect or CVE."
        )
        key_medium = True
    elif port == "23" or "telnet" in text:
        name = "Disable Telnet; require encrypted remote admin"
        fix = "Disable Telnet (TCP/23). Use SSH or an approved jump host. Do not leave cleartext remote admin on the network."
    elif port == "21" or "ftp exposed" in text:
        name = "Disable or lock down cleartext FTP"
        fix = "Disable FTP (TCP/21) or replace with SFTP/FTPS. Restrict any remaining listener to a management VLAN."
    elif port == "3389" or "rdp" in text:
        name = "Restrict RDP to approved paths"
        fix = "Restrict TCP/3389 (RDP) to VPN/jump hosts. Require NLA. This is an exposure finding, not a specific RDP CVE."
        key_medium = True
    elif (
        port == "443"
        or "tls" in text
        or "ssl" in text
        or "https" in text
        or "certificate" in text
    ):
        name = "Harden TLS on the exposed service"
        fix = (
            "Require TLS 1.2 or newer, disable weak ciphers, and use a valid certificate. "
            "This is a posture finding, not a specific TLS CVE."
        )
        key_medium = True
    elif "public" in text and ("s3" in text or "bucket" in text):
        name = "Block public object-storage access"
        fix = "Remove public ACL/policy on the bucket. Keep the object private unless a documented exception exists."
    elif "secret" in text or "gitleaks" in text or "trufflehog" in text:
        name = "Rotate and revoke exposed credentials"
        fix = "Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material."
    elif str(rec.get("category") or "") == "exposure":
        name = f"Reduce unnecessary network exposure ({rec.get('name') or port or 'service'})"
        fix = (
            f"Limit the exposed service on {', '.join(rec.get('assets') or []) or 'the asset'} "
            "to required networks. Confirm the listener is still needed."
        )
        key_medium = port in {"3389", "445"}
    else:
        name = f"Remediate: {rec.get('name') or rec.get('ref_id')}"
        fix = str(rec.get("description") or rec.get("name") or "Review and remediate the finding.")

    if sev in {"high", "critical"}:
        cpg = [CPG_WEAK_SERVICE, CPG_EXPOSURE]
    include = sev in {"high", "critical"} or key_medium or (sev == "medium" and key_medium)
    return {
        "control_name": name,
        "recommended_fix": fix,
        "cpg": cpg,
        "csf": csf,
        "csf_function": fn,
        "include_poam": include or sev in {"high", "critical"},
        "framework_refs": ",".join(dict.fromkeys(cpg + csf)),
    }


def extra_labels(rec: dict[str, Any] | None = None) -> list[str]:
    """Wizard-safe CPG + CSF stamps. No colons on the CISO wire."""
    stamps = [CPG_WEAK_SERVICE, CPG_EXPOSURE, "csf_PR", "nist_csf", "cisa_cpg"]
    if rec:
        mapped = map_finding(rec)
        stamps.extend(mapped["cpg"])
        stamps.extend(mapped["csf"])
    out: list[str] = []
    for stamp in stamps:
        if stamp and ":" not in stamp and stamp not in out:
            out.append(stamp)
    return out
