"""Finding → CISA CPG + NIST CSF stamps and a POA&M fix line.

Wizard-safe labels only (no colons). Honest: port-open is not a CVE.
"""

from __future__ import annotations

from typing import Any

from shared.schema import canon_severity

# CISA CPG 2.x-style stamps already used on the CISO wire (underscore, not colon).
# 2_W = known-weak / unnecessary service posture. 1_E = asset/exposure inventory.
CPG_WEAK_SERVICE = "cpg_2_W"
CPG_EXPOSURE = "cpg_1_E"

# NIST CSF 2.0 function stamps. Derived from control family/topic, never severity.
CSF_FUNCTIONS = ("govern", "identify", "protect", "detect", "respond", "recover")
CSF_STAMP = {
    "govern": "csf_GV",
    "identify": "csf_ID",
    "protect": "csf_PR",
    "detect": "csf_DE",
    "respond": "csf_RS",
    "recover": "csf_RC",
}
# Schema-valid fallback when no 800-53 / CIS / topic maps. Identify = found, not classified.
CSF_UNMAPPED_FUNCTION = "identify"
CSF_UNMAPPED_STAMP = "csf_unmapped"

# SP 800-53 Rev. 5 family → CSF 2.0 function (NIST CSF 2.0 Informative References).
N53_FAMILY_CSF = {
    "AC": "protect",
    "AT": "protect",
    "AU": "detect",
    "CA": "identify",
    "CM": "protect",
    "CP": "recover",
    "IA": "protect",
    "IR": "respond",
    "MA": "protect",
    "MP": "protect",
    "PE": "protect",
    "PL": "govern",
    "PM": "govern",
    "PS": "protect",
    "PT": "govern",
    "RA": "identify",
    "SA": "protect",
    "SC": "protect",
    "SI": "detect",
    "SR": "govern",
}

# Control-id overrides where the family default is the wrong CSF function.
N53_CONTROL_CSF = {
    "CM-8": "identify",  # system component inventory
    "SI-2": "protect",  # flaw remediation
    "SI-3": "protect",  # malicious code protection
    "SI-7": "protect",  # software / firmware integrity
    "SI-8": "protect",  # spam protection
    "SI-10": "protect",  # information input validation
    "CA-7": "detect",  # continuous monitoring
}

# CIS Controls v8 (cis_<control>_<safeguard>) → CSF 2.0 function.
CIS_CONTROL_CSF = {
    1: "identify",
    2: "identify",
    3: "protect",
    4: "protect",
    5: "protect",
    6: "protect",
    7: "protect",
    8: "detect",
    9: "protect",
    10: "protect",
    11: "recover",
    12: "protect",
    13: "detect",
    14: "protect",
    15: "govern",
    16: "protect",
    17: "respond",
    18: "identify",
}

# Topic primary when the control name is more specific than family defaults.
TOPIC_CSF = {
    "Review deception-sensor telemetry": "detect",
    "Deploy endpoint detection and response": "detect",
    "Restore endpoint coverage": "detect",
    "Enable time synchronization": "detect",
    "Lock down sensitive perimeter hostnames": "identify",
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
            extra.get("rule"),
            extra.get("cve"),
            extra.get("check_id"),
            extra.get("arn"),
            extra.get("id"),
            extra.get("name"),
            extra.get("control"),
        )
    ).lower()


# Evidence-backed misconfig rules keyed by extra.check_id (shared/nmap_nse.py).
# nist_800_53 = SP 800-53 Rev. 5 control ids; cis = CIS Controls v8 safeguards.
# CSF function is the control's topic (protect), not a severity heuristic.
MISCONFIG_RULES: dict[str, dict[str, Any]] = {
    "nse-ftp-anon": {
        "name": "Disable anonymous FTP access",
        "fix": (
            "Set anonymous_enable=NO (vsftpd) or the equivalent, remove world-readable content from the "
            "anonymous root, and move file transfer to authenticated SFTP or FTPS. Restrict TCP/21 to the "
            "hosts that need it. Rescan with nmap ftp-anon to verify FTP code 530 for anonymous."
        ),
        "nist_800_53": ["AC-3", "AC-14", "CM-7", "IA-2"],
        "cis": ["cis_4_8", "cis_3_3"],
    },
    "nse-redis-noauth": {
        "name": "Require authentication on Redis",
        "fix": (
            "Enable Redis ACL users or requirepass with a strong secret, set protected-mode yes, bind Redis "
            "to localhost or a private interface only, and firewall TCP/6379. Rename or disable CONFIG, "
            "MODULE, and DEBUG for application users. Rescan with nmap redis-info to verify INFO is refused."
        ),
        "nist_800_53": ["IA-2", "AC-3", "CM-6", "CM-7", "SC-7"],
        "cis": ["cis_4_1", "cis_4_8", "cis_5_2"],
    },
    "nse-http-dirlist": {
        "name": "Disable web server directory listing",
        "fix": (
            "Turn off auto-indexing (nginx autoindex off; Apache Options -Indexes; IIS directoryBrowse "
            "enabled=false), remove backups and other sensitive files from the web root, and serve an "
            "explicit index or 403. Rescan with nmap http-enum to verify no 'directory listing' paths."
        ),
        "nist_800_53": ["CM-7", "CM-6", "AC-3"],
        "cis": ["cis_4_1", "cis_3_3"],
    },
    "nse-tls-deprecated-protocol": {
        "name": "Disable deprecated TLS protocols",
        "fix": (
            "Disable SSLv3, TLS 1.0, and TLS 1.1 and require TLS 1.2 or TLS 1.3 (e.g. nginx ssl_protocols "
            "TLSv1.2 TLSv1.3; Windows SCHANNEL registry or IIS Crypto). Confirm client compatibility first. "
            "Rescan with nmap ssl-enum-ciphers to verify only TLSv1.2/1.3 are listed."
        ),
        "nist_800_53": ["SC-8", "SC-8(1)", "SC-13", "CM-6"],
        "cis": ["cis_3_10", "cis_4_1"],
    },
    "nse-tls-weak-cipher": {
        "name": "Remove weak TLS cipher suites",
        "fix": (
            "Remove anonymous (aNULL), NULL, EXPORT, RC4, DES/3DES, and MD5 suites and prefer ECDHE with "
            "AES-GCM or CHACHA20-POLY1305 (e.g. Mozilla 'intermediate' profile). Rescan with nmap "
            "ssl-enum-ciphers and target least strength A."
        ),
        "nist_800_53": ["SC-8", "SC-8(1)", "SC-13", "CM-6"],
        "cis": ["cis_3_10", "cis_4_1"],
    },
    "nse-tls-self-signed": {
        "name": "Replace self-signed TLS certificate with a trusted CA certificate",
        "fix": (
            "Issue a certificate from the organization's internal CA or a public CA with the full chain, "
            "matching hostnames (SAN), and a tracked expiry. Self-signed certificates train users to click "
            "through warnings and allow undetected interception. Rescan with nmap ssl-cert to verify "
            "issuer != subject."
        ),
        "nist_800_53": ["SC-17", "SC-23", "SC-8"],
        "cis": ["cis_3_10"],
    },
    "nse-tls-weak-key": {
        "name": "Reissue TLS certificate with a strong key",
        "fix": (
            "Reissue the certificate with RSA 2048-bit or larger (3072 preferred) or ECDSA P-256, and revoke "
            "the old key. Rescan with nmap ssl-cert to verify Public Key bits >= 2048."
        ),
        "nist_800_53": ["SC-12", "SC-13", "SC-17"],
        "cis": ["cis_3_10"],
    },
    "nse-smb-signing-not-required": {
        "name": "Require SMB message signing",
        "fix": (
            "Require SMB signing: Windows GPO 'Microsoft network server: Digitally sign communications "
            "(always)' = Enabled (and client), or Samba 'server signing = mandatory'. Disable SMBv1 and "
            "restrict TCP/445 to required hosts. Unsigned SMB enables NTLM relay. Rescan with nmap "
            "smb2-security-mode to verify 'enabled and required'."
        ),
        "nist_800_53": ["SC-8", "SC-8(1)", "SC-23", "CM-6"],
        "cis": ["cis_4_1", "cis_3_10"],
    },
    "nse-smb-guest": {
        "name": "Disable SMB guest access",
        "fix": (
            "Set 'map to guest = Never' and remove 'guest ok' shares (Samba) or disable the Guest account and "
            "insecure guest logons (Windows GPO). Require authenticated, least-privilege share access. "
            "Rescan with nmap smb-security-mode to verify account_used is not guest."
        ),
        "nist_800_53": ["AC-3", "AC-14", "IA-2", "AC-6"],
        "cis": ["cis_3_3", "cis_4_7"],
    },
    "nse-db-empty-password": {
        "name": "Set strong credentials on database accounts",
        "fix": (
            "Set a strong unique password or socket/auth-plugin-only login for root and every account with an "
            "empty password, remove anonymous users and the test database (mysql_secure_installation), set "
            "bind-address to localhost or a private interface, and firewall TCP/3306. Rotate any secrets the "
            "database held. Rescan with nmap mysql-empty-password to verify."
        ),
        "nist_800_53": ["IA-5", "IA-5(1)", "IA-2", "AC-2", "CM-6"],
        "cis": ["cis_4_7", "cis_5_2"],
    },
    "nse-default-credentials": {
        "name": "Remove vendor default credentials",
        "fix": (
            "Change or disable the vendor default account immediately, set a strong unique password, restrict "
            "the admin interface to the management network or VPN, and enable MFA where supported. Review "
            "logs for prior use of the default login. Rescan with nmap http-default-accounts to verify."
        ),
        "nist_800_53": ["IA-5", "IA-5(1)", "AC-2", "CM-6", "AC-17"],
        "cis": ["cis_4_7", "cis_5_2"],
    },
}

# Named controls → SP 800-53 Rev. 5 ids (family/topic drives CSF, not severity).
CONTROL_800_53: dict[str, list[str]] = {
    "Restrict Windows admin shares": ["AC-3", "AC-6", "CM-7"],
    "Harden or restrict SMB file sharing": ["CM-7", "SC-7"],
    "Disable Telnet; require encrypted remote admin": ["CM-7", "SC-8", "AC-17"],
    "Disable or lock down cleartext FTP": ["CM-7", "SC-8"],
    "Restrict RDP to approved paths": ["AC-17", "SC-7"],
    "Disable TLS 1.0": ["SC-8", "SC-8(1)", "SC-13"],
    "Harden TLS on the exposed service": ["SC-8", "SC-8(1)", "SC-13"],
    "Remediate Heartbleed-vulnerable TLS": ["SI-2", "SC-8", "RA-5"],
    "Review deception-sensor telemetry": ["SI-4", "AU-2"],
    "Publish a DMARC policy": ["SI-8", "SC-8"],
    "Tighten DMARC beyond p=none": ["SI-8", "SC-8"],
    "Restrict SPF +all": ["SI-8", "SC-8"],
    "Publish an SPF record": ["SI-8", "SC-8"],
    "Tighten SPF softfail (~all)": ["SI-8", "SC-8"],
    "Publish DKIM for the listed selector": ["SI-8", "SC-8"],
    "Block public object-storage access": ["AC-3", "AC-6", "SC-7"],
    "Remove standing IAM AdministratorAccess": ["AC-2", "AC-6"],
    "Require MFA on the cloud root account": ["IA-2", "IA-2(1)"],
    "Restrict security-group ingress from the internet": ["SC-7", "AC-17"],
    "Disable public accessibility on RDS": ["SC-7", "AC-3"],
    "Enable encryption at rest on cloud storage": ["SC-28", "SC-13"],
    "Stop SQL injection in the application": ["SI-10", "SA-11"],
    "Stop OS command injection": ["SI-10", "SA-11"],
    "Patch Log4Shell-vulnerable services": ["SI-2", "RA-5"],
    "Stop remote code execution": ["SI-2", "SI-10"],
    "Stop cross-site scripting": ["SI-10", "SA-11"],
    "Remove non-DC DCSync rights": ["AC-6", "AC-2"],
    "Remove GenericAll on privileged objects": ["AC-6", "AC-2"],
    "Require Kerberos preauthentication": ["IA-2", "AC-2"],
    "Harden kerberoastable service accounts": ["IA-5", "AC-6"],
    "Remove unconstrained Kerberos delegation": ["AC-6", "IA-2"],
    "Restrict Backup Operators membership": ["AC-6", "AC-2"],
    "Restrict Domain Admins membership": ["AC-6", "AC-2"],
    "Enable full-disk encryption": ["SC-28", "MP-5"],
    "Deploy endpoint detection and response": ["SI-4"],
    "Enroll the endpoint in MDM": ["CM-2", "CM-6"],
    "Review and expire stale guest accounts": ["AC-2"],
    "Restore endpoint coverage": ["SI-4"],
    "Rotate and revoke exposed credentials": ["IA-5", "SI-4"],
    "Require phishing-resistant MFA for privileged users": ["IA-2", "IA-2(1)"],
    "Require MFA for privileged SaaS admins": ["IA-2", "IA-2(1)"],
    "Remove standing Global Administrator assignment": ["AC-2", "AC-6", "AC-5"],
    "Enforce Windows password history": ["IA-5"],
    "Disable LM hash storage": ["IA-5", "CM-6"],
    "Enable a host firewall": ["SC-7", "CM-7"],
    "Disable SSH root login": ["IA-2", "AC-6"],
    "Disable SSH empty passwords": ["IA-5", "IA-2"],
    "Apply security updates": ["SI-2", "CM-6", "RA-5"],
    "Enable time synchronization": ["AU-8"],
    "Deny privileged Kubernetes containers": ["AC-6", "CM-7"],
    "Disable anonymous Kubernetes API access": ["AC-3", "IA-2"],
    "Block Kubernetes privilege escalation": ["AC-6"],
    "Avoid hostNetwork on Kubernetes workloads": ["SC-7", "CM-7"],
    "Restrict exposed admin interfaces": ["AC-17", "SC-7"],
    "Lock down sensitive perimeter hostnames": ["CM-8"],
}

# Backward-compatible alias used by older tests/docs.
EXPOSURE_800_53 = CONTROL_800_53

CONTROL_CIS: dict[str, list[str]] = {
    "Publish a DMARC policy": ["cis_9_5"],
    "Tighten DMARC beyond p=none": ["cis_9_5"],
    "Restrict SPF +all": ["cis_9_5"],
    "Publish an SPF record": ["cis_9_5"],
    "Tighten SPF softfail (~all)": ["cis_9_5"],
    "Publish DKIM for the listed selector": ["cis_9_5"],
    "Deploy endpoint detection and response": ["cis_13_2"],
    "Restore endpoint coverage": ["cis_13_2"],
    "Enable time synchronization": ["cis_8_4"],
    "Lock down sensitive perimeter hostnames": ["cis_1_1"],
    "Rotate and revoke exposed credentials": ["cis_3_3"],
}


def _n53_tokens(ids: list[str]) -> list[str]:
    return [f"nist80053_{cid}" for cid in ids]


def _n53_base(cid: str) -> str:
    return str(cid or "").split("(", 1)[0].strip().upper()


def _n53_family(cid: str) -> str:
    return _n53_base(cid).split("-", 1)[0]


def _cis_control_num(token: str) -> int | None:
    raw = str(token or "").strip().lower().replace("-", "_")
    if not raw.startswith("cis_"):
        return None
    parts = raw.split("_")
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def _csf_from_n53(cid: str) -> str | None:
    base = _n53_base(cid)
    if base in N53_CONTROL_CSF:
        return N53_CONTROL_CSF[base]
    return N53_FAMILY_CSF.get(_n53_family(cid))


def _csf_from_cis(token: str) -> str | None:
    num = _cis_control_num(token)
    if num is None:
        return None
    return CIS_CONTROL_CSF.get(num)


def _collect_csf_functions(n53: list[str], cis: list[str]) -> tuple[set[str], dict[str, int]]:
    counts: dict[str, int] = {fn: 0 for fn in CSF_FUNCTIONS}
    found: set[str] = set()
    for cid in n53:
        fn = _csf_from_n53(cid)
        if fn in counts:
            found.add(fn)
            counts[fn] += 1
    for token in cis:
        fn = _csf_from_cis(token)
        if fn in counts:
            found.add(fn)
            counts[fn] += 1
    return found, counts


def _primary_csf(found: set[str], counts: dict[str, int], topic: str | None) -> str:
    """One stamp for the CISO wire. Topic wins; else most votes, then CSF 2.0 order."""
    if topic in found:
        return topic
    ranked = sorted(found, key=lambda fn: (-counts.get(fn, 0), CSF_FUNCTIONS.index(fn)))
    return ranked[0]


def _lookup_control_ids(control_name: str) -> tuple[list[str], list[str]]:
    if control_name in CONTROL_800_53:
        return list(CONTROL_800_53[control_name]), list(CONTROL_CIS.get(control_name) or [])
    if control_name.startswith("Reduce unnecessary network exposure"):
        return ["CM-7", "SC-7"], []
    return [], []


def _stamp_csf(mapped: dict[str, Any]) -> dict[str, Any]:
    """Attach CSF 2.0 function stamps from 800-53 / CIS / topic. Never from severity."""
    n53 = list(mapped.get("nist_800_53") or [])
    cis = list(mapped.get("cis") or [])
    name = str(mapped.get("control_name") or "")
    found, counts = _collect_csf_functions(n53, cis)
    topic = TOPIC_CSF.get(name)
    if topic:
        found.add(topic)
        counts[topic] = counts.get(topic, 0) + 1
    if found:
        primary = _primary_csf(found, counts, topic)
        unmapped = False
    else:
        primary = CSF_UNMAPPED_FUNCTION
        found = {primary}
        unmapped = True
    stamps: list[str] = []
    for fn in CSF_FUNCTIONS:
        if fn in found:
            stamps.append(CSF_STAMP[fn])
            stamps.append(f"csf_{fn}")
    if unmapped:
        stamps.append(CSF_UNMAPPED_STAMP)
    mapped["csf"] = stamps
    mapped["csf_function"] = primary
    mapped["csf_functions"] = [fn for fn in CSF_FUNCTIONS if fn in found]
    cpg = list(mapped.get("cpg") or [])
    refs = cpg + stamps + _n53_tokens(n53) + list(cis)
    mapped["framework_refs"] = ",".join(dict.fromkeys(x for x in refs if x))
    return mapped


def map_finding(rec: dict[str, Any]) -> dict[str, Any]:
    """Return stamps + a recommended fix. Does not invent CVEs or due dates."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    check = str(extra.get("check_id") or "")
    rule = MISCONFIG_RULES.get(check)
    if rule:
        sev = canon_severity(rec.get("severity"))
        cpg = [CPG_WEAK_SERVICE, CPG_EXPOSURE] if sev in {"high", "critical"} else [CPG_WEAK_SERVICE]
        return _stamp_csf(
            {
                "control_name": rule["name"],
                "recommended_fix": rule["fix"],
                "cpg": cpg,
                "include_poam": True,
                "nist_800_53": list(rule["nist_800_53"]),
                "cis": list(rule["cis"]),
            }
        )
    mapped = _map_finding_legacy(rec)
    n53, cis = _lookup_control_ids(mapped["control_name"])
    mapped["nist_800_53"] = n53
    mapped["cis"] = cis
    return _stamp_csf(mapped)


def _map_finding_legacy(rec: dict[str, Any]) -> dict[str, Any]:
    """Return stamps + a recommended fix. Does not invent CVEs or due dates."""
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    port = str(extra.get("port") or "")
    text = _blob(rec)
    sev = canon_severity(rec.get("severity"))
    cpg = [CPG_WEAK_SERVICE]
    key_medium = False
    source = str(rec.get("source") or "").lower()
    category = str(rec.get("category") or "").lower()
    if (
        source in {"honeypot", "honeypot-sensor"}
        or category in {"honeypot", "deception-sensor"}
        or extra.get("honesty") == "deception-sensor"
        or "deception-sensor" in text
    ):
        return {
            "control_name": "Review deception-sensor telemetry",
            "recommended_fix": (
                "Treat this as deception-sensor evidence / an agent-behavior signal. "
                "A honeypot stage hit is not a full control failure and does not mean "
                "the network is compromised. Review the trap session; do not open a "
                "compromise incident from the stage hit alone."
            ),
            "cpg": [CPG_EXPOSURE],
            "include_poam": False,
        }

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
            "Restrict TCP/445 (SMB) to the admin network. "
            "Confirm SMBv1 is disabled. This is a share-exposure finding, not a dialect or CVE."
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
    elif "dmarc missing" in text or "dmarc_missing" in text.replace(" ", "").replace("-", "_"):
        name = "Publish a DMARC policy"
        fix = (
            "Publish a _dmarc TXT record (start at p=none, move to quarantine/reject). "
            "This is a Seen DNS control-gap candidate, not mailbox compromise and not a breach."
        )
        key_medium = True
    elif "dmarc p=none" in text or "dmarc_monitor_only" in text.replace(" ", "").replace("-", "_"):
        name = "Tighten DMARC beyond p=none"
        fix = (
            "Move DMARC from p=none to quarantine or reject after reviewing aggregate reports. "
            "A TXT record is Seen, not Shown mailbox protection."
        )
    elif "spf +all" in text or "spf_pass_all" in text.replace(" ", "").replace("-", "_"):
        name = "Restrict SPF +all"
        fix = (
            "Replace SPF +all with -all (or a scoped include). "
            "This is a Seen DNS control-gap candidate, not a breach."
        )
        key_medium = True
    elif "spf missing" in text or "spf_missing" in text.replace(" ", "").replace("-", "_"):
        name = "Publish an SPF record"
        fix = (
            "Publish a v=spf1 TXT that names approved senders and ends in -all. "
            "This is a Seen DNS control-gap candidate, not a breach."
        )
        key_medium = True
    elif "spf softfail" in text or "spf_softfail_only" in text.replace(" ", "").replace("-", "_"):
        name = "Tighten SPF softfail (~all)"
        fix = (
            "Move SPF from ~all to -all once senders are inventoried. "
            "Softfail-only is a hygiene gap, not a breach."
        )
    elif "dkim" in text and ("missing" in text or "selector" in text):
        name = "Publish DKIM for the listed selector"
        fix = (
            "Publish v=DKIM1 at <selector>._domainkey for in-SCOPE domains. "
            "This is a Seen DNS control-gap candidate, not a breach."
        )
        key_medium = True
    elif "heartbleed" in text:
        name = "Remediate Heartbleed-vulnerable TLS"
        fix = (
            "Upgrade the TLS stack so Heartbleed is not offered. "
            "This is a dropped TLS export, not a live probe."
        )
    elif "tls 1.0" in text or "tlsv1.0" in text or "tls1 offered" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Disable TLS 1.0"
        fix = (
            "Disable TLS 1.0 and require TLS 1.2 or newer. "
            "This is a dropped TLS export, not a live probe."
        )
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
    elif (
        (
            "public access" in text
            or "public-access" in text
            or "allusers" in text
            or "public acl" in text
            or "publicly" in text
            or "public list" in text
            or "public get" in text
            or "public read" in text
            or "allows public" in text
        )
        and ("s3" in text or "bucket" in text)
    ):
        name = "Block public object-storage access"
        fix = "Remove public ACL/policy on the bucket. Keep the object private unless a documented exception exists."
    elif "administratoraccess" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Remove standing IAM AdministratorAccess"
        fix = (
            "Detach AdministratorAccess from users. Prefer a role or break-glass group. "
            "This is an IAM posture finding, not a CVE."
        )
    elif "root" in text and "mfa" in text:
        name = "Require MFA on the cloud root account"
        fix = (
            "Enable MFA on the root account. Prefer a hardware key. "
            "This is an identity posture finding, not a CVE."
        )
    elif ("0.0.0.0/0" in text or "0.0.0.0 / 0" in text) and any(
        tok in text
        for tok in ("security group", "security_group", "securitygroup", "ingress", "sg-")
    ):
        name = "Restrict security-group ingress from the internet"
        fix = (
            "Remove 0.0.0.0/0 ingress. Allow only required CIDRs or prefix lists. "
            "This is a network-exposure finding, not a CVE."
        )
    elif "rds" in text and ("public" in text or "publiclyaccessible" in text.replace(" ", "").replace("_", "").replace("-", "")):
        name = "Disable public accessibility on RDS"
        fix = (
            "Set PubliclyAccessible=false and place the instance in private subnets. "
            "This is an exposure finding, not a CVE."
        )
    elif (
        "s3" in text or "bucket" in text or "ebs" in text
    ) and (
        "unencrypted" in text
        or "not encrypted" in text
        or "encryption not" in text
        or "without default encryption" in text
        or "default_encryption" in text
        or "defaultencryption" in text.replace(" ", "").replace("_", "").replace("-", "")
    ):
        name = "Enable encryption at rest on cloud storage"
        fix = (
            "Enable default encryption (SSE-S3/SSE-KMS or EBS encryption). "
            "This is a posture finding, not a CVE."
        )
    elif "sql-injection" in text or "sqli" in text or "sql injection" in text:
        name = "Stop SQL injection in the application"
        fix = (
            "Parameterize queries. Do not concatenate untrusted input into SQL. "
            "This is a SAST/SARIF finding, not a CVE."
        )
    elif "command-injection" in text or "os command" in text or "shell injection" in text:
        name = "Stop OS command injection"
        fix = (
            "Do not pass untrusted input to a shell. Use argv arrays or a safe API. "
            "This is a SAST/SARIF finding, not a CVE."
        )
    elif "log4j" in text or "log4shell" in text or "jndi" in text:
        name = "Patch Log4Shell-vulnerable services"
        fix = (
            "Upgrade Log4j to a fixed release and block JNDI lookups. "
            "This is a dropped Nuclei finding, not a live scan."
        )
    elif "remote code execution" in text or text.endswith(" rce") or " rce " in f" {text} ":
        name = "Stop remote code execution"
        fix = (
            "Patch or isolate the service that Nuclei flagged as RCE. "
            "This is a dropped Nuclei finding, not a live scan."
        )
    elif "xss" in text or "cross-site scripting" in text:
        name = "Stop cross-site scripting"
        fix = (
            "Encode untrusted output for the HTML context. Avoid raw innerHTML. "
            "This is a SAST/SARIF finding, not a CVE."
        )
    elif "dcsync" in text:
        name = "Remove non-DC DCSync rights"
        fix = (
            "Revoke Replicating Directory Changes / All from non-DC principals. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "genericall" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Remove GenericAll on privileged objects"
        fix = (
            "Remove GenericAll ACE from the principal. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "as-rep" in text or "asrep" in text.replace("-", "").replace(" ", "") or "does not require kerberos preauth" in text:
        name = "Require Kerberos preauthentication"
        fix = (
            "Uncheck 'Do not require Kerberos preauthentication'. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "roastable" in text or "kerberoast" in text:
        name = "Harden kerberoastable service accounts"
        fix = (
            "Use a gMSA or rotate the SPN password; avoid user accounts with SPNs. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "unconstrained delegation" in text:
        name = "Remove unconstrained Kerberos delegation"
        fix = (
            "Disable unconstrained delegation; prefer constrained or resource-based. "
            "This is a BloodHound file-drop finding, not a live AD call."
        )
    elif "backup operators" in text:
        name = "Restrict Backup Operators membership"
        fix = (
            "Remove standing Backup Operators members. "
            "This is a BloodHound/PingCastle file-drop finding, not a live AD call."
        )
    elif "domain admins" in text:
        name = "Restrict Domain Admins membership"
        fix = (
            "Remove standing Domain Admins members. "
            "This is a dropped identity export, not a live directory call."
        )
    elif (
        "disk encryption" in text
        or "filevault" in text
        or "bitlocker" in text
        or "encryption compliance" in text
    ):
        name = "Enable full-disk encryption"
        fix = (
            "Enable FileVault, BitLocker, or LUKS on the endpoint. "
            "This is a Fleet/Intune/Jamf file-drop finding, not a live agent query."
        )
    elif "missing edr" in text or ("edr" in text and "missing" in text):
        name = "Deploy endpoint detection and response"
        fix = (
            "Install the approved EDR/antivirus agent and confirm it reports healthy. "
            "This is an MDM file-drop assessment finding, not a live agent query."
        )
    elif "mdm" in text and (
        "enroll" in text or "unenroll" in text or "enrollment off" in text or "not enrolled" in text
    ):
        name = "Enroll the endpoint in MDM"
        fix = (
            "Enroll the host in the approved MDM. "
            "This is a Fleet/Intune/Jamf file-drop finding, not a live agent query."
        )
    elif "stale guest" in text or ("guest" in text and "stale" in text):
        name = "Review and expire stale guest accounts"
        fix = (
            "Disable or remove guest accounts with stale last-sign-in. "
            "This is an IdP file-drop assessment finding, not a Graph/Okta API call."
        )
    elif "coverage gap" in text or "agent disconnected" in text:
        name = "Restore endpoint coverage"
        fix = (
            "Reconnect the agent or enroll the host in Fleet/Wazuh. "
            "This is a coverage finding from a dropped export, not a live query."
        )
    elif "secret" in text or "gitleaks" in text or "trufflehog" in text:
        name = "Rotate and revoke exposed credentials"
        fix = "Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material."
    elif "phishing-resistant" in text and "mfa" in text:
        name = "Require phishing-resistant MFA for privileged users"
        fix = (
            "Require FIDO2 or another phishing-resistant method for privileged Entra roles. "
            "This is a Maester posture finding from a dropped export, not a Graph API call."
        )
    elif (
        ("okta" in text and "mfa" in text)
        or "privileged users require mfa" in text
        or "admin mfa" in text
        or "mfa enrollment" in text
        or "mfa not enforced" in text
        or "mfa not registered" in text
        or "mfa gap" in text
        or "privileged mfa" in text
    ):
        name = "Require MFA for privileged SaaS admins"
        fix = (
            "Enforce MFA on privileged Okta/Entra/Google roles from the dropped ScubaGear or Okta export. "
            "This is not a Graph or Okta API call."
        )
    elif "global administrator" in text and (
        "permanently" in text
        or "pim" in text
        or "standing" in text
        or "via graph" in text
    ):
        name = "Remove standing Global Administrator assignment"
        fix = (
            "Use PIM eligible assignments instead of standing Global Administrator. "
            "This is a dropped Scuba/Graph export finding, not a Graph API call."
        )
    elif "password history" in text:
        name = "Enforce Windows password history"
        fix = (
            "Set password history to the recommended length. "
            "This is a HardeningKitty/CIS posture finding, not a CVE."
        )
    elif "lm hash" in text or "lmhash" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Disable LM hash storage"
        fix = (
            "Disable storage of LAN Manager hashes. Prefer NTLMv2. "
            "This is a HardeningKitty/CIS posture finding, not a CVE."
        )
    elif "firewall" in text and (
        "no firewall" in text or "not installed" in text or "inactive" in text
    ):
        name = "Enable a host firewall"
        fix = (
            "Install and enable a host firewall. This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif "permitrootlogin" in text.replace(" ", "").replace("_", "").replace("-", "") or (
        "ssh" in text and "root login" in text
    ):
        name = "Disable SSH root login"
        fix = (
            "Set PermitRootLogin no and use a named sudo account. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif extra.get("control_key") == "ssh_empty_passwords" or (
        "empty password" in text and ("ssh" in text or "permitemptypasswords" in text.replace(" ", ""))
    ) or "permitemptypasswords" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Disable SSH empty passwords"
        fix = (
            "Set PermitEmptyPasswords no. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif extra.get("control_key") == "patching" or "security patch" in text or (
        "package update" in text
    ):
        name = "Apply security updates"
        fix = (
            "Install outstanding security patches. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif extra.get("control_key") == "time_sync" or "chrony" in text or (
        "ntp" in text and ("enable" in text or "time" in text)
    ):
        name = "Enable time synchronization"
        fix = (
            "Run chrony or ntpd so audit timestamps stay trustworthy. "
            "This is a Lynis/OpenSCAP posture finding, not a CVE."
        )
    elif extra.get("control_key") == "host_firewall":
        name = "Enable a host firewall"
        fix = (
            "Install and enable a host firewall. This is a Lynis/OpenSCAP "
            "posture finding, not a CVE."
        )
    elif "privileged" in text and (
        "container" in text or "pod" in text or "admission" in text
    ):
        name = "Deny privileged Kubernetes containers"
        fix = (
            "Do not run privileged=true. This is a Kubescape/kube-bench finding "
            "from a dropped export, not a live kubectl call."
        )
    elif "anonymous" in text and (
        "auth" in text or "api" in text or "kubernetes" in text
    ):
        name = "Disable anonymous Kubernetes API access"
        fix = (
            "Set --anonymous-auth=false. This is a dropped CIS/kube-bench finding, "
            "not a live cluster call."
        )
    elif "privilege escalation" in text or "allowprivilegeescalation" in text.replace(" ", "").replace("_", "").replace("-", ""):
        name = "Block Kubernetes privilege escalation"
        fix = (
            "Set allowPrivilegeEscalation=false. This is a dropped Kubescape finding, "
            "not a live kubectl call."
        )
    elif "hostnetwork" in text.replace(" ", "").replace("_", "").replace("-", "") or "host network" in text:
        name = "Avoid hostNetwork on Kubernetes workloads"
        fix = (
            "Unset hostNetwork unless the workload is a documented system DaemonSet. "
            "This is a dropped Kubescape finding, not a live cluster call."
        )
    elif (
        "admin interface" in text
        or "admin login" in text
        or "admin panel" in text
        or "admin console" in text
    ):
        name = "Restrict exposed admin interfaces"
        fix = (
            "Move the admin UI off the public perimeter or put it behind SSO/VPN. "
            "This is a dropped httpx/EASM finding, not a live HTTP probe."
        )
    elif "sensitive external hostname" in text or "public perimeter" in text:
        name = "Lock down sensitive perimeter hostnames"
        fix = (
            "Do not publish vpn/admin/dev hostnames on the open internet. "
            "This is a dropped EASM finding, not a live DNS/HTTP probe."
        )
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
        "include_poam": include or sev in {"high", "critical"},
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
