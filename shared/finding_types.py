"""Stable finding-type ids, type-specific remediations, and weakness dedupe.

Root cause of mixed remediations: shared.control_map first-match substring on a
blob that included ARNs/asset names (demo-public-assets → public ACL) and the
word "secret" (DCSync "directory secrets" → rotate-secret). Types are keyed
exactly (check_id / edge / control) before any narrative fallback.

Dedupe key: normalized asset id + finding type. Merge evidence/sources; keep
provenance. Apply before risk-register and POA&M generation.
"""

from __future__ import annotations

from typing import Any

# Sources whose emitted types this catalog covers. Other collectors stay on
# the legacy nmap/easm/code/dns/host map.
TYPED_SOURCES = frozenset({"cloud-prowler", "identity-ad", "k8s-kubescape"})

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Tool labels that must survive a same-issue-same-asset merge (Falco +
# Kubescape privileged on prod-cluster, etc.). Collector `source` is often
# the same lane (k8s-kubescape) so labels/tools are the evidence.
TOOL_LABELS = frozenset(
    {
        "falco",
        "kubescape",
        "kube-bench",
        "nuclei",
        "trivy",
        "greenbone",
        "semgrep",
        "checkov",
        "sarif",
        "scuba",
        "gitleaks",
        "trufflehog",
        "nmap",
        "nessus",
        "testssl",
        "nikto",
        "sslscan",
        "rustscan",
        "naabu",
    }
)

# Normalized extra.check_id / extra.edge / extra.control / extra.id → type.
TYPE_ALIASES: dict[str, str] = {
    # Cloud — AWS (fixtures + collector CheckID). Azure/GCP equivalents only
    # when the same collector emits them; unknown ids stay generic.
    "s3_bucket_public_access": "s3_public_access",
    "s3_bucket_allusers_read": "s3_public_access",
    "s3_bucket_acl_public": "s3_public_access",
    "s3_encryption_missing": "s3_encryption",
    "s3_bucket_server_side_encryption_enabled": "s3_encryption",
    "s3_bucket_default_encryption": "s3_encryption",
    "iam_user_administrator_access": "iam_admin_access",
    "iam_root_mfa_enabled": "iam_root_mfa",
    "aws_iam_user_mfa": "iam_user_mfa",
    "ec2_securitygroup_allow_ingress_from_internet_to_any_port": "sg_ingress_open",
    "cloudtrail_multi_region_enabled": "cloudtrail_logging",
    "rds_instance_no_public_access": "rds_public",
    "ec2_ebs_default_encryption": "ebs_encryption",
    # Identity — BloodHound edges + node titles + HK ids.
    "dcsync": "ad_dcsync",
    "genericall": "ad_genericall",
    "adminto": "ad_adminto",
    "hasesession": "ad_session",
    "genericwrite": "ad_genericwrite",
    "allowedtodelegate": "ad_constrained_delegation",
    "addmember": "ad_addmember",
    "1.1": "hk_password_history",
    "18.9": "hk_lm_hash",
    # Kubernetes — Kubescape / kube-bench / Falco rule ids.
    "c_0057": "k8s_privileged",
    "5_2_1": "k8s_privileged",
    "c_0013": "k8s_anonymous_auth",
    "1_2_1": "k8s_anonymous_auth",
    "c_0034": "k8s_privilege_escalation",
    "c_0041": "k8s_hostnetwork",
}

# Type-specific remediations. Distinct types must not share identical fix text
# unless listed in SHARED_REMEDIATION_ALLOWLIST.
TYPE_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "s3_public_access": {
        "control_name": "Block public object-storage ACL and policy",
        "recommended_fix": (
            "Remove public ACLs and bucket policies (S3 Public Access Block; drop "
            "AllUsers/AuthenticatedUsers). This is an ACL/public-access finding, "
            "not a default-encryption change."
        ),
        "nist_800_53": ["AC-3", "AC-6", "SC-7"],
        "key_medium": True,
    },
    "s3_encryption": {
        "control_name": "Enable S3 default encryption (SSE-S3 or SSE-KMS)",
        "recommended_fix": (
            "Enable default bucket encryption with SSE-S3 or SSE-KMS. This is an "
            "encryption-at-rest finding, not a bucket-policy exposure."
        ),
        "nist_800_53": ["SC-28", "SC-13"],
        "key_medium": True,
    },
    "ebs_encryption": {
        "control_name": "Enable EBS volume encryption",
        "recommended_fix": (
            "Enable EBS default encryption and encrypt the volume (or a snapshot "
            "copy). This is block-storage encryption, not an object-store policy change."
        ),
        "nist_800_53": ["SC-28", "SC-13"],
        "key_medium": True,
    },
    "iam_admin_access": {
        "control_name": "Remove standing IAM AdministratorAccess",
        "recommended_fix": (
            "Detach AdministratorAccess from IAM users. Prefer a role or "
            "break-glass group. This is an IAM posture finding, not a CVE."
        ),
        "nist_800_53": ["AC-2", "AC-6"],
    },
    "iam_root_mfa": {
        "control_name": "Require MFA on the cloud root account",
        "recommended_fix": (
            "Enable MFA on the account root. Prefer a hardware key. This is a "
            "root-identity posture finding, not a CVE."
        ),
        "nist_800_53": ["IA-2", "IA-2(1)"],
    },
    "iam_user_mfa": {
        "control_name": "Require MFA on IAM users",
        "recommended_fix": (
            "Enforce MFA on the IAM user (console login or policy condition). "
            "This is a user-MFA gap, not the account-root MFA control."
        ),
        "nist_800_53": ["IA-2", "IA-2(1)"],
    },
    "sg_ingress_open": {
        "control_name": "Restrict security-group ingress from the internet",
        "recommended_fix": (
            "Remove 0.0.0.0/0 ingress. Allow only required CIDRs or prefix lists. "
            "This is a network-exposure finding, not a CVE."
        ),
        "nist_800_53": ["SC-7", "AC-3"],
    },
    "cloudtrail_logging": {
        "control_name": "Enable multi-region CloudTrail logging",
        "recommended_fix": (
            "Create a multi-region CloudTrail trail with log-file validation to a "
            "locked log bucket. This is an audit-logging finding, not encryption "
            "or public-access."
        ),
        "nist_800_53": ["AU-2", "AU-3", "AU-12"],
    },
    "rds_public": {
        "control_name": "Disable public accessibility on RDS",
        "recommended_fix": (
            "Set PubliclyAccessible=false and place the instance in private "
            "subnets. This is an RDS exposure finding, not a CVE."
        ),
        "nist_800_53": ["SC-7", "AC-3"],
    },
    "ad_dcsync": {
        "control_name": "Remove non-DC DCSync / replication rights",
        "recommended_fix": (
            "Revoke DS-Replication-Get-Changes and DS-Replication-Get-Changes-All "
            "(DCSync) from non-DC principals. This is a directory replication-rights "
            "finding, not a secret-rotation-only fix."
        ),
        "nist_800_53": ["AC-6", "AC-2", "AC-3"],
    },
    "ad_genericall": {
        "control_name": "Remove GenericAll on privileged objects",
        "recommended_fix": (
            "Remove the GenericAll ACE from the principal. This is a BloodHound "
            "file-drop finding, not a live AD call."
        ),
        "nist_800_53": ["AC-6", "AC-2"],
    },
    "ad_adminto": {
        "control_name": "Remove standing local-admin (AdminTo) rights",
        "recommended_fix": (
            "Remove the AdminTo local-admin edge; prefer just-in-time privileged "
            "access. This is a BloodHound file-drop finding, not a live AD call."
        ),
        "nist_800_53": ["AC-6", "AC-2"],
    },
    "ad_backup_operators": {
        "control_name": "Restrict Backup Operators membership",
        "recommended_fix": (
            "Remove standing Backup Operators members. This is a "
            "BloodHound/PingCastle file-drop finding, not a live AD call."
        ),
        "nist_800_53": ["AC-2", "AC-6"],
    },
    "ad_kerberoast": {
        "control_name": "Harden kerberoastable service accounts",
        "recommended_fix": (
            "Use a gMSA or rotate the SPN password; avoid user accounts with SPNs. "
            "This is a Kerberoast finding, not a secret-in-repo rotation."
        ),
        "nist_800_53": ["IA-5", "AC-2"],
    },
    "ad_asrep": {
        "control_name": "Require Kerberos preauthentication",
        "recommended_fix": (
            "Uncheck 'Do not require Kerberos preauthentication'. This is a "
            "BloodHound file-drop finding, not a live AD call."
        ),
        "nist_800_53": ["IA-2", "AC-2"],
    },
    "ad_domain_admins": {
        "control_name": "Restrict Domain Admins membership",
        "recommended_fix": (
            "Remove standing Domain Admins members. This is a dropped identity "
            "export, not a live directory call."
        ),
        "nist_800_53": ["AC-2", "AC-6"],
        "key_medium": True,
    },
    "ad_unconstrained_delegation": {
        "control_name": "Remove unconstrained Kerberos delegation",
        "recommended_fix": (
            "Disable unconstrained delegation; prefer constrained or resource-based. "
            "This is a BloodHound file-drop finding, not a live AD call."
        ),
        "nist_800_53": ["AC-6", "IA-2"],
    },
    "entra_ga_pim": {
        "control_name": "Remove standing Global Administrator assignment",
        "recommended_fix": (
            "Use PIM eligible assignments instead of standing Global Administrator. "
            "This is a dropped Scuba/Graph export finding, not a Graph API call."
        ),
        "nist_800_53": ["AC-2", "AC-6"],
    },
    "ad_smb_null_session": {
        "control_name": "Disable SMB null / anonymous sessions",
        "recommended_fix": (
            "Disable anonymous/null SMB sessions (RestrictNullSessAccess; no guest). "
            "This is a null-session finding, not only an open TCP/445 exposure."
        ),
        "nist_800_53": ["AC-14", "AC-3", "IA-2"],
    },
    "hk_password_history": {
        "control_name": "Enforce Windows password history",
        "recommended_fix": (
            "Set password history to the recommended length. This is a "
            "HardeningKitty/CIS posture finding, not a CVE."
        ),
        "nist_800_53": ["IA-5"],
    },
    "hk_lm_hash": {
        "control_name": "Disable LM hash storage",
        "recommended_fix": (
            "Disable storage of LAN Manager hashes. Prefer NTLMv2. This is a "
            "HardeningKitty/CIS posture finding, not a CVE."
        ),
        "nist_800_53": ["IA-5", "SC-13"],
    },
    "k8s_privileged": {
        "control_name": "Deny privileged Kubernetes containers",
        "recommended_fix": (
            "Do not run privileged=true; block admission of privileged pods. This "
            "is a Kubescape/kube-bench/Falco finding from a dropped export, not a "
            "live kubectl call."
        ),
        "nist_800_53": ["AC-6", "CM-7"],
    },
    "k8s_anonymous_auth": {
        "control_name": "Disable anonymous Kubernetes API access",
        "recommended_fix": (
            "Set --anonymous-auth=false on kube-apiserver. This is a dropped "
            "CIS/kube-bench finding, not a live cluster call."
        ),
        "nist_800_53": ["IA-2", "AC-3"],
    },
    "k8s_privilege_escalation": {
        "control_name": "Block Kubernetes privilege escalation",
        "recommended_fix": (
            "Set allowPrivilegeEscalation=false. This is a dropped Kubescape "
            "finding, not a live kubectl call."
        ),
        "nist_800_53": ["AC-6", "CM-7"],
    },
    "k8s_hostnetwork": {
        "control_name": "Avoid hostNetwork on Kubernetes workloads",
        "recommended_fix": (
            "Unset hostNetwork unless the workload is a documented system DaemonSet. "
            "This is a dropped Kubescape finding, not a live cluster call."
        ),
        "nist_800_53": ["SC-7", "CM-7"],
    },
    "k8s_write_binary_dir": {
        "control_name": "Stop writes under container binary directories",
        "recommended_fix": (
            "Set readOnlyRootFilesystem and drop root so the workload cannot write "
            "under binary dirs. This is a Falco file-drop signal, not a live kubectl call."
        ),
        "nist_800_53": ["SI-7", "CM-6", "AC-3"],
        "key_medium": True,
    },
}

# Failure-oriented weakness names. Check titles that read as passes
# (e.g. "Root account MFA enabled") must not appear as the weakness.
TYPE_WEAKNESS_NAME: dict[str, str] = {
    "s3_public_access": "S3 bucket allows public access",
    "s3_encryption": "S3 bucket default encryption is not enabled",
    "ebs_encryption": "EBS volume is not encrypted",
    "iam_admin_access": "IAM user has standing AdministratorAccess",
    "iam_root_mfa": "Root account has no MFA",
    "iam_user_mfa": "IAM user has no MFA",
    "sg_ingress_open": "Security group allows inbound traffic from the internet",
    "cloudtrail_logging": "CloudTrail multi-region trail is missing",
    "rds_public": "RDS instance is publicly accessible",
    "ad_dcsync": "Non-DC principal has DCSync / replication rights",
    "ad_genericall": "Principal has GenericAll on a privileged object",
    "ad_adminto": "Principal has standing local-admin (AdminTo) rights",
    "ad_backup_operators": "Backup Operators has standing members",
    "ad_kerberoast": "Service account is kerberoastable",
    "ad_asrep": "Account does not require Kerberos preauthentication",
    "ad_domain_admins": "Domain Admins has standing members",
    "ad_unconstrained_delegation": "Account has unconstrained Kerberos delegation",
    "entra_ga_pim": "Global Administrator is a standing assignment",
    "ad_smb_null_session": "SMB null / anonymous sessions are allowed",
    "hk_password_history": "Windows password history is not enforced",
    "hk_lm_hash": "LM hash storage is enabled",
    "k8s_privileged": "Privileged Kubernetes containers are admitted",
    "k8s_anonymous_auth": "Anonymous Kubernetes API access is enabled",
    "k8s_privilege_escalation": "Kubernetes privilege escalation is allowed",
    "k8s_hostnetwork": "Workload uses hostNetwork",
    "k8s_write_binary_dir": "Workload can write under container binary directories",
}

# Distinct types may share remediations only with an explicit reason.
SHARED_REMEDIATION_ALLOWLIST: dict[tuple[str, str], str] = {}

GENERIC_FLAG = "generic fallback"


def norm_type_key(raw: str) -> str:
    text = str(raw or "").strip().lower()
    for ch in ("-", " ", ".", "/"):
        text = text.replace(ch, "_")
    return text


def extra_dict(rec: dict[str, Any]) -> dict[str, Any]:
    extra = rec.get("extra")
    return extra if isinstance(extra, dict) else {}


def _alias_keys(rec: dict[str, Any]) -> list[str]:
    extra = extra_dict(rec)
    keys = [
        extra.get("check_id"),
        extra.get("edge"),
        extra.get("control"),
        extra.get("id"),
        extra.get("control_key"),
        extra.get("rule"),
    ]
    return [norm_type_key(str(k)) for k in keys if k]


def _match_blob(rec: dict[str, Any]) -> str:
    """Name/description/ids only — never ARN or asset names (avoids public-assets)."""
    extra = extra_dict(rec)
    return " ".join(
        str(x or "")
        for x in (
            rec.get("name"),
            rec.get("description"),
            rec.get("category"),
            extra.get("check_id"),
            extra.get("edge"),
            extra.get("control"),
            extra.get("id"),
            extra.get("rule"),
            extra.get("access"),
        )
    ).lower()


def _heuristic_type(rec: dict[str, Any]) -> str:
    text = _match_blob(rec)
    if "dcsync" in text or "ds-replication-get-changes" in text or (
        "replicat" in text and ("directory" in text or "get-changes" in text)
    ):
        return "ad_dcsync"
    if "kerberoast" in text or "roastable spn" in text:
        return "ad_kerberoast"
    if "as-rep" in text or "asrep" in text.replace("-", "") or "kerberos preauth" in text:
        return "ad_asrep"
    if "backup operators" in text:
        return "ad_backup_operators"
    if "unconstrained" in text and "delegat" in text:
        return "ad_unconstrained_delegation"
    if "genericall" in text.replace(" ", "").replace("_", "").replace("-", ""):
        return "ad_genericall"
    if "adminto" in text.replace(" ", "") or (
        "local admin" in text and "bloodhound" in text
    ):
        return "ad_adminto"
    if "null session" in text or extra_dict(rec).get("access") == "null-session":
        return "ad_smb_null_session"
    if "domain admins" in text:
        return "ad_domain_admins"
    if "global administrator" in text and ("pim" in text or "standing" in text or "graph" in text):
        return "entra_ga_pim"
    if "password history" in text:
        return "hk_password_history"
    if (
        "lm hash" in text
        or "lan manager hash" in text
        or "lmhash" in text.replace(" ", "").replace("_", "")
    ):
        return "hk_lm_hash"
    if "write below binary" in text or "binary directory" in text:
        return "k8s_write_binary_dir"
    if "allowprivilegeescalation" in text.replace(" ", "").replace("_", "").replace("-", "") or (
        "privilege escalation" in text and ("pod" in text or "container" in text or "k8s" in text or "kubernetes" in text)
    ):
        return "k8s_privilege_escalation"
    if "hostnetwork" in text.replace(" ", "").replace("_", "") or "host network" in text:
        return "k8s_hostnetwork"
    if "anonymous" in text and ("auth" in text or "api" in text or "kubernetes" in text):
        return "k8s_anonymous_auth"
    if "privileged" in text and ("container" in text or "pod" in text or "admission" in text):
        return "k8s_privileged"
    if ("s3" in text or "bucket" in text) and (
        "public access" in text
        or "public-access" in text
        or "allusers" in text
        or "public acl" in text
        or "public list" in text
        or "public get" in text
        or "public read" in text
    ):
        return "s3_public_access"
    if ("s3" in text or "bucket" in text) and (
        "encrypt" in text or "sse" in text or "kms" in text
    ):
        return "s3_encryption"
    if "ebs" in text and "encrypt" in text:
        return "ebs_encryption"
    if "administratoraccess" in text.replace(" ", "").replace("_", "").replace("-", ""):
        return "iam_admin_access"
    if "root" in text and "mfa" in text:
        return "iam_root_mfa"
    if ("iam" in text or "user" in text) and "mfa" in text:
        return "iam_user_mfa"
    if "cloudtrail" in text or ("multi-region" in text and "trail" in text):
        return "cloudtrail_logging"
    if "rds" in text and "public" in text:
        return "rds_public"
    if ("0.0.0.0/0" in text or "0.0.0.0 / 0" in text) and (
        "security group" in text or "security_group" in text or "securitygroup" in text
    ):
        return "sg_ingress_open"
    return ""


def finding_type(rec: dict[str, Any]) -> str:
    """Stable type id. Empty string = leave the row to the legacy narrative map."""
    keys = _alias_keys(rec)
    for key in keys:
        mapped = TYPE_ALIASES.get(key)
        if mapped:
            return mapped
    source = str(rec.get("source") or "")
    if source not in TYPED_SOURCES:
        return ""
    guessed = _heuristic_type(rec)
    if guessed:
        return guessed
    # Typed collector with an explicit check/edge/control we do not know.
    if keys:
        return "unknown"
    return ""


def generic_remediation(rec: dict[str, Any]) -> dict[str, Any]:
    ref = str(rec.get("ref_id") or rec.get("name") or "unknown")
    extra = extra_dict(rec)
    control = str(extra.get("check_id") or extra.get("control") or extra.get("id") or ref)
    return {
        "control_name": f"Review and remediate per control {control}",
        "recommended_fix": (
            f"Review and remediate per control {control}. "
            f"{GENERIC_FLAG.capitalize()} — no type-specific playbook is mapped "
            "for this finding type."
        ),
        "generic": True,
        "finding_type": "unknown",
        "nist_800_53": [],
        "cis": [],
        "key_medium": False,
        "weakness_name": "",
    }


def type_remediation(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Return type-specific stamps, or a flagged generic for unknown typed rows."""
    ftype = finding_type(rec)
    if not ftype:
        return None
    if ftype == "unknown":
        return generic_remediation(rec)
    meta = TYPE_REMEDIATIONS.get(ftype)
    if not meta:
        return generic_remediation(rec)
    return {
        "control_name": meta["control_name"],
        "recommended_fix": meta["recommended_fix"],
        "generic": False,
        "finding_type": ftype,
        "nist_800_53": list(meta.get("nist_800_53") or []),
        "cis": list(meta.get("cis") or []),
        "key_medium": bool(meta.get("key_medium")),
        "weakness_name": TYPE_WEAKNESS_NAME.get(ftype) or str(meta.get("weakness_name") or ""),
    }


def normalize_asset_id(raw: Any) -> str:
    """Stable asset id: ARN leaf, identity sAMAccount before @, lowercased."""
    text = str(raw or "").strip().lower()
    if not text:
        return ""
    if text.startswith("arn:"):
        if ":::" in text:
            text = text.split(":::", 1)[1]
        elif "/" in text:
            text = text.rsplit("/", 1)[-1]
        elif ":" in text:
            text = text.rsplit(":", 1)[-1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text.strip()


def primary_asset(rec: dict[str, Any]) -> str:
    assets = rec.get("assets") or []
    if assets:
        return normalize_asset_id(assets[0])
    extra = extra_dict(rec)
    return normalize_asset_id(extra.get("arn") or rec.get("name") or "")


def finding_identity(rec: dict[str, Any]) -> str:
    """Full rule/vuln/check id. Never a 48-char display slug.

    Collectors store the raw SARIF rule, Trivy CVE, check_id, etc. in extra.
    ``make_ref`` / ``slug(..., maxlen=48)`` is display-only and must not feed
    this key — two long IDs that share a prefix would otherwise collide.
    """
    extra = extra_dict(rec)
    for key in (
        "check_id",
        "rule",
        "cve",
        "template_id",
        "plugin_id",
        "nse_script",
        "id",
        "edge",
        "control",
    ):
        val = str(extra.get(key) or "").strip()
        if val:
            return val.lower()
    return str(rec.get("ref_id") or rec.get("name") or "").strip().lower()


def dedupe_key(rec: dict[str, Any]) -> tuple[str, str]:
    """(normalized asset, finding type or full identity). Asset is always in the key."""
    ftype = finding_type(rec)
    if not ftype or ftype == "unknown":
        ftype = finding_identity(rec) or "finding"
    return (primary_asset(rec), ftype)


def _sev_rank(rec: dict[str, Any]) -> int:
    return SEV_RANK.get(str(rec.get("severity") or "info").lower(), 0)


def tools_of(rec: dict[str, Any]) -> list[str]:
    """Scanner/tool names from labels + extra.tools. Survives a merge."""
    extra = extra_dict(rec)
    out: list[str] = []
    for raw in extra.get("tools") or []:
        token = str(raw or "").strip().lower()
        if token and token not in out:
            out.append(token)
    for lab in rec.get("labels") or []:
        token = str(lab or "").strip().lower()
        if token in TOOL_LABELS and token not in out:
            out.append(token)
    return out


def _record_tools(extra: dict[str, Any], rec: dict[str, Any]) -> None:
    tools = extra.setdefault("tools", [])
    if not isinstance(tools, list):
        extra["tools"] = tools = []
    sources = extra.setdefault("sources", [])
    if not isinstance(sources, list):
        extra["sources"] = sources = []
    for token in tools_of(rec):
        if token not in tools:
            tools.append(token)
        if token not in sources:
            sources.append(token)


def _merge_weakness(kept: dict[str, Any], other: dict[str, Any]) -> None:
    extra = kept.setdefault("extra", {})
    if not isinstance(extra, dict):
        kept["extra"] = extra = {}
    other_extra = extra_dict(other)
    sources = extra.setdefault("sources", [])
    if not isinstance(sources, list):
        extra["sources"] = sources = []
    for src in (kept.get("source"), other.get("source")):
        if src and src not in sources:
            sources.append(src)
    _record_tools(extra, kept)
    _record_tools(extra, other)
    also = extra.setdefault("also_ids", [])
    if not isinstance(also, list):
        extra["also_ids"] = also = []
    oid = str(other.get("ref_id") or "")
    if oid and oid not in also and oid != str(kept.get("ref_id") or ""):
        also.append(oid)
    also_check = extra.setdefault("also_check_ids", [])
    if not isinstance(also_check, list):
        extra["also_check_ids"] = also_check = []
    for cid in (
        other_extra.get("check_id"),
        other_extra.get("control"),
        other_extra.get("id"),
        other_extra.get("edge"),
        other_extra.get("rule"),
        extra.get("rule"),
        extra.get("id"),
        extra.get("control"),
    ):
        token = str(cid or "").strip()
        if token and token not in also_check:
            also_check.append(token)
    provenance = extra.setdefault("provenance", [])
    if not isinstance(provenance, list):
        extra["provenance"] = provenance = []
    if not provenance:
        provenance.append(
            {
                "source": kept.get("source"),
                "ref_id": kept.get("ref_id"),
                "name": kept.get("name"),
            }
        )
    provenance.append(
        {
            "source": other.get("source"),
            "ref_id": other.get("ref_id"),
            "name": other.get("name"),
        }
    )
    labels = kept.setdefault("labels", [])
    if not isinstance(labels, list):
        kept["labels"] = labels = []
    for lab in other.get("labels") or []:
        if lab and lab not in labels:
            labels.append(lab)
    assets = kept.setdefault("assets", [])
    if not isinstance(assets, list):
        kept["assets"] = assets = []
    for asset in other.get("assets") or []:
        if asset and asset not in assets:
            assets.append(asset)
    if _sev_rank(other) > _sev_rank(kept):
        kept["severity"] = other.get("severity")
    other_desc = str(other.get("description") or "").strip()
    kept_desc = str(kept.get("description") or "").strip()
    if other_desc and other_desc != kept_desc:
        extras = extra.setdefault("also_descriptions", [])
        if not isinstance(extras, list):
            extra["also_descriptions"] = extras = []
        if other_desc not in extras:
            extras.append(other_desc)


def dedupe_weaknesses(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse same-issue-same-asset findings. Non-findings pass through in order."""
    out: list[dict[str, Any]] = []
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for rec in records:
        if rec.get("kind") != "finding":
            out.append(rec)
            continue
        key = dedupe_key(rec)
        if not key[0]:
            out.append(rec)
            continue
        existing = index.get(key)
        if existing is None:
            extra = rec.setdefault("extra", {})
            if isinstance(extra, dict):
                extra.setdefault("sources", [rec.get("source")] if rec.get("source") else [])
                extra.setdefault(
                    "provenance",
                    [
                        {
                            "source": rec.get("source"),
                            "ref_id": rec.get("ref_id"),
                            "name": rec.get("name"),
                        }
                    ],
                )
                _record_tools(extra, rec)
            index[key] = rec
            out.append(rec)
            continue
        _merge_weakness(existing, rec)
    return out
