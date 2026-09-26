"""Stable finding-type ids, type-specific remediations, and weakness dedupe.

Root cause of mixed remediations: shared.control_map first-match substring on a
blob that included ARNs/asset names (demo-public-assets → public ACL) and the
word "secret" (DCSync "directory secrets" → rotate-secret). Types are keyed
exactly (check_id / edge / control) before any narrative fallback.

Dedupe key: normalized asset id + finding type. Merge evidence/sources; keep
provenance. Apply before risk-register and POA&M generation.
"""

from __future__ import annotations

import re
from typing import Any

# Sources whose emitted types this catalog covers. Other collectors stay on
# the legacy nmap/easm/code/dns/host map unless an alias or heuristic hits.
TYPED_SOURCES = frozenset({"cloud-prowler", "identity-ad", "k8s-kubescape"})
HEURISTIC_SOURCES = TYPED_SOURCES | frozenset({"host-wazuh"})

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
    "hassession": "ad_session",
    "hasession": "ad_session",
    "hasesession": "ad_session",
    "genericwrite": "ad_genericwrite",
    "xccdf_sample_rule_ssh_permitroot": "ssh_root_login",
    "sample_rule_ssh_permitroot": "ssh_root_login",
    "xccdf_sample_rule_firewall": "host_fw",
    "sample_rule_firewall": "host_fw",
    "alf": "host_fw",
    "ds_0002": "docker_nonroot",
    "ds0002": "docker_nonroot",
    "check_ebs_snapshot_public": "ebs_snapshot_public",
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
    # Host / vuln — disk encryption + Redis bind/dangerous-cmd.
    "disk_encryption": "disk_encryption",
    "disk_encryption_enabled": "disk_encryption",
    "redis_bind": "redis_bind",
    "redis_dangerous_cmd": "redis_dangerous_cmd",
    "redis_info": "nse-redis-noauth",
    # testssl.sh exact ids (norm_type_key of SSLv2 → sslv2, not ssl2).
    "breach": "tls_breach",
    "lucky13": "tls_lucky13",
    "cert_expirationstatus": "tls_cert_expiration",
    "heartbleed": "tls_heartbleed",
    "tls1": "tls_1_0",
    "tls1_1": "tls_1_1",
    "sslv3": "tls_sslv3",
    "ssl3": "tls_sslv3",
    "sslv2": "tls_sslv2",
    # Nikto plugin ids that name a known web-app class (IDs drift; message wins).
    "999966": "tls_breach",
    "999995": "web_http_methods",  # Nikto 2.6.1 PUT
    "999978": "web_http_methods",  # Nikto 2.1.5 PUT
    # PingCastle Healthcheck exact RiskId values (norm_type_key).
    "a_minpwdlen": "pc_min_pwd_len",
    "a_krbtgt": "pc_krbtgt",
    "s_nopreauth": "ad_asrep",
    "s_nopreauthadmin": "ad_asrep",
    "p_delegated": "pc_delegated",
    "p_unconstraineddelegation": "ad_unconstrained_delegation",
    "a_dsheuristicsldapsecurity": "pc_dsheuristics",
    # Nuclei / nmap Redis-without-auth → existing nse-redis-noauth class.
    "exposed_redis": "nse-redis-noauth",
    "nse_redis_noauth": "nse-redis-noauth",
    "redis_noauth": "nse-redis-noauth",
    "redis_unauth": "nse-redis-noauth",
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
    "ad_session": {
        "control_name": "End privileged HasSession logons",
        "recommended_fix": (
            "Log off the privileged HasSession, stop using Domain Admin on "
            "workstations, and rotate that credential if the host is untrusted. "
            "This is a BloodHound file-drop finding, not a live AD call."
        ),
        "nist_800_53": ["AC-6", "AC-2"],
    },
    "ssh_root_login": {
        "control_name": "Disable SSH root login",
        "recommended_fix": (
            "Set PermitRootLogin no and use a named sudo account. This is a "
            "CIS-CAT/XCCDF file-drop finding, not a live SSH call."
        ),
        "nist_800_53": ["IA-2", "CM-6"],
    },
    "host_fw": {
        "control_name": "Enable a host firewall",
        "recommended_fix": (
            "Enable the host or application firewall (macOS ALF, firewalld, "
            "iptables, or ufw). This is a CIS-CAT/XCCDF or osquery file-drop "
            "finding, not a live host call."
        ),
        "nist_800_53": ["SC-7", "CM-7"],
    },
    "docker_nonroot": {
        "control_name": "Run container images as a non-root USER",
        "recommended_fix": (
            "Add a non-root USER instruction in the Dockerfile so the image "
            "does not run as root. This is a Trivy Dockerfile misconfig "
            "file-drop, not a live image build."
        ),
        "nist_800_53": ["AC-6", "CM-7"],
    },
    "ebs_snapshot_public": {
        "control_name": "Block public EBS snapshot sharing",
        "recommended_fix": (
            "Make the EBS snapshot private and drop public or CrossAccount "
            "share-all. This is a Cloud Custodian file-drop, not a live AWS call."
        ),
        "nist_800_53": ["AC-3", "SC-7"],
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
    "disk_encryption": {
        "control_name": "Enable full-disk encryption on the endpoint",
        "recommended_fix": (
            "Enable BitLocker or FileVault (or the MDM disk-encryption profile) "
            "on the endpoint and confirm the device reports encrypted. Intune and "
            "Jamf evidence on the same asset is one weakness, not two. This is an "
            "MDM file-drop finding, not a live Graph/Jamf API call."
        ),
        "nist_800_53": ["SC-28", "MP-5"],
        "key_medium": True,
    },
    "redis_bind": {
        "control_name": "Bind Redis and enable protected-mode",
        "recommended_fix": (
            "Set protected-mode yes and bind Redis to localhost or a private "
            "interface only; firewall TCP/6379. This is a bind/protected-mode "
            "finding, not a password rotation."
        ),
        "nist_800_53": ["SC-7", "CM-6", "CM-7"],
    },
    "redis_dangerous_cmd": {
        "control_name": "Rename or disable dangerous Redis commands",
        "recommended_fix": (
            "Rename or disable CONFIG, MODULE, and DEBUG for application users "
            "(rename-command in redis.conf or an ACL that denies those commands). "
            "This is a dangerous-command finding, not bind-only."
        ),
        "nist_800_53": ["AC-3", "CM-6", "CM-7"],
    },
    # Playbook text is paraphrase-only. PingCastle reports are NPOSL-3.0;
    # Nikto plugin DBs are All Rights Reserved. Never copy vendor wording.
    "tls_breach": {
        "control_name": "Disable HTTP compression on HTTPS (BREACH)",
        "recommended_fix": (
            "Disable gzip, deflate, and brotli HTTP compression on HTTPS, or mask "
            "secrets so they never appear in a compressed body. BREACH is a "
            "compression side-channel, not a cipher-suite upgrade and not a live TLS probe."
        ),
        "nist_800_53": ["SC-8", "SC-13"],
        "key_medium": True,
        "source": "testssl",
    },
    "tls_lucky13": {
        "control_name": "Disable TLS CBC ciphers (LUCKY13)",
        "recommended_fix": (
            "Disable CBC cipher suites and prefer AEAD (AES-GCM or ChaCha20-Poly1305), "
            "or enable encrypt-then-MAC / a patched TLS library. LUCKY13 is a CBC "
            "timing side-channel, not HTTP compression and not a live probe."
        ),
        "nist_800_53": ["SC-8", "SC-13"],
        "source": "testssl",
    },
    "tls_cert_expiration": {
        "control_name": "Renew the expired or expiring TLS certificate",
        "recommended_fix": (
            "Replace the expired or expiring certificate before NotAfter with a "
            "currently-valid chain. This is a certificate-lifetime finding, not a "
            "protocol or cipher change and not a live TLS probe."
        ),
        "nist_800_53": ["SC-8", "SC-17"],
        "key_medium": True,
        "source": "testssl",
    },
    "tls_heartbleed": {
        "control_name": "Remediate Heartbleed-vulnerable TLS",
        "recommended_fix": (
            "Upgrade the TLS stack so Heartbleed is not offered, then regenerate "
            "private keys and reissue certificates (CISA TA14-098A). "
            "This is a dropped TLS export, not a live probe."
        ),
        "nist_800_53": ["SI-2", "RA-5", "SC-8"],
        "key_medium": True,
        "source": "testssl",
    },
    "tls_1_0": {
        "control_name": "Disable TLS 1.0",
        "recommended_fix": (
            "Disable TLS 1.0 and require TLS 1.2 or newer. "
            "This is a dropped TLS export, not a live probe."
        ),
        "nist_800_53": ["SC-8", "SC-13"],
        "key_medium": True,
        "source": "testssl",
    },
    "tls_1_1": {
        "control_name": "Disable TLS 1.1",
        "recommended_fix": (
            "Disable TLS 1.1 and require TLS 1.2 or newer. "
            "This is a dropped TLS export, not a live probe and not a TLS 1.0-only finding."
        ),
        "nist_800_53": ["SC-8", "SC-13"],
        "source": "testssl",
    },
    "tls_sslv3": {
        "control_name": "Disable SSLv3",
        "recommended_fix": (
            "Disable SSLv3 on the listener. Prefer TLS 1.2 or newer. "
            "This is a dropped TLS export, not a live probe."
        ),
        "nist_800_53": ["SC-8", "SC-13"],
        "key_medium": True,
        "source": "testssl",
    },
    "tls_sslv2": {
        "control_name": "Disable SSLv2",
        "recommended_fix": (
            "Disable SSLv2 on the listener. Prefer TLS 1.2 or newer. "
            "This is a dropped TLS export, not a live probe."
        ),
        "nist_800_53": ["SC-8", "SC-13"],
        "key_medium": True,
        "source": "testssl",
    },
    "web_admin_path": {
        "control_name": "Remove or lock down the exposed web admin path",
        "recommended_fix": (
            "Remove or restrict /admin (and sibling login/manager consoles) so they "
            "are not reachable from untrusted networks. Require SSO or VPN. "
            "This is a Nikto file-drop finding, not a live HTTP probe and not a hostname inventory row."
        ),
        "nist_800_53": ["AC-6", "CM-7", "SC-7"],
        "key_medium": True,
        "source": "nikto",
    },
    "web_dir_listing": {
        "control_name": "Disable web-app directory listing",
        "recommended_fix": (
            "Turn off autoindex / directory listing on the web root. "
            "This is a Nikto file-drop finding, not a live HTTP probe."
        ),
        "nist_800_53": ["CM-6", "AC-3"],
        "source": "nikto",
    },
    "web_sensitive_file": {
        "control_name": "Remove exposed web-app sensitive files",
        "recommended_fix": (
            "Remove .git / .env / phpinfo / server-status from the published tree "
            "and block those paths. This is a Nikto file-drop finding, not a live HTTP probe."
        ),
        "nist_800_53": ["CM-7", "AC-3", "SI-12"],
        "key_medium": True,
        "source": "nikto",
    },
    "web_http_methods": {
        "control_name": "Disable dangerous HTTP methods",
        "recommended_fix": (
            "Disable PUT and DELETE (and any unused write methods) on the public listener. "
            "This is a Nikto file-drop finding, not a live HTTP probe."
        ),
        "nist_800_53": ["CM-7", "AC-3"],
        "source": "nikto",
    },
    "web_default_creds": {
        "control_name": "Replace web-app default credentials",
        "recommended_fix": (
            "Change vendor default passwords on the admin console and disable the "
            "default account. This is a Nikto file-drop finding, not a live login."
        ),
        "nist_800_53": ["IA-5", "AC-2"],
        "key_medium": True,
        "source": "nikto",
    },
    "web_xss": {
        "control_name": "Stop reflected web-app cross-site scripting",
        "recommended_fix": (
            "Encode untrusted response output for the HTML and JavaScript context "
            "and set a Content-Security-Policy that blocks inline script. "
            "This is a Nikto web-app finding, not a source-code static-analysis "
            "row and not a live HTTP probe."
        ),
        "nist_800_53": ["SI-10", "SC-18", "CM-6"],
        "key_medium": True,
        "source": "nikto",
    },
    "web_lfi": {
        "control_name": "Stop web-app local file inclusion",
        "recommended_fix": (
            "Reject path traversal in upload/connector parameters and keep plugin "
            "files off the public tree. This is a Nikto web-app finding, not a "
            "listener-protocol or remote-desktop exposure and not a live HTTP probe."
        ),
        "nist_800_53": ["SI-10", "AC-3", "CM-7"],
        "key_medium": True,
        "source": "nikto",
    },
    "pc_min_pwd_len": {
        "control_name": "Raise domain minimum password length",
        "recommended_fix": (
            "Set the domain minimum password length per NIST SP 800-63B-4 "
            "(15 characters password-only, or 8 with MFA) or at least 8 as "
            "PingCastle A-MinPwdLen scores. This is a PingCastle file-drop, not a "
            "live directory call."
        ),
        "nist_800_53": ["IA-5", "AC-2"],
        "key_medium": True,
        "source": "pingcastle",
    },
    "pc_krbtgt": {
        "control_name": "Rotate the krbtgt password twice",
        "recommended_fix": (
            "Reset the krbtgt password twice, at least 10 hours apart, so old "
            "KRBTGT keys die. This is PingCastle rule A-Krbtgt from a file-drop, "
            "not a live DC call."
        ),
        "nist_800_53": ["IA-5", "SC-12"],
        "key_medium": True,
        "source": "pingcastle",
    },
    "pc_delegated": {
        "control_name": "Mark privileged accounts sensitive and cannot be delegated",
        "recommended_fix": (
            "Set 'Account is sensitive and cannot be delegated' on admins, or add "
            "them to Protected Users. PingCastle P-Delegated is that flag, not "
            "the P-UnconstrainedDelegation RiskId. File-drop only."
        ),
        "nist_800_53": ["AC-6", "IA-2"],
        "key_medium": True,
        "source": "pingcastle",
    },
    "pc_dsheuristics": {
        "control_name": "Set dSHeuristics LDAP security (CVE-2021-42291)",
        "recommended_fix": (
            "Set dSHeuristics characters 28 (LDAPAddAuthZVerifications) and 29 "
            "(LDAPOwnerModify) to 1 for Enforcement after watching events "
            "3044-3056 in audit mode. The 10th character must be 1 and the 20th "
            "character must be 2 per KB5008383 (CVE-2021-42291). PingCastle "
            "A-DsHeuristicsLDAPSecurity from a file-drop, not a live directory call."
        ),
        "nist_800_53": ["AC-3", "AC-6", "SI-2"],
        "key_medium": True,
        "source": "pingcastle",
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
    "ad_session": "Privileged principal has a HasSession on a workstation",
    "ssh_root_login": "SSH PermitRootLogin is enabled",
    "host_fw": "Host firewall or macOS ALF is disabled",
    "docker_nonroot": "Container image runs as root",
    "ebs_snapshot_public": "EBS snapshot is shared publicly",
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
    "disk_encryption": "Disk encryption is disabled",
    "redis_bind": "Redis is bound beyond localhost without protected-mode",
    "redis_dangerous_cmd": "Dangerous Redis commands are enabled",
    "tls_breach": "HTTPS response compression enables BREACH",
    "tls_lucky13": "TLS CBC ciphers enable LUCKY13",
    "tls_cert_expiration": "TLS certificate is expired or expiring",
    "tls_heartbleed": "TLS stack is vulnerable to Heartbleed",
    "tls_1_0": "TLS 1.0 is offered",
    "tls_1_1": "TLS 1.1 is offered",
    "tls_sslv3": "SSLv3 is offered",
    "tls_sslv2": "SSLv2 is offered",
    "web_admin_path": "Web admin or login path is exposed",
    "web_dir_listing": "Web-app directory listing is enabled",
    "web_sensitive_file": "Sensitive web-app file is published",
    "web_http_methods": "Dangerous HTTP write methods are enabled",
    "web_default_creds": "Web-app default credentials are in use",
    "web_xss": "Web application reflects cross-site scripting",
    "web_lfi": "Web application allows local file inclusion",
    "pc_min_pwd_len": "Domain minimum password length is below policy",
    "pc_krbtgt": "krbtgt password has not been rotated",
    "pc_delegated": "Privileged account is not marked sensitive / Protected Users",
    "pc_dsheuristics": "dSHeuristics LDAP security flags are not set",
    "nse-redis-noauth": "Redis accepts unauthenticated access",
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
    # risk_id is not an alias key: unmapped PingCastle RiskIds must fall
    # through to control_map._pingcastle_playbook (#145), not "unknown".
    # Mapped RiskIds are read via _exact_scanner_id / _PINGCASTLE_EXACT.
    keys = [
        extra.get("check_id"),
        extra.get("edge"),
        extra.get("control"),
        extra.get("id"),
        extra.get("control_key"),
        extra.get("rule"),
        extra.get("template_id"),
        extra.get("template-id"),
    ]
    return [norm_type_key(str(k)) for k in keys if k]


def _risk_id_only(rec: dict[str, Any]) -> bool:
    extra = extra_dict(rec)
    if not str(extra.get("risk_id") or "").strip():
        return False
    return not any(
        extra.get(k)
        for k in ("check_id", "edge", "control", "id", "control_key", "rule")
    )


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


def _has_word(text: str, *words: str) -> bool:
    """True when any token matches on a word boundary (not a substring)."""
    blob = str(text or "")
    for word in words:
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(word)}(?![A-Za-z0-9_])", blob, re.I):
            return True
    return False


def has_xss_signal(rec: dict[str, Any]) -> bool:
    """XSS only from plugin name, family, or CWE — never the description body.

    'Multiple Vulnerabilities' plugins list XSS among other issues in the
    description; that must not type the row as web_xss or pick an XSS playbook.
    """
    extra = extra_dict(rec)
    blob = " ".join(
        str(x or "")
        for x in (
            rec.get("name"),
            extra.get("plugin_family"),
            extra.get("family"),
            extra.get("cwe"),
            extra.get("cwes"),
        )
    ).lower()
    if _has_word(blob, "xss") or "cross-site scripting" in blob or "cross site scripting" in blob:
        return True
    if re.search(r"cwe[-_ ]?79\b", blob):
        return True
    return False


def _message_text(rec: dict[str, Any]) -> str:
    """Nikto/testssl message first — name + description, not URL-only extra."""
    return f"{rec.get('name') or ''} {rec.get('description') or ''}"


def _exact_scanner_id(rec: dict[str, Any]) -> str:
    extra = extra_dict(rec)
    return norm_type_key(str(extra.get("id") or extra.get("risk_id") or "").strip())


_TESTSSL_EXACT: dict[str, str] = {
    "breach": "tls_breach",
    "lucky13": "tls_lucky13",
    "cert_expirationstatus": "tls_cert_expiration",
    "heartbleed": "tls_heartbleed",
    "tls1": "tls_1_0",
    "tls1_1": "tls_1_1",
    "sslv3": "tls_sslv3",
    "ssl3": "tls_sslv3",
    "sslv2": "tls_sslv2",
}

_PINGCASTLE_EXACT: dict[str, str] = {
    "a_minpwdlen": "pc_min_pwd_len",
    "a_krbtgt": "pc_krbtgt",
    "s_nopreauth": "ad_asrep",
    "s_nopreauthadmin": "ad_asrep",
    "p_delegated": "pc_delegated",
    "p_unconstraineddelegation": "ad_unconstrained_delegation",
    "a_dsheuristicsldapsecurity": "pc_dsheuristics",
}

_NIKTO_METHOD_IDS = frozenset({"999995", "999978"})
_NIKTO_BREACH_IDS = frozenset({"999966"})


def _nikto_http_methods(msg: str, extra_id: str) -> bool:
    if extra_id in _NIKTO_METHOD_IDS:
        return True
    write_method = _has_word(msg, "put", "delete") or "webdav" in msg
    if not write_method:
        return False
    if "allowed http methods" in msg:
        return True
    if _has_word(msg, "method", "methods") or ("allow" in msg and "header" in msg):
        return True
    return False


def _heuristic_type(rec: dict[str, Any]) -> str:
    text = _match_blob(rec)
    extra = extra_dict(rec)
    extra_id = _exact_scanner_id(rec)
    raw_id = str(extra.get("id") or extra.get("risk_id") or "").strip()
    mapped = _TESTSSL_EXACT.get(extra_id) or _PINGCASTLE_EXACT.get(extra_id)
    if mapped:
        return mapped
    msg = _message_text(rec)
    labels = {str(x).lower() for x in (rec.get("labels") or [])}
    nessus = "nessus" in labels or str(extra.get("tool") or "").lower() == "nessus"
    nikto = (not nessus) and (
        "nikto" in labels or raw_id.isdigit() or "nikto" in msg.lower()
    )
    if has_xss_signal(rec):
        return "web_xss"
    if nikto:
        # Message-text-first, then plugin ID (IDs drift between Nikto versions).
        # XSS is name / family / CWE only (has_xss_signal above) — never a
        # substring inside a Nessus 'Multiple Vulnerabilities' description.
        if _has_word(msg, "breach") or raw_id in _NIKTO_BREACH_IDS:
            return "tls_breach"
        if (
            _has_word(msg, "lfi")
            or "directory traversal" in msg.lower()
            or "directory-traversal" in msg.lower()
            or "local file inclusion" in msg.lower()
        ):
            return "web_lfi"
        if "directory listing" in msg.lower() or "directory index" in msg.lower() or "indexing found" in msg.lower():
            return "web_dir_listing"
        if any(tok in msg.lower() for tok in (".git", ".env", "phpinfo", "server-status")):
            return "web_sensitive_file"
        if "default password" in msg.lower() or "default credential" in msg.lower():
            return "web_default_creds"
        if _nikto_http_methods(msg.lower(), raw_id):
            return "web_http_methods"
        if any(tok in msg.lower() for tok in ("admin login", "/admin", "phpmyadmin", "wp-admin", "manager/html")):
            return "web_admin_path"
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
    if (
        "hassession" in text.replace(" ", "")
        or "hasession" in text.replace(" ", "")
        or "has session" in text
    ):
        return "ad_session"
    if "ebs" in text and "snapshot" in text and "public" in text:
        return "ebs_snapshot_public"
    if "null session" in text or extra_dict(rec).get("access") == "null-session":
        return "ad_smb_null_session"
    if "domain admins" in text:
        return "ad_domain_admins"
    if "not a global administrator" not in text and (
        (
            "global administrator" in text
            or "entra ga" in text
            or (" ga " in f" {text} " and "pim" in text)
        )
        and ("pim" in text or "standing" in text or "graph" in text)
    ):
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
    if "disk encryption" in text or "filevault" in text or "bitlocker" in text:
        return "disk_encryption"
    if "redis" in text and (
        "unauth" in text
        or "noauth" in text
        or "without auth" in text
        or "requirepass" in text
        or "no password" in text
    ):
        return "redis_unauth"
    if "redis" in text and ("protected-mode" in text or "bind" in text):
        return "redis_bind"
    if "redis" in text and (
        "rename-command" in text or "dangerous" in text or "config" in text and "debug" in text
    ):
        return "redis_dangerous_cmd"
    return ""


def finding_type(rec: dict[str, Any]) -> str:
    """Stable type id. Empty string = leave the row to the legacy narrative map."""
    extra = extra_dict(rec)
    risk_key = norm_type_key(str(extra.get("risk_id") or "").strip())
    if risk_key:
        mapped_risk = TYPE_ALIASES.get(risk_key) or _PINGCASTLE_EXACT.get(risk_key)
        if mapped_risk:
            return mapped_risk
    keys = _alias_keys(rec)
    for key in keys:
        mapped = TYPE_ALIASES.get(key)
        if mapped:
            return mapped
    guessed = _heuristic_type(rec)
    source = str(rec.get("source") or "")
    # Unmapped PingCastle RiskId-only rows stay untyped so #145 playbooks win.
    if _risk_id_only(rec) and source in {"identity-ad", ""}:
        return ""
    if guessed and (
        source in TYPED_SOURCES
        or guessed.startswith(("tls_", "web_", "pc_"))
        or guessed == "entra_ga_pim"
    ):
        return guessed
    if source not in TYPED_SOURCES:
        return ""
    # Typed collector with an explicit check/edge/control we do not know.
    if source in TYPED_SOURCES and keys:
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
        "source": str(meta.get("source") or ""),
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


_IDENTITY_LOCATION_KEYS = (
    "path",
    "url",
    "file",
    "line",
    "user",
    "evidence",
    "evidence_ref",
    "cmd",
    "command",
)


def _identity_location(extra: dict[str, Any]) -> str:
    """Path/url/file/line/user/cmd so the same check_id on two URLs stays two rows."""
    bits: list[str] = []
    seen: set[str] = set()
    for key in _IDENTITY_LOCATION_KEYS:
        val = str(extra.get(key) or "").strip().lower()
        if not val or val in seen:
            continue
        seen.add(val)
        bits.append(f"{key}:{val}")
    return "|".join(bits)


def finding_identity(rec: dict[str, Any]) -> str:
    """Full rule/vuln/check id. Never a 48-char display slug.

    Collectors store the raw SARIF rule, Trivy CVE, check_id, etc. in extra.
    ``make_ref`` / ``slug(..., maxlen=48)`` is display-only and must not feed
    this key — two long IDs that share a prefix would otherwise collide.
    Repeating check_ids (httpx-admin / whatweb-admin / path-exposure) keep
    the #170 path/url discriminator so root vs /login do not collapse.
    """
    extra = extra_dict(rec)
    for key in (
        "check_id",
        "rule",
        "cve",
        "template_id",
        "plugin_id",
        "nse_script",
        "edge",
        "control",
    ):
        val = str(extra.get(key) or "").strip()
        if val:
            ident = val.lower()
            if key != "cve" and not ident.startswith("cve-"):
                loc = _identity_location(extra)
                if loc:
                    ident = f"{ident}:{loc}"
            return ident
    return str(rec.get("ref_id") or rec.get("name") or "").strip().lower()


def _norm_weakness_token(raw: str) -> str:
    return " ".join(str(raw or "").strip().lower().split())


def semantic_weakness_key(rec: dict[str, Any]) -> str:
    """Stable weakness id for register merge: type, then CVE, then name.

    Not ``tool:scanner_id`` — same issue from Intune+Jamf or nmap+rustscan
    on one EGA- asset must collapse.
    """
    ftype = finding_type(rec)
    if ftype and ftype != "unknown":
        return f"type:{ftype}"
    extra = extra_dict(rec)
    cve = str(extra.get("cve") or "").strip().upper()
    if cve.startswith("CVE-"):
        return f"cve:{cve}"
    for blob in (rec.get("ref_id"), rec.get("name"), rec.get("description")):
        text = str(blob or "").upper()
        idx = text.find("CVE-")
        if idx >= 0:
            token = text[idx : idx + 20].split()[0].rstrip(",;:)")
            if token.startswith("CVE-"):
                return f"cve:{token}"
    return f"name:{_norm_weakness_token(rec.get('name') or rec.get('ref_id') or 'finding')}"


def register_asset_key(rec: dict[str, Any]) -> str:
    """EGA- asset UID when #138 stamped it; else the normalized display asset.

    Standing Global Administrator / Graph / Scuba rows for the same UPN share
    one key even when one copy also lists the tenant as a second asset.
    """
    extra = extra_dict(rec)
    ftype = finding_type(rec)
    if ftype == "entra_ga_pim":
        for raw in rec.get("assets") or []:
            text = str(raw or "")
            if "@" in text:
                return normalize_asset_id(text)
        return primary_asset(rec)
    uid = str(extra.get("asset_uid") or "").strip()
    if uid.startswith("EGA-"):
        return uid
    return primary_asset(rec)


def dedupe_key(rec: dict[str, Any]) -> tuple[str, str]:
    """(asset, port/proto or weakness class). Observation id is not a key.

    Port-only inventory rows (nmap/rustscan/…) merge on asset + port/proto.
    Named weaknesses (type, CVE, or title) keep their class so TLS 1.0 and
    a bare 443/tcp open stay two rows.
    """
    ftype = finding_type(rec)
    asset = register_asset_key(rec)
    extra = extra_dict(rec)
    loc = _identity_location(extra)
    if ftype and ftype != "unknown":
        return (asset, f"{ftype}:{loc}" if loc else ftype)
    port = str(extra.get("port") or "").strip()
    proto = str(extra.get("protocol") or extra.get("proto") or "").strip().lower()
    if port and port != "0":
        from shared.port_fold import finding_port, finding_proto, is_port_only_finding

        port = finding_port(rec) or port
        proto = finding_proto(rec) or proto
        if is_port_only_finding(rec):
            return (asset, f"port:{port}/{proto or 'tcp'}")
    base = semantic_weakness_key(rec)
    if loc:
        return (asset, f"{base}:{loc}")
    return (asset, base)


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


def dedupe_weaknesses(
    records: list[dict[str, Any]], drops: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
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
        if drops is not None:
            drops.append({"rec": rec, "survivor": existing})
        _merge_weakness(existing, rec)
    return out
