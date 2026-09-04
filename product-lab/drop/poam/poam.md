# POA&M (operator draft)

Pentera (or any scanner) finds it. Evergreen maps it.
Owner and due are blank — a human fills them. No invented dates.

| Weakness | Asset | Severity | Framework | Recommended fix | Status |
|---|---|---|---|---|---|
| Cloud Custodian s3-encryption-missing | demo-unencrypted-tmp | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | S3 bucket without default encryption | open |
| S3 bucket server-side encryption | arn:aws:s3:::demo-public-assets | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Remove public ACL/policy on the bucket. Keep the object private unless a documented exception exists. | open |
| S3 bucket prohibits public access | demo-public-assets | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Remove public ACL/policy on the bucket. Keep the object private unless a documented exception exists. | open |
| IAM user does not have AdministratorAccess | iam-admin-breakglass | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | User has AdministratorAccess attached directly. | open |
| Root account MFA enabled | root | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Root user has no MFA device. | open |
| Default security group restricts all traffic | sg-default | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Default SG allows 0.0.0.0/0 on all ports. | open |
| CloudTrail multi-region trail exists | acct-123456789012 | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | No multi-region CloudTrail trail. | open |
| RDS instance not publicly accessible | rds-app-prod | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | RDS instance PubliclyAccessible=true. | open |
| ScoutSuite Bucket readable by AllUsers | demo-scout-public | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Bucket readable by AllUsers | open |
| IAM users should have MFA | iam-user-nomega | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | User nomega has no MFA device | open |
| Sensitive external hostname vpn.example.com | vpn.example.com | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Limit the exposed service on vpn.example.com to required networks. Confirm the listener is still needed. | open |
| Sensitive external hostname admin.example.com | admin.example.com | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Limit the exposed service on admin.example.com to required networks. Confirm the listener is still needed. | open |
| Sensitive external hostname dev-api.example.com | dev-api.example.com | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Limit the exposed service on dev-api.example.com to required networks. Confirm the listener is still needed. | open |
| Wazuh agent disconnected: db-01 | db-01 | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Endpoint db-01 is disconnected; coverage gap. | open |
| sshd: brute force trying to get access | web-01 | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | sshd: brute force trying to get access | open |
| Wazuh agent disconnected: fleet-laptop-07 | fleet-laptop-07 | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Endpoint fleet-laptop-07 is disconnected; coverage gap. | open |
| Wazuh agent disconnected: jump-unmanaged | jump-unmanaged | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Endpoint jump-unmanaged is never_connected; coverage gap. | open |
| BloodHound GenericAll | HELPDESK@CORP.LOCAL|DOMAIN ADMINS@CORP.LOCAL | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Full control over the object. HELPDESK@CORP.LOCAL -> DOMAIN ADMINS@CORP.LOCAL | open |
| BloodHound DCSync | SVC-SQL@CORP.LOCAL|CORP.LOCAL | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | open |
| BloodHound AdminTo | HELPDESK@CORP.LOCAL|DC01.CORP.LOCAL | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Principal has local admin on the target. HELPDESK@CORP.LOCAL -> DC01.CORP.LOCAL | open |
| Backup Operators privileged group | BACKUP OPERATORS@CORP.LOCAL | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Members can dump SAM / seize privileged files. | open |
| Roastable SPN | SVC-SQL@CORP.LOCAL | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | SVC-SQL@CORP.LOCAL has an SPN and is kerberoastable. | open |
| Entra GA without PIM | ga@contoso.onmicrosoft.com | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | ga@contoso.onmicrosoft.com is Global Administrator without PIM eligibility. | open |
| Unconstrained delegation | DC01.CORP.LOCAL | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | DC01.CORP.LOCAL has unconstrained Kerberos delegation. | open |
| HardeningKitty Enforce password history | win-dc01 | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Enforce password history result=failed recommended=24 actual=[REDACTED] | open |
| HardeningKitty Disable LM hash storage | win-dc01 | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Disable LM hash storage result=failed recommended=Enabled actual=[REDACTED] | open |
| Roastable SPN | SVC-KRBTGT-ROAST | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | SVC-KRBTGT-ROAST has an SPN and is kerberoastable. | open |
| AS-REP roastable account | SVC-KRBTGT-ROAST | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | SVC-KRBTGT-ROAST does not require Kerberos preauth. | open |
| FTP exposed | legacy-ftp.corp.local | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Disable FTP (TCP/21) or replace with SFTP/FTPS. Restrict any remaining listener to a management VLAN. | open |
| SMB 445 exposed | filesrv.corp.local | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Restrict TCP/445 (SMB) to required admin or file-share hosts. Confirm SMBv1 is disabled on the endpoint. This finding is an open-port exposure, not a dialect or CVE. | open |
| SMB 445 exposed | dc.corp.local | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Restrict TCP/445 (SMB) to required admin or file-share hosts. Confirm SMBv1 is disabled on the endpoint. This finding is an open-port exposure, not a dialect or CVE. | open |
| RDP exposed | dc.corp.local | medium | cpg_2_W,csf_PR,csf_protect | Restrict TCP/3389 (RDP) to VPN/jump hosts. Require NLA. This is an exposure finding, not a specific RDP CVE. | open |
| Telnet exposed | telnet-legacy.corp.local | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Disable Telnet (TCP/23). Use SSH or an approved jump host. Do not leave cleartext remote admin on the network. | open |
| Launch Privileged Container | payments-worker|prod-cluster | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Privileged container started | open |
| Anonymous authentication is not enabled | cluster | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Anonymous authentication is not enabled | open |
| Minimize the admission of privileged containers | cluster | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Minimize the admission of privileged containers | open |
| Privileged container | prod-cluster | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Pod payments-worker runs privileged=true | open |
| Anonymous Kubernetes API access | prod-cluster | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | anonymous-auth=true on kube-apiserver | open |
| Allow privilege escalation | prod-cluster | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | allowPrivilegeEscalation not set false | open |
| HostNetwork access | prod-cluster | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | DaemonSet uses hostNetwork | open |
| Entra Global Administrator via Graph | ga@contoso.onmicrosoft.com|contoso.onmicrosoft.com | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | ga@contoso.onmicrosoft.com holds Global Administrator (Microsoft Graph export) | open |
| Maester MT.1035 | contoso.onmicrosoft.com | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Privileged users should have phishing-resistant MFA | open |
| Okta admin MFA gap | example.okta.com | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Okta admin MFA enrollment disabled | open |
| Legacy authentication protocols disabled | contoso.onmicrosoft.com | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | M365 legacy auth (IMAP/SMTP basic) still enabled | open |
| Privileged roles use PIM | contoso.onmicrosoft.com | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Global Administrator assigned permanently | open |
| Generic API Key | services/payments/config.py | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | open |
| Generic Secret | deploy/.env.sample | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | open |
| Hardcoded credential assigned to variable | services/payments/config.py | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Hardcoded credential assigned to variable | open |
| Possible SQL injection via string format | services/payments/query.py | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Possible SQL injection via string format | open |
| semver regular expression DoS | package-lock.json | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | ReDoS in npm semver. | open |
| TruffleHog AWS | infra/terraform.tfvars | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | open |
| TruffleHog Github | scripts/deploy.sh | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Rotate the secret, revoke the old value, and remove it from the repo. The pack redacts secret material. | open |
| OpenSSL Heartbleed | 10.0.0.30 | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Require TLS 1.2 or newer, disable weak ciphers, and use a valid certificate. This is a posture finding, not a specific TLS CVE. | open |
| Apache Log4j RCE | https://app.corp.local | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Log4Shell JNDI lookup | open |
| HTTP/2 Rapid Reset | https://dev-api.example.com | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | HTTP/2 rapid reset DoS | open |
| heartbleed | dev-api.example.com | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Require TLS 1.2 or newer, disable weak ciphers, and use a valid certificate. This is a posture finding, not a specific TLS CVE. | open |
| xz-utils supply chain backdoor | app-server:latest | critical | cpg_2_W,cpg_1_E,csf_RS,csf_respond | Malicious code in xz-utils liblzma. | open |
| curl SOCKS heap overflow | app-server:latest | high | cpg_2_W,cpg_1_E,csf_PR,csf_protect | Heap buffer overflow in curl SOCKS handshake. | open |
