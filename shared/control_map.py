"""Finding → CISA CPG + NIST CSF stamps and a POA&M fix line.

Wizard-safe labels only (no colons). Honest: port-open is not a CVE.
"""

from __future__ import annotations

import os
import re
from typing import Any

from shared.finding_types import TYPE_WEAKNESS_NAME, type_remediation
from shared.framework_class_map import apply_class_mapping
from shared.schema import canon_severity
from shared.poam_fields import _CVE_RE

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

# Honest CPG only from 800-53 ids that sit in that CPG's scope.
# 2_W = known-weak / unnecessary service posture. 1_E = asset/exposure inventory.
# Do not stamp either from severity. Drop CPG when no control maps.
N53_CPG = {
    "CM-7": CPG_WEAK_SERVICE,
    "SC-7": CPG_WEAK_SERVICE,
    "CM-8": CPG_EXPOSURE,
}
CVE_N53 = ["SI-2", "RA-5"]
CVE_CIS = ["cis_7_3", "cis_7_4", "cis_7_7"]
# Specific remediations where the CVE + package/title make a playbook derivable.
KNOWN_CVE_REMEDIATION: dict[str, dict[str, str]] = {
    "CVE-2024-3094": {
        "weakness_name": "xz-utils supply chain backdoor (CVE-2024-3094)",
        "control_name": "Remove the xz-utils/liblzma backdoor",
        "fix": (
            "Replace xz-utils/liblzma 5.6.0/5.6.1 (the backdoored builds) with a clean "
            "package (5.4.x or a later rebuilt release). Rotate credentials or keys that "
            "may have been exposed on hosts that ran the backdoored library. This is a "
            "supply-chain CVE, not a config-drift finding."
        ),
    },
    "CVE-2023-38545": {
        "weakness_name": "curl SOCKS heap overflow (CVE-2023-38545)",
        "control_name": "Patch curl SOCKS heap overflow",
        "fix": (
            "Upgrade curl/libcurl to 8.4.0 or later so CVE-2023-38545 (SOCKS5 heap "
            "buffer overflow) is not present."
        ),
    },
    "CVE-2023-44487": {
        "weakness_name": "HTTP/2 Rapid Reset (CVE-2023-44487)",
        "control_name": "Mitigate HTTP/2 Rapid Reset",
        "fix": (
            "Upgrade the HTTP/2 stack (nginx, Envoy, load balancer, or language runtime) "
            "to a release that limits or rejects Rapid Reset; disable HTTP/2 only if a "
            "patch is not available."
        ),
    },
    "CVE-2021-44228": {
        "weakness_name": "Log4Shell (CVE-2021-44228) is present",
        "control_name": "Patch Log4Shell-vulnerable services",
        "fix": (
            "Upgrade Log4j to a fixed release and block JNDI lookups. "
            "This is a dropped Nuclei finding, not a live scan."
        ),
    },
    "CVE-2014-0160": {
        "weakness_name": "Heartbleed (CVE-2014-0160) is present",
        "control_name": "Remediate Heartbleed-vulnerable TLS",
        "fix": (
            "Upgrade the TLS stack so Heartbleed is not offered. "
            "This is a dropped TLS export, not a live probe."
        ),
    },
}
