"""Finding → CISA CPG + NIST CSF stamps and a POA&M fix line.

Wizard-safe labels only (no colons). Honest: port-open is not a CVE.
"""

from __future__ import annotations

import os
import re
from typing import Any

from shared.finding_types import TYPE_WEAKNESS_NAME, finding_type, has_xss_signal, type_remediation
from shared.framework_class_map import (
    BLANKET_REGISTER_STAMPS,
    REDIS_AUTH_TEMPLATE_IDS,
    apply_class_mapping,
    csf_cpg_tag_set,
    redis_auth_template_ids,
)
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
# FULL_FILE_CONTINUES_FROM_WORKSPACE_shared/control_map.py
