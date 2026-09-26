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
