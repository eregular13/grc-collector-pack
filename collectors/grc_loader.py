#!/usr/bin/env python3
"""Normalize canonical JSONL into CISO Assistant + POA&M + OCSF outputs.

RiskReady JSON is LICENSE-LOCK stay-out and is not generated. Count identity
is findings + vulnerabilities == risk_scenarios; POA&M == open_risks.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
from pathlib import Path

from shared.asset_ledger import AssetLedger, attach_asset_uids
from shared.control_map import (
    LIGHTER_ENV,
    extra_labels,
    iter_poam_decisions,
    map_finding,
    poam_breakdown,
    poam_decision,
    poam_lighter_requested,
    weakness_name_for,
)
from shared.estate_pages import (
    PageContext,
    classify_estate,
    write_client_pages,
    write_csv_with_estate,
    write_estate_sidecar,
    write_export_manifest,
)
from shared.evidence import build_evidence_rows
from shared.ciso_shape import EXCLUDED_FIELDS
from shared.finding_types import dedupe_weaknesses, finding_identity, primary_asset
from shared.port_fold import fold_port_only_into_specific
from shared.hardening_dedup import dedupe_hardening
from shared.iiw import write_iiw
from shared.kev import KevSnapshotError, load_kev_catalog
from shared.poam_fedramp import kev_md_footer, write_fedramp_poam
from shared.poam_fields import POAM_EXTRA_FIELDS, SLA_NOTE, apply_ledger_detection, poam_fields, utc_run_date
from shared.poam_ledger import ledger_run_delta, run_ledger
from shared.io_util import (
    in_dir,
    iso_now,
    load_sensor_coverage,
    out_dir,
    read_jsonl,
    redact,
    stable_hash as _stable_hash,
    write_json,
    write_text,
)
from shared.schema import (
    ASSET_TYPES,
    canon_severity,
    ciso_finding_severity,
    ciso_vuln_severity,
    control_priority,
    residual_level,
    scenario_level,
    slug,
)
