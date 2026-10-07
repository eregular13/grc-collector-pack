"""Data-driven EOL / ancient-version severity bumps for nmap -sV product+version.

Parse-only. No network lookups, no CVE feed. Unknown or unparseable versions
leave the port-table severity unchanged. Grain/check_id stays
``nmap-port-{port}/{proto}`` so POA&M IDs do not remint on title edits.
"""

from __future__ import annotations

import re
from typing import Any

# Lowest → highest. bump steps climb this ladder (capped at critical).
_SEV_ORDER = ("info", "low", "medium", "high", "critical")

# Leading numeric version components: "6.0p1 Debian 4+deb7u7" → (6, 0)
_VER_HEAD = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")

# Rules are evaluated in order; first match wins.
# product_contains: case-insensitive substrings matched against
#   " ".join([product, version, extrainfo, script_blob, service_name])
# version_lt: exclusive upper bound on parsed (major, minor[, patch])
# bump: how many severity steps to raise (typically 1)
EOL_RULES: list[dict[str, Any]] = [
    {
        "id": "openssh-lt-7.0",
        "product_contains": ("openssh",),
        "version_lt": (7, 0),
        "bump": 1,
        "note": "OpenSSH < 7.0 is end-of-life / ancient",
    },
    {
        "id": "apache-httpd-lt-2.4",
        "product_contains": ("apache httpd", "apache"),
        "version_lt": (2, 4),
        "bump": 1,
        "note": "Apache HTTP Server 2.2.x branch is EOL",
    },
    {
        "id": "drupal-lt-8.0",
        "product_contains": ("drupal",),
        "version_lt": (8, 0),
        "bump": 1,
        "note": "Drupal 7 is EOL",
    },
    {
        "id": "nginx-lt-1.18",
        "product_contains": ("nginx",),
        "version_lt": (1, 18),
        "bump": 1,
        "note": "nginx < 1.18 is past common support windows",
    },
    {
        "id": "openssl-lt-1.1.1",
        "product_contains": ("openssl",),
        "version_lt": (1, 1, 1),
        "bump": 1,
        "note": "OpenSSL < 1.1.1 is EOL",
    },
    {
        "id": "php-lt-8.0",
        "product_contains": ("php",),
        "version_lt": (8, 0),
        "bump": 1,
        "note": "PHP < 8.0 is EOL",
    },
]


def parse_version_tuple(raw: str) -> tuple[int, ...] | None:
    """Extract leading numeric version components, or None if absent."""
    text = (raw or "").strip()
    if not text:
        return None
    # Prefer a version after a product name: "OpenSSH 6.0p1" or bare "6.0p1"
    m = _VER_HEAD.search(text)
    if not m:
        return None
    parts = [int(g) for g in m.groups() if g is not None]
    return tuple(parts) if parts else None


def _norm_blob(*parts: str) -> str:
    return " ".join(p for p in parts if p).strip().lower()


def _version_lt(got: tuple[int, ...], bound: tuple[int, ...]) -> bool:
    """True if got < bound (pad shorter with zeros)."""
    n = max(len(got), len(bound))
    g = got + (0,) * (n - len(got))
    b = bound + (0,) * (n - len(bound))
    return g < b


def _version_near_needle(blob: str, needle: str, fallback_version: str) -> tuple[int, ...] | None:
    """Parse version adjacent to product needle when possible (e.g. 'Drupal 7')."""
    n = (needle or "").lower()
    if not n:
        return parse_version_tuple(fallback_version)
    # "openssh 6.0p1", "drupal 7", "apache httpd 2.2.22"
    m = re.search(re.escape(n) + r"\s*[\/]?\s*(\d+(?:\.\d+){0,3}[a-z0-9]*)", blob, flags=re.I)
    if m:
        return parse_version_tuple(m.group(1))
    # Fallback: nmap version= attribute when the needle is the service product
    # (OpenSSH/Apache) — not for secondary script hints that lack a local version.
    fb = parse_version_tuple(fallback_version)
    if fb is None:
        return None
    # Only accept fallback when needle looks like the primary product token
    # at the start of the blob (product field leads the joined blob).
    head = blob[:80]
    if n in head:
        return fb
    return None


def match_eol_rule(
    *,
    product: str = "",
    version: str = "",
    extrainfo: str = "",
    service: str = "",
    script_blob: str = "",
) -> dict[str, Any] | None:
    """Return the first matching EOL rule, or None.

    First match wins. Version is taken near the matched product token so a
    Drupal script hint does not inherit Apache's version tuple (and vice versa).
    """
    blob = _norm_blob(product, version, extrainfo, service, script_blob)
    if not blob:
        return None
    for rule in EOL_RULES:
        needles = rule.get("product_contains") or ()
        hit = next((n for n in needles if n.lower() in blob), None)
        if not hit:
            continue
        bound = rule.get("version_lt")
        if bound is None:
            return rule
        ver = _version_near_needle(blob, hit, version)
        # Product matched but version unknown → do not bump
        if ver is None:
            continue
        if _version_lt(ver, tuple(bound)):
            return rule
    return None


def bump_severity(base: str, steps: int) -> str:
    """Raise severity by ``steps`` levels; never above critical; never invent."""
    sev = (base or "info").strip().lower()
    if sev not in _SEV_ORDER:
        sev = "info"
    if steps <= 0:
        return sev
    idx = _SEV_ORDER.index(sev)
    return _SEV_ORDER[min(idx + steps, len(_SEV_ORDER) - 1)]


def apply_version_severity(
    base_sev: str,
    *,
    product: str = "",
    version: str = "",
    extrainfo: str = "",
    service: str = "",
    script_blob: str = "",
) -> tuple[str, str | None]:
    """Return (severity, matched_rule_id_or_None)."""
    rule = match_eol_rule(
        product=product,
        version=version,
        extrainfo=extrainfo,
        service=service,
        script_blob=script_blob,
    )
    if rule is None:
        return (base_sev or "info").strip().lower() or "info", None
    steps = int(rule.get("bump") or 1)
    return bump_severity(base_sev, steps), str(rule.get("id") or "")


def format_product_version(
    *,
    product: str = "",
    version: str = "",
    extrainfo: str = "",
    script_blob: str = "",
) -> str:
    """Human label for finding name/description. Empty when nothing known."""
    product = (product or "").strip()
    version = (version or "").strip()
    extrainfo = (extrainfo or "").strip()
    parts: list[str] = []
    if product and version:
        parts.append(f"{product} {version}")
    elif product:
        parts.append(product)
    elif version:
        parts.append(version)
    if extrainfo and extrainfo not in " ".join(parts):
        # Keep short; avoid dumping huge banners
        if len(extrainfo) <= 80:
            parts.append(f"({extrainfo})" if parts else extrainfo)
    # Drupal etc. often only appear in nmap scripts (http-generator)
    low = " ".join(parts).lower()
    blob = (script_blob or "").strip()
    if blob:
        # Capture "Drupal 7" style tokens from script outputs
        for m in re.finditer(
            r"\b(Drupal|WordPress|Joomla|Tomcat|IIS|nginx)\s+([0-9]+(?:\.[0-9]+)*)",
            blob,
            flags=re.I,
        ):
            token = f"{m.group(1)} {m.group(2)}"
            if token.lower() not in low:
                parts.append(token)
                low = " ".join(parts).lower()
    return " ".join(parts).strip()


def enrich_port_title(base_title: str, product_version_label: str) -> str:
    """Append product/version to the port-table title when present."""
    label = (product_version_label or "").strip()
    title = (base_title or "").strip() or "Open port"
    if not label:
        return title
    if label.lower() in title.lower():
        return title
    return f"{title} ({label})"


def enrich_port_description(
    base_desc: str,
    product_version_label: str,
    *,
    rule_id: str | None = None,
) -> str:
    """Ensure product+version appears in the finding description."""
    label = (product_version_label or "").strip()
    desc = (base_desc or "").strip()
    if not label:
        return desc
    if label.lower() in desc.lower():
        out = desc
    else:
        out = f"{desc} Service: {label}."
    if rule_id:
        note = f" Version severity rule: {rule_id}."
        if note.strip().lower() not in out.lower():
            out = f"{out}{note}"
    return out
