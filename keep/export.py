"""SAMPLE keep-lab CISO intermediate → OpenGRC + Probo files.

Reid: SAMPLE/DEMO KEEP is enough. Do not wait for denser KEEP.
RiskReady stay-out. No sockets. posted=false. demo=true.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from exporters.model import load_pack_estate
from exporters.opengrc import write_opengrc
from exporters.probo import write_probo


def export_keep_sinks(out: Path, *, sample: bool = True) -> dict[str, Any]:
    """Read keep/work/out/ciso-assistant and write OpenGRC + Probo drops."""
    out = Path(out)
    estate = load_pack_estate(out)
    estate.sample = True
    estate.demo = True
    estate.client = False
    estate.origin = "keep-lab"
    estate.source = "ciso-assistant"
    opengrc = write_opengrc(out, estate=estate)
    probo = write_probo(out, estate=estate)
    return {
        "posted": False,
        "http": False,
        "demo": True,
        "sample": True,
        "client": False,
        "client_keep": False,
        "paying_day": "FAIL",
        "riskready": "stay-out",
        "origin": "keep-lab",
        "opengrc": opengrc,
        "probo": str(probo),
        "note": (
            "SAMPLE/DEMO KEEP CISO intermediate → OpenGRC CSVs + Probo drafts. "
            "Not a client KEEP. Not a paying-day stamp. No denser KEEP required."
        ),
        "sample_keep": bool(sample),
    }
