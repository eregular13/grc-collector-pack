from __future__ import annotations

import json
from pathlib import Path

from scripts.preview_probo import build_probo_preview, write_preview as write_probo
from scripts.preview_rr import build_rr_preview, write_preview as write_rr

ROOT = Path(__file__).resolve().parents[1]


def test_previews_write_pending_shapes(tmp_path: Path) -> None:
    ciso = tmp_path / "ciso-assistant"
    rr = tmp_path / "riskready"
    ciso.mkdir()
    rr.mkdir()
    (ciso / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        "X-1,Public bucket,demo,critical,identified,demo\n",
        encoding="utf-8",
    )
    (rr / "risks_proposed.json").write_text(
        json.dumps(
            [
                {
                    "ref_id": "X-1",
                    "name": "Public bucket",
                    "severity": "critical",
                    "likelihood": "ALMOST_CERTAIN",
                    "impact": "SEVERE",
                    "treatment": "mitigate",
                }
            ]
        ),
        encoding="utf-8",
    )
    probo = build_probo_preview(tmp_path)
    assert probo["posted"] is False
    assert probo["createRisk"][0]["shape"] == "createRisk"
    rr_prev = build_rr_preview(tmp_path)
    assert rr_prev["posts_api_risks"] is False
    assert rr_prev["status"] == "PENDING"
    assert rr_prev["pending"][0]["auto_approve"] is False
    write_probo(tmp_path)
    write_rr(tmp_path)
    assert (tmp_path / "import_preview" / "probo.json").exists()
    assert (tmp_path / "import_preview" / "riskready_pending.json").exists()
    manifest = json.loads((tmp_path / "import_preview" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["posts_api_risks"] is False


def test_preview_scripts_have_no_sockets_or_risks_post() -> None:
    banned = ("socket.socket", "urllib.request", "http.client", "requests.get")
    for name in ("preview_probo.py", "preview_rr.py"):
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, name
        assert "curl" not in text
        assert 'POST "/api/risks"' not in text
        assert "${API}/risks" not in text
