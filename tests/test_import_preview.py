from __future__ import annotations

import json
from pathlib import Path

from scripts.preview_probo import build_probo_preview, write_preview as write_probo

ROOT = Path(__file__).resolve().parents[1]


def test_previews_write_pending_shapes(tmp_path: Path) -> None:
    ciso = tmp_path / "ciso-assistant"
    ciso.mkdir()
    (ciso / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        "X-1,Public bucket,demo,critical,identified,demo\n",
        encoding="utf-8",
    )
    probo = build_probo_preview(tmp_path)
    assert probo["posted"] is False
    assert probo["http"] is False
    assert probo["createRisk"][0]["shape"] == "createRisk"
    assert probo["addFinding"][0]["shape"] == "addFinding"
    assert probo["addRisk"][0]["shape"] == "addRisk"
    assert probo["organization_id"] is None
    write_probo(tmp_path)
    preview_path = tmp_path / "import_preview" / "probo.json"
    assert preview_path.exists()
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    assert preview["posted"] is False
    assert preview.get("http") is False
    assert "posts_api_risks" not in preview or preview["posts_api_risks"] is False


def test_preview_scripts_have_no_sockets_or_risks_post() -> None:
    banned = ("socket.socket", "urllib.request", "http.client", "requests.get")
    for name in ("preview_probo.py", "export_opengrc.py"):
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, name
        assert "curl" not in text
        assert 'POST "/api/risks"' not in text
        assert "${API}/risks" not in text
