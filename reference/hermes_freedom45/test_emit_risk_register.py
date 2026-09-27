"""risk register emit unit checks."""
import json, tempfile
from pathlib import Path
import emit_risk_register as e

def test_emit_maps_cleartext_and_writes_files():
    sensory = {
        "findings": [
            {"id": "1", "title": "HTTP without HTTPS on x", "severity": "high", "sensor": "sense-cleartext-http",
             "target": "192.0.2.1", "description": "cleartext"},
            {"id": "2", "title": "Open ports on x: [22]", "severity": "medium", "sensor": "sense-surface",
             "target": "192.0.2.1", "description": "ports"},
        ]
    }
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)/"s.json"
        p.write_text(json.dumps(sensory))
        out = Path(td)/"out"
        rows = e.findings_from_sensory(p)
        assert len(rows) == 2
        assert any("SC-8" in c for r in rows for c in r["control_refs"])
        e.write_register(rows, out)
        assert (out/"risk_register.csv").exists()
        assert (out/"poam.csv").exists()
        assert (out/"risk_register.json").exists()
