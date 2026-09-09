"""Check the two published frontend artifacts and the Pages API preflight."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
with httpx.Client(timeout=60, follow_redirects=False) as client:
    records = []
    for url in ("https://sentinelueba-harthik.onrender.com/", "https://harthik777.github.io/CN-Project/"):
        response = client.get(url)
        response.raise_for_status()
        data = response.content
        assert "text/html" in response.headers.get("content-type", ""), url
        assert all(text in response.text for text in ("From packets to network evidence", "Analyze sample capture", "Upload and analyze", "Export flows CSV")), url
        record = dict(url=url, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), packet_ui_present=True)
        if "github.io" in url:
            record["matches_packaged_frontend"] = data == (ROOT / "assets" / "SentinelUEBA-React-Console.html").read_bytes()
            assert record["matches_packaged_frontend"], "Pages artifact does not match this release"
        records.append(record)
    origin = "https://harthik777.github.io"
    response = client.options("https://sentinelueba-harthik.onrender.com/api/sessions/test/capture", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"})
    response.raise_for_status()
    assert response.headers["access-control-allow-origin"] == origin
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "authorization" in response.headers["access-control-allow-headers"].lower()
    report = dict(verified_at=datetime.now(timezone.utc).isoformat(), artifacts=records, pages_upload_preflight_passed=True)
    output = ROOT / "output" / "public-frontend.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2))
