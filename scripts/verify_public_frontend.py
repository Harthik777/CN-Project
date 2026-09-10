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
        assert all(text in response.text for text in ("From packets to network evidence", "Analyze selected dataset", "Upload and analyze", "Export flows CSV", "Browser inference", "Browser only: no upload", "Download offline HTML", "Real dataset transfer check", "CTU-13")), url
        record = dict(url=url, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), packet_ui_present=True)
        if "github.io" in url:
            record["matches_packaged_frontend"] = data == (ROOT / "assets" / "SentinelUEBA-React-Console.html").read_bytes()
            assert record["matches_packaged_frontend"], "Pages artifact does not match this release"
        records.append(record)
        worker = client.get(url + "sw.js")
        worker.raise_for_status()
        assert "sentinel-shell:" in worker.text and "__BUILD_ID__" not in worker.text
        record["offline_worker_present"] = True
    origin = "https://harthik777.github.io"
    response = client.options("https://sentinelueba-harthik.onrender.com/api/sessions/test/capture", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"})
    response.raise_for_status()
    assert response.headers["access-control-allow-origin"] == origin
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "authorization" in response.headers["access-control-allow-headers"].lower()
    real = json.loads((ROOT / "artifacts" / "real_captures" / "manifest.json").read_text())
    capture_checks = []
    for capture in real["captures"]:
        response = client.post("https://sentinelueba-harthik.onrender.com/api/sessions", json={})
        response.raise_for_status()
        credential = response.json()
        url = f"https://sentinelueba-harthik.onrender.com/api/sessions/{credential['session_id']}/capture"
        headers = {"Authorization": f"Bearer {credential['token']}", "Content-Type": "application/vnd.tcpdump.pcap"}
        response = client.post(url, content=(ROOT / "artifacts" / "real_captures" / capture["file"]).read_bytes(), headers=headers)
        response.raise_for_status()
        response = client.get(url, headers={"Authorization": headers["Authorization"]})
        response.raise_for_status()
        saved = response.json()
        assert saved["model"]["model_id"] == real["model_id"]
        for key in ("capture_sha256", "parsed_packets", "flows", "flagged_flows", "completed_handshakes"):
            assert saved["summary"][key] == capture["summary"][key], (capture["id"], key)
        capture_checks.append(dict(id=capture["id"], sha256=capture["sha256"], packets=saved["summary"]["parsed_packets"], flows=saved["summary"]["flows"], upload_and_readback_passed=True))
    report = dict(verified_at=datetime.now(timezone.utc).isoformat(), artifacts=records, pages_upload_preflight_passed=True, real_capture_checks=capture_checks)
    output = ROOT / "output" / "public-frontend.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2))
