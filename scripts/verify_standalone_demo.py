"""Verify the published standalone artifact without contacting a backend."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import urlopen


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.policy = ""
        self.dependencies = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "content-security-policy":
            self.policy = attrs.get("content", "")
        if tag in ("script", "img", "iframe") and attrs.get("src", "").startswith(("http:", "https:", "//", "/")):
            self.dependencies.append(attrs["src"])
        if tag == "link" and attrs.get("rel") == "stylesheet":
            self.dependencies.append(attrs.get("href"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://harthik777.github.io/CN-Project/")
    parser.add_argument("--output", type=Path, default=Path("output/public-standalone.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    with urlopen(args.url, timeout=30) as response:
        assert response.status == 200
        assert response.headers.get_content_type() == "text/html"
        data = response.read()
    assert data == (root / "assets/SentinelUEBA-React-Console.html").read_bytes(), "Published HTML differs from this release"
    html = data.decode("utf-8")
    document = Document()
    document.feed(html)
    assert "connect-src 'self'" in document.policy and not document.dependencies
    for forbidden in ("/api/health", "/api/sessions", "sentinelueba-harthik.onrender.com", "Refresh saved report", "Score baseline", "Save to server"):
        assert forbidden not in html, forbidden
    for required in ("Standalone demo", "No backend, sign-in or cloud session is needed", "Analyze selected dataset", "CTU-13", "Show topology table", "Save disposition", "Export report JSON", "Download offline HTML"):
        assert required in html, required
    with urlopen(args.url.rstrip("/") + "/sw.js", timeout=30) as response:
        worker = response.read().decode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    assert digest[:16] in worker and "__BUILD_ID__" not in worker
    record = dict(verified_at=datetime.now(timezone.utc).isoformat(), url=args.url, bytes=len(data), sha256=digest,
                  matches_packaged_frontend=True, backend_routes_absent=True, external_runtime_assets=[],
                  content_security_policy=document.policy, offline_worker_matches_build=True,
                  scope="HTTP artifact checks; interactive behavior is verified separately in the browser")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
