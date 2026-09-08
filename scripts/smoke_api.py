"""Verify an actual running service over HTTP, without exposing session tokens."""
import argparse
import json
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="output/api-smoke.json")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    def call(path, body=None, token=None, expected=200):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer "+token
        request = Request(base+path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            with urlopen(request, timeout=90) as response:
                status, payload = response.status, json.load(response)
        except HTTPError as error:
            status, payload = error.code, json.load(error)
        if status != expected:
            raise RuntimeError(f"{path}: expected {expected}, received {status}: {payload}")
        return payload

    started = time.perf_counter()
    health = call("/api/health")
    examples = call("/api/scenarios")
    session = call("/api/sessions", {"policy": "top_2pct"}, expected=201)
    route, token = "/api/sessions/"+session["session_id"], session["token"]
    baseline = call(route+"/events", {"events": examples["baseline"]["events"]}, token)
    attack = call(route+"/events", {"events": examples["attack"]["events"]}, token)
    duplicate = call(route+"/events", {"events": examples["attack"]["events"]}, token)
    assert duplicate["accepted"] == 0 and duplicate["duplicates"] == 48
    call(route, expected=401)
    invalid = dict(examples["attack"]["events"][0], geo_lat=200)
    call(route+"/events", {"events": [invalid]}, token, expected=422)
    for i, decision in enumerate(("needs_investigation", "confirmed_attack")):
        feedback = {"request_id": f"smoke-review-{i}", "event_id": 167,
                    "disposition": decision, "note": "Synthetic end-to-end verification"}
        call(route+"/feedback", feedback, token)
        assert call(route+"/feedback", feedback, token)["duplicate"]
    state = call(route, token=token)
    assert len(state["events"]) == 168
    assert len(state["feedback"]) == 2
    assert state["events"][-1]["pred_label"] == "credential_stuffing"
    assert state["events"][-1]["is_alert"]
    report = {"url": base, "verified_at_unix": time.time(), "model_id": health["model_id"],
              "events": len(state["events"]), "baseline_alerts": sum(e["is_alert"] for e in state["events"][:120]),
              "campaign_alerts": sum(e["is_alert"] for e in state["events"][120:]),
              "audit_records": len(state["feedback"]), "baseline_scoring_ms": baseline["scoring_ms"],
              "campaign_scoring_ms": attack["scoring_ms"], "wall_seconds": round(time.perf_counter()-started,2),
              "checks": ["health", "ingestion", "real inference", "duplicate replay", "authentication", "invalid input rejection", "feedback history", "feedback idempotency"]}
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
