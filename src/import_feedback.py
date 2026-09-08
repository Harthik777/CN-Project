"""Preview or import offline console decisions for the exact current snapshot."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

import config as C
from src.feedback import append_feedback, load_feedback


def import_decisions(input_path, snapshot_path=None, feedback_path=None, apply=False):
    snapshot_path = Path(snapshot_path or Path(C.ASSET_DIR) / "dashboard_data.json")
    feedback_path = str(feedback_path or C.FEEDBACK_CSV)
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    snapshot_bytes = snapshot_path.read_bytes()
    if payload.get("schema_version") != 1:
        raise ValueError("Unsupported feedback format")
    if payload.get("snapshot_sha256") != hashlib.sha256(snapshot_bytes).hexdigest():
        raise ValueError("Feedback belongs to a different score snapshot")
    events = {int(row["id"]): row for row in json.loads(snapshot_bytes)["alerts"]}
    allowed = {"false_positive", "expected_behavior", "needs_investigation"}
    allowed.update(f"confirmed_{label}" for label in C.ALL_LABELS)
    decisions = payload.get("decisions")
    if not isinstance(decisions, list):
        raise ValueError("decisions must be a list")
    prepared = []
    # Validate the complete file before writing any records.
    for decision in decisions:
        event_id = decision.get("event_id")
        if type(event_id) is not int or event_id not in events:
            raise ValueError(f"Unknown snapshot event: {event_id}")
        if decision.get("disposition") not in allowed:
            raise ValueError("Unknown disposition")
        if not isinstance(decision.get("note"), str):
            raise ValueError("Case note must be text")
        timestamp = pd.Timestamp(decision.get("at"))
        if pd.isna(timestamp) or timestamp.tzinfo is None:
            raise ValueError("Decision timestamp must include a timezone")
        prepared.append((timestamp.tz_convert("UTC"), decision))
    history = load_feedback(feedback_path)
    latest = {}
    for row in history.itertuples():
        key = int(row.event_id)
        timestamp = pd.Timestamp(row.submitted_at_utc)
        latest[key] = max(latest.get(key, timestamp), timestamp)
    accepted = 0
    for timestamp, decision in sorted(prepared, key=lambda item: item[0]):
        event_id = decision["event_id"]
        if event_id in latest and timestamp <= latest[event_id]:
            continue
        event = events[event_id]
        if apply:
            append_feedback(
                {"event_id": event_id, "entity_id": event["entity"],
                 "pred_label": event["classification"], "risk": event["risk"]},
                decision["disposition"], analyst="offline_console",
                note=decision["note"], path=feedback_path,
                submitted_at_utc=timestamp.isoformat(),
            )
        latest[event_id] = timestamp
        accepted += 1
    return {"new_decisions": accepted, "skipped": len(decisions) - accepted,
            "applied": apply}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="sentinel-feedback.json exported by the console")
    parser.add_argument("--apply", action="store_true", help="append validated decisions")
    parser.add_argument("--feedback-path", help="optional audit CSV path, e.g. output/demo_feedback.csv")
    args = parser.parse_args()
    print(json.dumps(import_decisions(args.input, feedback_path=args.feedback_path,
                                     apply=args.apply), indent=2))


if __name__ == "__main__":
    main()
