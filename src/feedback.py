"""Persistent analyst-feedback audit log used by the SOC dashboard and next model refresh."""
from __future__ import annotations

from datetime import datetime, timezone
import os
import csv

import pandas as pd

import config as C


FEEDBACK_COLUMNS = [
    "submitted_at_utc",
    "event_id",
    "entity_id",
    "model_label",
    "model_risk",
    "disposition",
    "analyst",
    "note",
]


def load_feedback(path=C.FEEDBACK_CSV):
    if not os.path.exists(path):
        return pd.DataFrame(columns=FEEDBACK_COLUMNS)
    frame = pd.read_csv(path)
    for column in FEEDBACK_COLUMNS:
        if column not in frame:
            frame[column] = ""
    return frame[FEEDBACK_COLUMNS]


def append_feedback(event, disposition, analyst="campus_demo", note="",
                    path=C.FEEDBACK_CSV, submitted_at_utc=None):
    """Append a decision without deleting earlier audit records (single writer)."""
    allowed = {"false_positive", "expected_behavior", "needs_investigation"}
    allowed.update(f"confirmed_{label}" for label in C.ALL_LABELS)
    if disposition not in allowed:
        raise ValueError(f"Unknown disposition: {disposition}")
    event_id = int(event["event_id"])
    row = {
        "submitted_at_utc": submitted_at_utc or datetime.now(timezone.utc).isoformat(),
        "event_id": event_id,
        "entity_id": str(event["entity_id"]),
        "model_label": str(event["pred_label"]),
        "model_risk": round(float(event["risk"]), 4),
        "disposition": str(disposition),
        "analyst": str(analyst).strip() or "campus_demo",
        "note": str(note).strip(),
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    needs_header = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEEDBACK_COLUMNS)
        if needs_header:
            writer.writeheader()
        writer.writerow(row)
    return row


def training_overrides(path=C.FEEDBACK_CSV):
    """Return feedback consumable by the next model refresh."""
    feedback = load_feedback(path)
    if feedback.empty:
        return {"normal_event_ids": set(), "attack_labels": {}, "rebaseline_entities": set()}
    # Audit retains every decision; only the latest decision governs training.
    feedback = feedback.drop_duplicates(subset="event_id", keep="last")
    normal = feedback[
        feedback["disposition"].isin(["false_positive", "expected_behavior"])
    ]
    attacks = feedback[feedback["disposition"].str.startswith("confirmed_")]
    labels = {
        int(row.event_id): row.disposition.removeprefix("confirmed_")
        for row in attacks.itertuples()
    }
    return {
        "normal_event_ids": set(normal["event_id"].astype(int)),
        "attack_labels": labels,
        "rebaseline_entities": set(
            feedback.loc[feedback["disposition"] == "expected_behavior",
                         "entity_id"].astype(str)),
    }
