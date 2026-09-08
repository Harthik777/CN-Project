import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.feedback import append_feedback, load_feedback, training_overrides
from src.import_feedback import import_decisions


class TestFeedbackAudit(unittest.TestCase):
    def test_revised_decision_preserves_history_and_replaces_training_override(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "feedback.csv")
            event = {"event_id": 17, "entity_id": "U17", "pred_label": "brute_force", "risk": 99}
            append_feedback(event, "expected_behavior", path=path)
            append_feedback(event, "confirmed_brute_force", path=path)
            self.assertEqual(len(load_feedback(path)), 2)
            overrides = training_overrides(path)
            self.assertEqual(overrides["normal_event_ids"], set())
            self.assertEqual(overrides["rebaseline_entities"], set())
            self.assertEqual(overrides["attack_labels"], {17: "brute_force"})

    def test_import_preview_apply_repeat_and_snapshot_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, payload_path, output = root / "snapshot.json", root / "import.json", root / "audit.csv"
            snapshot.write_text(json.dumps({"alerts": [{"id": 17, "entity": "U17",
                "classification": "brute_force", "risk": 99}]}), encoding="utf-8")
            payload = {"schema_version": 1,
                "snapshot_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                "decisions": [{"event_id": 17, "disposition": "expected_behavior",
                    "note": "Approved test", "at": "2026-09-08T01:00:00Z"}]}
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(import_decisions(payload_path, snapshot, output)["new_decisions"], 1)
            self.assertFalse(output.exists())
            self.assertEqual(import_decisions(payload_path, snapshot, output, True)["new_decisions"], 1)
            self.assertEqual(import_decisions(payload_path, snapshot, output, True)["skipped"], 1)
            self.assertEqual(len(load_feedback(output)), 1)
            payload["snapshot_sha256"] = "wrong"
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different score snapshot"):
                import_decisions(payload_path, snapshot, output, True)
            self.assertEqual(len(load_feedback(output)), 1)

    def test_invalid_later_decision_prevents_partial_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, payload_path, output = root / "snapshot.json", root / "import.json", root / "audit.csv"
            snapshot.write_text(json.dumps({"alerts": [{"id": 1, "entity": "U1",
                "classification": "brute_force", "risk": 99}]}), encoding="utf-8")
            valid = {"event_id": 1, "disposition": "expected_behavior",
                     "note": "Test", "at": "2026-09-08T01:00:00Z"}
            payload_path.write_text(json.dumps({"schema_version": 1,
                "snapshot_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                "decisions": [valid, {**valid, "disposition": "invalid"}]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                import_decisions(payload_path, snapshot, output, True)
            self.assertFalse(output.exists())
