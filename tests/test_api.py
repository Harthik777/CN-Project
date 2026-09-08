import copy
import tempfile
import unittest
from pathlib import Path

import numpy as np
from fastapi.testclient import TestClient

from backend.app import ModelScorer, create_app
from backend.scenarios import scenarios
from backend.schemas import Event
from backend.store import Store


class FakeScorer:
    model_id = "test-model"
    thresholds = {"top_2pct": 50}

    def __call__(self, events, policy):
        return [dict(e, risk=float(i), pred_label="normal", is_alert=False)
                for i, e in enumerate(events)]


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/"state.sqlite3"
        self.scorer = FakeScorer()
        self.client = TestClient(create_app(self.path, self.scorer))
        self.client.__enter__()
        self.credentials = self.client.post("/api/sessions", json={}).json()
        self.route = f"/api/sessions/{self.credentials['session_id']}"
        self.headers = {"Authorization": f"Bearer {self.credentials['token']}"}
        self.events = scenarios()["baseline"]["events"][:3]

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def post(self, suffix, payload):
        return self.client.post(self.route+suffix, headers=self.headers, json=payload)

    def state(self):
        return self.client.get(self.route, headers=self.headers).json()

    def test_health_and_cors(self):
        result = self.client.get("/api/health", headers={"Origin": "https://harthik777.github.io"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["access-control-allow-origin"], "https://harthik777.github.io")
        self.assertEqual(result.headers["cache-control"], "no-store")

    def test_session_isolation(self):
        other = self.client.post("/api/sessions", json={}).json()
        self.assertEqual(self.client.get(self.route).status_code, 401)
        self.assertEqual(self.client.get(self.route, headers={"Authorization": f"Bearer {other['token']}"}).status_code, 401)

    def test_duplicate_ingestion_and_conflicts(self):
        first = self.post("/events", {"events": self.events})
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["accepted"], 3)
        duplicate = self.post("/events", {"events": self.events}).json()
        self.assertEqual((duplicate["accepted"],duplicate["duplicates"]), (0,3))
        conflict = copy.deepcopy(self.events)
        conflict[0]["bytes_out"] += 100
        self.assertEqual(self.post("/events", {"events": conflict}).status_code, 409)
        self.assertEqual(len(self.state()["events"]), 3)

    def test_invalid_batch_has_no_partial_write(self):
        self.events[1]["geo_lat"] = 200
        self.assertEqual(self.post("/events", {"events": self.events}).status_code, 422)
        self.assertEqual(self.state()["events"], [])

    def test_labels_and_scores_rejected(self):
        for key in ("label", "risk", "scenario"):
            event = dict(self.events[0], **{key: "normal"})
            self.assertEqual(self.post("/events", {"events": [event]}).status_code, 422)

    def test_timezone_and_order_enforced(self):
        naive = dict(self.events[0], timestamp="2026-09-01T09:00:00")
        self.assertEqual(self.post("/events", {"events": [naive]}).status_code, 422)
        self.assertEqual(self.post("/events", {"events": self.events[::-1]}).status_code, 422)
        self.assertEqual(self.post("/events", {"events": self.events[1:]}).status_code, 200)
        self.assertEqual(self.post("/events", {"events": self.events[:1]}).status_code, 409)

    def test_timestamp_fraction_and_offset_normalization(self):
        first = dict(self.events[0], timestamp="2026-09-01T14:30:00+05:30")
        second = dict(self.events[1], timestamp="2026-09-01T09:00:00.000001Z")
        self.assertEqual(self.post("/events", {"events": [first, second]}).status_code, 200)
        self.assertEqual(self.state()["events"][0]["timestamp"], "2026-09-01T09:00:00.000000Z")

    def test_feedback_audit_survives_reopen(self):
        self.post("/events", {"events": self.events})
        feedback = dict(event_id=0, request_id="review-request-1", disposition="needs_investigation", note="Initial observation")
        self.assertTrue(self.post("/feedback", feedback).json()["saved"])
        self.assertTrue(self.post("/feedback", feedback).json()["duplicate"])
        conflict = dict(feedback, note="Changed request body")
        self.assertEqual(self.post("/feedback", conflict).status_code, 409)
        revised = dict(feedback, request_id="review-request-2", disposition="benign", note="Approved access")
        self.post("/feedback", revised)
        with TestClient(create_app(self.path, self.scorer)) as reopened:
            saved = reopened.get(self.route, headers=self.headers).json()
            self.assertEqual(len(saved["events"]), 3)
            self.assertEqual([x["disposition"] for x in saved["feedback"]], ["needs_investigation", "benign"])

    def test_unknown_feedback_and_empty_batch(self):
        self.assertEqual(self.post("/feedback", dict(event_id=99, request_id="review-request-1", disposition="benign")).status_code,404)
        self.assertEqual(self.post("/events", {"events": []}).status_code,422)

    def test_model_version_pinned(self):
        self.scorer.model_id = "replacement-model"
        self.assertEqual(self.post("/events", {"events": self.events}).status_code,409)

    def test_inference_failure_rolls_back(self):
        def failed(events, policy):
            raise RuntimeError("simulated failure")
        failed.model_id = self.scorer.model_id
        self.client.app.state.scorer = failed
        self.assertEqual(self.post("/events", {"events": self.events}).status_code,503)
        self.assertEqual(self.state()["events"], [])

    def test_oversized_and_nonfinite_input(self):
        response = self.client.post(self.route+"/events",headers={**self.headers, "Origin": "https://harthik777.github.io"},content=b"x"*(512*1024+1))
        self.assertEqual(response.status_code,413)
        self.assertEqual(response.headers["access-control-allow-origin"], "https://harthik777.github.io")
        event = dict(self.events[0],bytes_out="NaN")
        self.assertEqual(self.post("/events", {"events": [event]}).status_code,422)


class RealModelReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scorer = ModelScorer()
        demo = scenarios()
        cls.rows = [Event(**e).model_dump(mode="json") for e in demo["baseline"]["events"]+demo["attack"]["events"]]

    def test_chunked_replay_restart_matches_whole_model_run(self):
        whole = self.scorer(self.rows,"top_2pct")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"db.sqlite3"
            store = Store(path)
            auth = store.create("top_2pct",self.scorer.model_id)
            sid,token = auth["session_id"],auth["token"]
            store.ingest(sid,token,self.rows[:60],self.scorer,self.scorer.model_id)
            # Reconstruct all service state from SQLite before continuing.
            store = Store(path)
            store.ingest(sid,token,self.rows[60:120],self.scorer,self.scorer.model_id)
            store.ingest(sid,token,self.rows[120:],self.scorer,self.scorer.model_id)
            actual = store.snapshot(sid,token)["events"]
            self.assertEqual([e["pred_label"] for e in actual],[e["pred_label"] for e in whole])
            self.assertEqual([e["is_alert"] for e in actual],[e["is_alert"] for e in whole])
            for key in ("risk","ae_score","iso_score","seq_score","adaptive_unsup","entity_hist_count"):
                np.testing.assert_allclose([e[key] for e in actual],[e[key] for e in whole],atol=1e-6,rtol=1e-6,err_msg=key)
            self.assertEqual(len(actual),168)
            self.assertEqual(actual[-1]["pred_label"],"credential_stuffing")
            self.assertTrue(actual[-1]["is_alert"])
            self.assertNotIn("label",actual[-1])


if __name__ == "__main__":
    unittest.main()
