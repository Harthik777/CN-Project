"""
Unit tests for SentinelUEBA — run with:  python -m unittest discover -s tests

Covers the pure logic (rules, evaluation, drift, matrix assembly, score
normalisation) plus invariants on the generated data / engineered features when
those artifacts are present. Fast: no model training required.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config as C
from src.risk import rule_signals, RULE_COLUMNS
from src import evaluate as EV
from src.drift import PageHinkley, adaptive_entity_scores
from src.models import rank_normalise, build_matrix
from src.models_seq import build_prefix_index
from src.feedback import append_feedback, training_overrides

PACKAGED_LOG_FIXTURE = os.path.join(C.DATA_DIR, "test_access_logs.csv")
PACKAGED_FEATURE_FIXTURE = os.path.join(C.DATA_DIR, "test_features.parquet")
LOGS_UNDER_TEST = (
    C.LOGS_CSV if os.path.exists(C.LOGS_CSV) else PACKAGED_LOG_FIXTURE
)
FEATURES_UNDER_TEST = (
    C.FEATURES_PARQUET
    if os.path.exists(C.FEATURES_PARQUET)
    else PACKAGED_FEATURE_FIXTURE
)


class TestRules(unittest.TestCase):
    def _base_row(self, **over):
        row = dict(entity_fail_rate_1h=0.0, entity_event_count_5min=0.0,
                   ip_distinct_entities_1h=0.0, ip_fail_rate_1h=0.0,
                   ip_event_count_5min=0.0,
                   geo_velocity_kmh=0.0, device_mismatch=0.0, session_breadth=1.0,
                   session_new_resource_rate=0.0,
                   entity_new_resource_rate=0.0, is_off_hours=0.0,
                   bytes_z=0.0, peer_bytes_z=0.0,
                   offhour_bytes_24h_log=0.0)
        row.update(over)
        return pd.DataFrame([row])

    def test_impossible_travel_fires(self):
        r = rule_signals(self._base_row(geo_velocity_kmh=5000))
        self.assertEqual(r["rule_impossible_travel"].iloc[0], 1.0)

    def test_brute_force_fires(self):
        r = rule_signals(self._base_row(entity_fail_rate_1h=0.9,
                                        entity_event_count_5min=np.log1p(50)))
        self.assertEqual(r["rule_brute_force"].iloc[0], 1.0)

    def test_device_spoofing_fires(self):
        r = rule_signals(self._base_row(device_mismatch=1.0))
        self.assertEqual(r["rule_device_spoofing"].iloc[0], 1.0)

    def test_clean_row_fires_nothing(self):
        r = rule_signals(self._base_row())
        self.assertEqual(r[RULE_COLUMNS].sum().sum(), 0.0)


class TestEvaluate(unittest.TestCase):
    def test_alert_budget_perfect_ranking(self):
        # attacks all have the highest risk -> perfect precision at their budget
        risk = np.array([0.1, 0.2, 0.9, 0.95])
        is_atk = np.array([False, False, True, True])
        m = EV.alert_budget_metrics(risk, is_atk, budget=0.5)
        self.assertAlmostEqual(m["precision"], 1.0)
        self.assertAlmostEqual(m["recall"], 1.0)
        self.assertEqual(m["false_positives"], 0)

    def test_ranking_auc_perfect(self):
        risk = np.array([0.1, 0.2, 0.8, 0.9])
        is_atk = np.array([False, False, True, True])
        self.assertAlmostEqual(EV.ranking_metrics(risk, is_atk)["roc_auc"], 1.0)

    def test_operating_points_keys(self):
        risk = np.random.default_rng(0).random(1000)
        is_atk = risk > 0.98
        ops = EV.operating_points(risk, is_atk)
        self.assertIn("top_1pct", ops)

    def test_fixed_threshold_does_not_depend_on_test_distribution(self):
        risk = np.array([1.0, 2.0, 90.0, 95.0])
        truth = np.array([False, False, True, True])
        metric = EV.alert_budget_metrics(risk, truth, threshold=50.0)
        shifted = EV.alert_budget_metrics(risk + 1000, truth, threshold=50.0)
        self.assertNotEqual(metric["n_flagged"], shifted["n_flagged"])
        self.assertEqual(metric["threshold_source"], "validation_window")


class TestDrift(unittest.TestCase):
    def test_step_change_detected(self):
        ph = PageHinkley()
        fired = False
        for _ in range(40):
            ph.update(0.1)                       # stable low
        for _ in range(60):
            if ph.update(0.9):                   # sustained jump
                fired = True
        self.assertTrue(fired)

    def test_stable_signal_no_alarm(self):
        ph = PageHinkley()
        alarms = sum(ph.update(0.5) for _ in range(200))
        self.assertEqual(alarms, 0)

    def test_feedback_reset_starts_new_baseline_epoch(self):
        frame = pd.DataFrame({
            "event_id": [1, 2, 3],
            "entity_id": ["U1", "U1", "U1"],
            "timestamp": pd.to_datetime([
                "2026-01-01 00:00:00",
                "2026-01-01 00:01:00",
                "2026-01-01 00:02:00",
            ]),
        })
        _, _, epochs, stats = adaptive_entity_scores(
            frame, np.array([0.2, 0.2, 0.2]), reset_entities={"U1"})
        self.assertEqual(stats["feedback_rebaseline_entities"], 1)
        self.assertEqual(int(epochs[0]), 1)


class TestModels(unittest.TestCase):
    def test_rank_normalise_range(self):
        r = rank_normalise(np.array([5.0, 1.0, 3.0, 2.0]))
        self.assertGreaterEqual(r.min(), 0.0)
        self.assertAlmostEqual(r.max(), 1.0)

    def test_rank_normalise_uses_training_reference(self):
        ref = np.array([0.0, 1.0, 2.0, 3.0])
        a = rank_normalise(np.array([1.5]), ref=ref)
        b = rank_normalise(np.array([1.5, 999.0]), ref=ref)
        self.assertAlmostEqual(float(a[0]), float(b[0]))

    def test_build_matrix_shape(self):
        from src.features import NUMERIC_FEATURES, CATEGORICAL_FEATURES
        df = pd.DataFrame({**{f: np.random.rand(5) for f in NUMERIC_FEATURES},
                           "entity_type": ["user"] * 5,
                           "role": ["analyst"] * 5,
                           "protocol": ["HTTPS"] * 5})
        X, scaler, vocab, names = build_matrix(df)
        self.assertEqual(X.shape[0], 5)
        self.assertEqual(X.shape[1], len(names))
        self.assertGreaterEqual(len(names), len(NUMERIC_FEATURES))


class TestFeedback(unittest.TestCase):
    def test_feedback_is_auditable_and_consumable(self):
        event = {
            "event_id": 17,
            "entity_id": "U17",
            "pred_label": "brute_force",
            "risk": 98.5,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "feedback.csv")
            append_feedback(
                event, "expected_behavior", analyst="tester",
                note="approved travel", path=path)
            overrides = training_overrides(path)
            self.assertEqual(overrides["normal_event_ids"], {17})
            self.assertEqual(overrides["rebaseline_entities"], {"U17"})


class TestCausality(unittest.TestCase):
    def test_session_prefix_never_contains_future_event(self):
        frame = pd.DataFrame({
            "event_id": [1, 2, 3],
            "timestamp": pd.to_datetime([
                "2026-01-01 00:00:00",
                "2026-01-01 00:01:00",
                "2026-01-01 00:02:00",
            ]),
            "session_id": ["s", "s", "s"],
        })
        prefix = build_prefix_index(frame, seq_len=3)
        self.assertEqual(prefix[0].tolist(), [-1, -1, 0])
        self.assertEqual(prefix[1].tolist(), [-1, 0, 1])
        self.assertEqual(prefix[2].tolist(), [0, 1, 2])

    @unittest.skipUnless(os.path.exists(LOGS_UNDER_TEST), "data fixture not present")
    def test_appending_future_rows_does_not_change_past_features(self):
        from src.features import build_features, NUMERIC_FEATURES
        raw = pd.read_csv(LOGS_UNDER_TEST).head(120)
        past = raw.iloc[:100].copy()
        with_future = raw.copy()
        a = build_features(past)
        b = build_features(with_future).iloc[:len(past)]
        np.testing.assert_allclose(
            a[NUMERIC_FEATURES].to_numpy(),
            b[NUMERIC_FEATURES].to_numpy(),
            rtol=0, atol=1e-9)


@unittest.skipUnless(os.path.exists(LOGS_UNDER_TEST), "data fixture not present")
class TestDataInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = pd.read_csv(LOGS_UNDER_TEST)

    def test_schema_columns(self):
        for col in C.SCHEMA_COLUMNS:
            self.assertIn(col, self.df.columns)

    def test_labels_valid(self):
        self.assertTrue(set(self.df.label.unique()).issubset(set(C.ALL_LABELS)))

    def test_has_all_attack_types(self):
        present = set(self.df.label.unique())
        for atk in C.ATTACK_TYPES:
            self.assertIn(atk, present)

    def test_imbalance_realistic(self):
        rate = (self.df.label != C.BENIGN_LABEL).mean()
        self.assertTrue(0.003 < rate < 0.05, f"attack rate {rate} outside 0.3–5%")


@unittest.skipUnless(os.path.exists(FEATURES_UNDER_TEST), "feature fixture not present")
class TestFeatureInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from src.features import NUMERIC_FEATURES
        cls.NUM = NUMERIC_FEATURES
        cls.df = pd.read_parquet(FEATURES_UNDER_TEST)

    def test_numeric_features_present(self):
        for f in self.NUM:
            self.assertIn(f, self.df.columns)

    def test_no_nan_in_features(self):
        self.assertFalse(self.df[self.NUM].isna().any().any())

    def test_history_count_is_causal(self):
        # every entity's first event must have zero prior history
        self.assertEqual(int(self.df["entity_hist_count"].min()), 0)

    def test_first_ip_event_has_no_future_fanout(self):
        first = self.df.sort_values(["timestamp", "event_id"]).groupby(
            "source_ip", sort=False).head(1)
        self.assertTrue((np.expm1(first["ip_event_count_5min"]) <= 1.000001).all())
        self.assertTrue((np.expm1(first["ip_distinct_entities_1h"]) <= 1.000001).all())


if __name__ == "__main__":
    unittest.main(verbosity=2)
