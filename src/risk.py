"""Explainable rules and validation-gated operational risk fusion."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score


IMPOSSIBLE_KMH = 900.0

RULE_COLUMNS = [
    "rule_impossible_travel",
    "rule_brute_force",
    "rule_device_spoofing",
    "rule_credential_stuffing",
    "rule_lateral_movement",
    "rule_exfiltration",
]

RULE_TO_LABEL = [
    ("rule_impossible_travel", "impossible_travel"),
    ("rule_device_spoofing", "device_spoofing"),
    ("rule_credential_stuffing", "credential_stuffing"),
    ("rule_brute_force", "brute_force"),
    ("rule_lateral_movement", "lateral_movement"),
    ("rule_exfiltration", "low_and_slow_exfiltration"),
]


def rule_signals(df: pd.DataFrame) -> pd.DataFrame:
    """Physics and rate rules computed exclusively from causal features."""
    entity_events = np.expm1(df["entity_event_count_5min"].to_numpy())
    ip_entities = np.expm1(df["ip_distinct_entities_1h"].to_numpy())
    ip_events = np.expm1(df["ip_event_count_5min"].to_numpy())
    out = pd.DataFrame(index=df.index)
    out["rule_impossible_travel"] = (
        df["geo_velocity_kmh"] > IMPOSSIBLE_KMH).astype(float)
    out["rule_brute_force"] = (
        (df["entity_fail_rate_1h"] > 0.55) & (entity_events >= 15)).astype(float)
    out["rule_device_spoofing"] = (
        df["device_mismatch"] > 0.5).astype(float)
    out["rule_credential_stuffing"] = (
        (ip_entities >= 8) & (ip_events >= 8) &
        (df["ip_fail_rate_1h"] > 0.55)).astype(float)
    out["rule_lateral_movement"] = (
        (df["session_breadth"] >= 7) &
        (df["session_new_resource_rate"] > 0.55)).astype(float)
    out["rule_exfiltration"] = (
        (df["is_off_hours"] > 0.5) &
        (df["offhour_bytes_24h_log"] > 11.2) &
        ((df["bytes_z"] > 1.5) | (df["peer_bytes_z"] > 2.0))).astype(float)
    return out


def build_meta_features(ae_score, iso_score, seq_score, adaptive_unsup,
                        attack_prob, rules_df, cold_start_weight=None):
    matrix = pd.DataFrame({
        "ae": ae_score,
        "iso": iso_score,
        "seq": seq_score,
        "adaptive_unsup": adaptive_unsup,
        "attack_prob": attack_prob,
        "cold_start_weight": (
            np.zeros(len(attack_prob), dtype=float)
            if cold_start_weight is None else np.asarray(cold_start_weight, dtype=float)),
    })
    for column in RULE_COLUMNS:
        matrix[column] = rules_df[column].to_numpy()
    return matrix


class RiskFusion:
    """Select and calibrate the strongest risk strategy without touching test.

    A stacker is fit on the first validation segment. Candidate selection uses
    the next segment, and probability calibration uses the final segment. If a
    complex fusion does not beat the classifier on validation PR-AUC, the
    simpler classifier remains the operational champion. This prevents a weak
    ensemble from silently degrading production ranking.
    """

    def __init__(self):
        self.meta = LogisticRegression(
            max_iter=1500, class_weight="balanced", C=0.5, random_state=42)
        self.calibrator = LogisticRegression(
            max_iter=1000, C=0.5, random_state=42)
        self.selected = None
        self.candidate_metrics = {}
        self.calibration_start = None

    def _candidate_scores(self, matrix):
        values = matrix.to_numpy() if isinstance(matrix, pd.DataFrame) else matrix
        columns = list(matrix.columns) if isinstance(matrix, pd.DataFrame) else None
        if columns is None:
            raise ValueError("RiskFusion requires a named pandas DataFrame")
        attack = np.asarray(matrix["attack_prob"], dtype=float)
        unsup = np.asarray(matrix["adaptive_unsup"], dtype=float)
        rule_max = np.asarray(matrix[RULE_COLUMNS].max(axis=1), dtype=float)
        stacked = self.meta.predict_proba(values)[:, 1]
        return {
            # A tiny unsupervised term deterministically breaks saturated tree
            # probability ties without changing the classifier-led strategy.
            # Give history-free entities a small unsupervised prior. This is
            # only a tie-breaker for highly confident classifier scores, but it
            # prevents cold-start events from disappearing inside saturation.
            "classifier": (
                0.998 * attack + 0.001 * unsup +
                0.001 * np.asarray(matrix["cold_start_weight"], dtype=float) * unsup),
            "stacked_fusion": stacked,
            "classifier_plus_rules": 1.0 - (1.0 - attack) * (1.0 - 0.45 * rule_max),
            "hybrid_fusion": 0.80 * attack + 0.15 * unsup + 0.05 * rule_max,
        }

    def fit(self, fit_matrix, fit_labels, selection_matrix, selection_labels):
        self.meta.fit(fit_matrix.to_numpy(), np.asarray(fit_labels, dtype=int))

        n = len(selection_matrix)
        if n < 20:
            raise ValueError("validation selection window is too small")
        split = n // 2
        select_part = selection_matrix.iloc[:split]
        calibrate_part = selection_matrix.iloc[split:]
        y_select = np.asarray(selection_labels[:split], dtype=bool)
        y_calibrate = np.asarray(selection_labels[split:], dtype=bool)

        candidates = self._candidate_scores(select_part)
        for name, scores in candidates.items():
            self.candidate_metrics[name] = {
                "pr_auc": float(average_precision_score(y_select, scores)),
                "roc_auc": float(roc_auc_score(y_select, scores)),
            }
        best_pr = max(m["pr_auc"] for m in self.candidate_metrics.values())
        # Prefer the simplest candidate when it is statistically indistinguishable.
        preference = ["classifier", "classifier_plus_rules",
                      "hybrid_fusion", "stacked_fusion"]
        eligible = [
            name for name in preference
            if self.candidate_metrics[name]["pr_auc"] >= best_pr - 0.001
        ]
        self.selected = eligible[0]
        self.calibration_start = split

        raw_calibration = self._candidate_scores(calibrate_part)[self.selected]
        calibration_input = self._calibration_input(raw_calibration)
        self.calibrator.fit(calibration_input, y_calibrate.astype(int))
        return self

    @staticmethod
    def _calibration_input(raw):
        clipped = np.clip(np.asarray(raw, dtype=float), 1e-6, 1 - 1e-6)
        return np.log(clipped / (1.0 - clipped)).reshape(-1, 1)

    def raw_scores(self, matrix):
        if self.selected is None:
            raise RuntimeError("RiskFusion has not been fitted")
        return np.asarray(self._candidate_scores(matrix)[self.selected], dtype=float)

    def predict_proba(self, matrix):
        raw = self.raw_scores(matrix)
        calibrated = self.calibrator.predict_proba(
            self._calibration_input(raw))[:, 1]
        # Platt scaling can saturate a large block of probabilities under
        # extreme imbalance. Preserve a tiny pre-calibration tie-breaker so a
        # fixed alert budget remains deterministic instead of over-firing ties.
        calibrated = np.asarray(calibrated, dtype=np.float64)
        return np.clip(calibrated + 1e-4 * np.asarray(raw, dtype=np.float64), 0.0, 1.0)

    def risk_scores(self, matrix):
        return 100.0 * self.predict_proba(matrix)
