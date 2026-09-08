"""Re-fit risk calibration and policies from saved channel outputs."""
from __future__ import annotations

import json

import joblib
import numpy as np
import pandas as pd

import config as C
from run_all import temporal_masks
from src import evaluate as EV
from src.classify import predict_proba
from src.models import build_matrix
from src.risk import RULE_COLUMNS, RiskFusion, build_meta_features


def main():
    features = pd.read_parquet(C.FEATURES_PARQUET)
    features["timestamp"] = pd.to_datetime(features["timestamp"])
    features = features.sort_values(
        ["timestamp", "event_id"], kind="stable").reset_index(drop=True)
    scored = pd.read_parquet(C.SCORED_PARQUET)
    scored["timestamp"] = pd.to_datetime(scored["timestamp"])
    scored = scored.sort_values(
        ["timestamp", "event_id"], kind="stable").reset_index(drop=True)
    if not np.array_equal(features["event_id"], scored["event_id"]):
        raise RuntimeError("feature and scored event order differs")

    bundle = joblib.load(C.MODEL_BUNDLE)
    matrix_all, _, _, _ = build_matrix(
        features, scaler=bundle["scaler"],
        cat_vocab=bundle["categorical_vocab"])
    probabilities = predict_proba(bundle["classifier"], matrix_all)
    normal_index = bundle["label_to_idx"][C.BENIGN_LABEL]
    scored["attack_prob"] = 1.0 - probabilities[:, normal_index]

    masks = temporal_masks(features)
    fit = masks["fusion_fit"]
    select = masks["fusion_select"]
    test = masks["test"]
    truth = (scored["label"] != C.BENIGN_LABEL).to_numpy()
    rules = scored[RULE_COLUMNS]
    matrix = build_meta_features(
        scored["ae_score"].to_numpy(),
        scored["iso_score"].to_numpy(),
        scored["seq_score"].to_numpy(),
        scored["adaptive_unsup"].to_numpy(),
        scored["attack_prob"].to_numpy(),
        rules,
        cold_start_weight=features["cold_start_weight"].to_numpy(),
    )

    fusion = RiskFusion().fit(
        matrix[fit], truth[fit], matrix[select], truth[select])
    probability = fusion.predict_proba(matrix)
    risk = 100.0 * probability
    selection_positions = np.where(select)[0]
    calibration_positions = selection_positions[fusion.calibration_start:]
    thresholds = EV.fit_budget_thresholds(
        risk[calibration_positions], C.ALERT_BUDGETS)
    operating = EV.operating_points(
        risk[test], truth[test], thresholds=thresholds)
    top_threshold = thresholds["top_1pct"]["threshold"]

    with open(C.RESULTS_JSON, encoding="utf-8") as handle:
        results = json.load(handle)
    results["ranking"] = EV.ranking_metrics(probability[test], truth[test])
    results["ranking_confidence_interval"] = EV.bootstrap_ranking_ci(
        probability[test], truth[test], scored.loc[test, "entity_id"].to_numpy())
    results["calibration"] = EV.calibration_metrics(
        probability[test], truth[test])
    results["operating_points"] = operating
    results["alert_budget"] = operating["top_1pct"]
    results["thresholds"] = thresholds
    results["cold_start"] = EV.cold_start_recall(
        risk[test], truth[test],
        scored.loc[test, "is_cold_start"].to_numpy(),
        threshold=top_threshold)
    drift_summary = EV.drift_false_positive(
        risk[test], scored.loc[test, "scenario"].to_numpy(),
        truth[test], threshold=top_threshold)
    results["concept_drift"] = {
        **results["concept_drift"],
        **drift_summary,
    }
    results["per_attack_detection"] = EV.per_attack_detection(
        risk[test], scored.loc[test, "label"].to_numpy(), top_threshold)
    operational = EV.ranking_metrics(probability[test], truth[test])
    results["channel_metrics"]["operational_risk"] = operational
    results["channel_auc"]["operational_risk"] = operational["roc_auc"]
    results["fusion"] = {
        "selected_strategy": fusion.selected,
        "validation_candidate_metrics": fusion.candidate_metrics,
        "selection_rule": "highest validation PR-AUC; prefer simpler "
                          "candidate within 0.001",
        "calibration": "Platt scaling on held-out validation logits",
        "tie_breaker": "0.1% adaptive-unsupervised score for saturated "
                       "classifier probabilities",
    }

    test_thirds = np.full(len(scored), "", dtype=object)
    for name, positions in zip(
            ["early", "middle", "late"],
            np.array_split(np.where(test)[0], 3)):
        test_thirds[positions] = name
    results["slices"] = {
        "entity_type": EV.slice_metrics(
            probability[test], truth[test],
            scored.loc[test, "entity_type"].to_numpy()),
        "test_period": EV.slice_metrics(
            probability[test], truth[test], test_thirds[test]),
    }

    scored["risk_probability"] = probability
    scored["risk"] = risk
    scored["is_alert"] = risk >= top_threshold
    scored.to_parquet(C.SCORED_PARQUET, index=False)

    bundle["fusion"] = fusion
    bundle["thresholds"] = thresholds
    joblib.dump(bundle, C.MODEL_BUNDLE, compress=3)

    with open(C.RESULTS_JSON, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    print(
        f"[recalibrate] selected={fusion.selected} "
        f"PR-AUC={results['ranking']['pr_auc']:.4f} "
        f"ROC-AUC={results['ranking']['roc_auc']:.4f}")
    for name, point in operating.items():
        print(
            f"[recalibrate] {name}: alert_rate={point['realized_alert_rate']:.2%} "
            f"P={point['precision']:.3f} R={point['recall']:.3f} "
            f"FP={point['false_positive_rate']:.4f}")


if __name__ == "__main__":
    main()
