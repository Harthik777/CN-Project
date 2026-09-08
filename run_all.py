"""
SentinelUEBA end-to-end reproducible training and evaluation pipeline.

    python run_all.py --fresh

Protocol:
  1. Train base models on the earliest window.
  2. Fit fusion on validation A.
  3. Select/calibrate the operational risk strategy and alert thresholds on
     later validation segments.
  4. Report metrics once on the untouched final test window.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import sys
import time

import joblib
import lightgbm
import numpy as np
import pandas as pd
import sklearn
import torch

import config as C
from src import evaluate as EV
from src.classify import (
    apply_rule_overrides,
    predict_proba,
    select_rule_overrides,
    train_classifier,
)
from src.drift import adaptive_entity_scores
from src.explain import compose_reason, rule_reasons, shap_top_features
from src.feedback import load_feedback, training_overrides
from src.features import NUMERIC_FEATURES, build_features
from src.models import (
    ae_scores,
    build_matrix,
    iso_scores,
    rank_normalise,
    train_autoencoder,
    train_isoforest,
)
from src.models_seq import (
    build_prefix_index,
    clean_training_events,
    seq_event_scores,
    train_seq_ae,
)
from src.risk import (
    RULE_COLUMNS,
    RiskFusion,
    build_meta_features,
    rule_signals,
)


def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def ensure_data(fresh):
    timings = {}
    if fresh or not os.path.exists(C.LOGS_CSV):
        from src.generate_data import generate
        started = time.perf_counter()
        generate()
        timings["data_generation_sec"] = time.perf_counter() - started
    if fresh or not os.path.exists(C.FEATURES_PARQUET):
        from src.features import main as feature_main
        started = time.perf_counter()
        feature_main()
        timings["feature_build_sec"] = time.perf_counter() - started
    return timings


def temporal_masks(df):
    n = len(df)
    train_position = int(C.TRAIN_FRACTION * n)
    validation_end_position = int(
        (C.TRAIN_FRACTION + C.VALIDATION_FRACTION) * n)
    train_boundary = pd.Timestamp(df["timestamp"].iloc[train_position])
    test_boundary = pd.Timestamp(df["timestamp"].iloc[validation_end_position])
    gap = pd.Timedelta(hours=C.PURGE_HOURS)
    timestamps = df["timestamp"]

    train = (timestamps < train_boundary - gap).to_numpy()
    validation = (
        (timestamps >= train_boundary + gap) &
        (timestamps < test_boundary - gap)
    ).to_numpy()
    test = (timestamps >= test_boundary + gap).to_numpy()

    validation_positions = np.where(validation)[0]
    midpoint = len(validation_positions) // 2
    fusion_fit = np.zeros(n, dtype=bool)
    fusion_select = np.zeros(n, dtype=bool)
    fusion_fit[validation_positions[:midpoint]] = True
    fusion_select[validation_positions[midpoint:]] = True
    return {
        "train": train,
        "validation": validation,
        "fusion_fit": fusion_fit,
        "fusion_select": fusion_select,
        "test": test,
        "train_boundary": train_boundary,
        "test_boundary": test_boundary,
        "purged_events": int(n - train.sum() - validation.sum() - test.sum()),
    }


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_default(value):
    if isinstance(value, (np.integer, np.floating)):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()
    raise TypeError(f"not JSON serializable: {type(value)!r}")


def _channel_metrics(scores, truth):
    return {
        "roc_auc": EV.ranking_metrics(scores, truth)["roc_auc"],
        "pr_auc": EV.ranking_metrics(scores, truth)["pr_auc"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fresh", action="store_true",
        help="regenerate synthetic logs and causal features")
    args = parser.parse_args()

    started = time.time()
    generation_timings = ensure_data(args.fresh)

    log("loading causal features")
    df = pd.read_parquet(C.FEATURES_PARQUET)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(["timestamp", "event_id"], kind="stable").reset_index(drop=True)
    n = len(df)
    masks = temporal_masks(df)
    train = masks["train"]
    fusion_fit = masks["fusion_fit"]
    fusion_select = masks["fusion_select"]
    test = masks["test"]

    label_to_idx = {label: index for index, label in enumerate(C.ALL_LABELS)}
    truth_idx = df["label"].map(label_to_idx).to_numpy()
    is_attack = (df["label"] != C.BENIGN_LABEL).to_numpy()

    # Analyst decisions are consumed only as training labels; final evaluation
    # always uses immutable simulator ground truth.
    feedback = training_overrides()
    training_idx = truth_idx.copy()
    event_to_position = pd.Series(
        np.arange(n), index=df["event_id"].astype(int)).to_dict()
    for event_id in feedback["normal_event_ids"]:
        if event_id in event_to_position:
            training_idx[event_to_position[event_id]] = label_to_idx[C.BENIGN_LABEL]
    for event_id, label in feedback["attack_labels"].items():
        if event_id in event_to_position and label in label_to_idx:
            training_idx[event_to_position[event_id]] = label_to_idx[label]
    training_attack = training_idx != label_to_idx[C.BENIGN_LABEL]

    log(
        f"events={n:,} train={train.sum():,} validation={masks['validation'].sum():,} "
        f"test={test.sum():,} purged={masks['purged_events']:,} "
        f"attacks={is_attack.sum():,} ({is_attack.mean():.2%})")

    # Fit preprocessing and unsupervised baselines on known-normal training
    # observations only.
    normal_train = train & ~training_attack
    X_normal, scaler, vocab, feature_names = build_matrix(df[normal_train])
    X_all, _, _, _ = build_matrix(df, scaler=scaler, cat_vocab=vocab)

    log("training normal-only dense autoencoder")
    autoencoder = train_autoencoder(X_normal)
    ae_raw = ae_scores(autoencoder, X_all)
    ae_reference = ae_raw[normal_train]
    ae_score = rank_normalise(ae_raw, ref=ae_reference)

    log("training normal-only isolation forest")
    isolation_forest = train_isoforest(X_normal)
    iso_raw = iso_scores(isolation_forest, X_all)
    iso_reference = iso_raw[normal_train]
    iso_score = rank_normalise(iso_raw, ref=iso_reference)

    log("building causal session prefixes and training GRU")
    prefix_index = build_prefix_index(df)
    clean_events = clean_training_events(
        prefix_index,
        np.asarray([C.ALL_LABELS[index] for index in training_idx]),
        normal_train)
    if len(clean_events) > 30000:
        rng = np.random.default_rng(C.SEED)
        clean_events = np.sort(rng.choice(clean_events, 30000, replace=False))
    sequence_autoencoder = train_seq_ae(
        X_all, prefix_index, clean_events)
    seq_raw = seq_event_scores(sequence_autoencoder, X_all, prefix_index)
    seq_reference = seq_raw[normal_train]
    seq_score = rank_normalise(seq_raw, ref=seq_reference)

    log("computing causal rules and adaptive entity baselines")
    rules = rule_signals(df)
    protected = rules[RULE_COLUMNS].max(axis=1).to_numpy() > 0.5
    raw_unsupervised = np.maximum.reduce([ae_score, iso_score, seq_score])
    adaptive_unsup, drift_alarm, baseline_epoch, drift_stats = (
        adaptive_entity_scores(
            df, raw_unsupervised, protected_mask=protected,
            reset_entities=feedback["rebaseline_entities"]))

    log("training attack-type classifier")
    classifier = train_classifier(
        X_all[train], training_idx[train], n_classes=len(C.ALL_LABELS))
    probabilities = predict_proba(classifier, X_all)
    attack_probability = (
        1.0 - probabilities[:, label_to_idx[C.BENIGN_LABEL]])
    classifier_prediction = probabilities.argmax(axis=1)

    log("fitting, selecting, and calibrating operational risk")
    meta_features = build_meta_features(
        ae_score, iso_score, seq_score, adaptive_unsup,
        attack_probability, rules,
        cold_start_weight=df["cold_start_weight"].to_numpy())
    fusion = RiskFusion().fit(
        meta_features[fusion_fit], training_attack[fusion_fit],
        meta_features[fusion_select], training_attack[fusion_select])
    risk_probability = fusion.predict_proba(meta_features)
    risk = 100.0 * risk_probability

    # The final portion used by the calibrator also defines deployment
    # thresholds. Test labels and the test score distribution remain untouched.
    selection_positions = np.where(fusion_select)[0]
    calibration_positions = selection_positions[fusion.calibration_start:]
    fitted_thresholds = EV.fit_budget_thresholds(
        risk[calibration_positions], C.ALERT_BUDGETS)
    operating = EV.operating_points(
        risk[test], is_attack[test], thresholds=fitted_thresholds)
    top_one = operating["top_1pct"]
    alert_threshold = fitted_thresholds["top_1pct"]["threshold"]

    log("validation-gating attack-type rule overrides")
    enabled_rules, rule_evidence, validation_rule_f1 = select_rule_overrides(
        training_idx[fusion_select],
        classifier_prediction[fusion_select],
        rules.loc[fusion_select].reset_index(drop=True),
        label_to_idx)
    final_prediction = apply_rule_overrides(
        classifier_prediction, rules, enabled_rules, label_to_idx)

    log("benchmarking the complete batched inference path")
    benchmark_n = min(20000, n)
    benchmark_started = time.perf_counter()
    _ = ae_scores(autoencoder, X_all[:benchmark_n])
    _ = iso_scores(isolation_forest, X_all[:benchmark_n])
    _ = seq_event_scores(
        sequence_autoencoder, X_all, prefix_index[:benchmark_n])
    _ = predict_proba(classifier, X_all[:benchmark_n])
    _ = fusion.predict_proba(meta_features.iloc[:benchmark_n])
    benchmark_seconds = time.perf_counter() - benchmark_started

    raw_sample = pd.read_csv(C.LOGS_CSV, nrows=min(10000, n))
    feature_started = time.perf_counter()
    _ = build_features(raw_sample)
    feature_seconds = time.perf_counter() - feature_started
    scalability = {
        "model_benchmark_events": int(benchmark_n),
        "model_seconds": round(benchmark_seconds, 3),
        "model_events_per_sec": int(benchmark_n / benchmark_seconds),
        "model_ms_per_event": round(
            1000 * benchmark_seconds / benchmark_n, 4),
        "feature_benchmark_events": int(len(raw_sample)),
        "feature_seconds": round(feature_seconds, 3),
        "feature_events_per_sec": int(len(raw_sample) / feature_seconds),
        "hardware": f"{platform.processor() or platform.machine()} CPU; "
                    "single-thread model settings; no GPU",
        "scope": "causal feature replay measured separately; model benchmark "
                 "includes AE, Isolation Forest, causal GRU, classifier, and fusion",
    }

    log("generating quantified explanations")
    alert_positions = np.where(risk >= alert_threshold)[0]
    top_positions = np.argsort(risk)[::-1][:5000]
    explanation_positions = np.unique(
        np.concatenate([alert_positions, top_positions]))
    if len(explanation_positions) > 12000:
        explanation_positions = top_positions[:12000]
    explanation_rules = rules.iloc[explanation_positions].reset_index(drop=True)
    explanation_features = df.iloc[explanation_positions].reset_index(drop=True)
    fired, counterfactuals = rule_reasons(
        explanation_rules, explanation_features)
    shap_features = shap_top_features(
        classifier, X_all[explanation_positions],
        classifier_prediction[explanation_positions], feature_names, k=3)
    reasons = np.full(n, "", dtype=object)
    for local, position in enumerate(explanation_positions):
        reasons[position] = compose_reason(
            fired[local], shap_features[local],
            C.ALL_LABELS[final_prediction[position]],
            counterfactuals[local])

    log("evaluating once on the untouched final window")
    test_probability = risk_probability[test]
    test_truth = is_attack[test]
    test_labels = df.loc[test, "label"].to_numpy()
    is_cold = df["entity_hist_count"].to_numpy() < C.COLD_HISTORY

    channel_scores = {
        "autoencoder": ae_score,
        "isolation_forest": iso_score,
        "causal_gru": seq_score,
        "adaptive_unsupervised": adaptive_unsup,
        "classifier": attack_probability,
        "operational_risk": risk_probability,
    }
    channel_metrics = {
        name: _channel_metrics(score[test], test_truth)
        for name, score in channel_scores.items()
    }

    # Zero-label view: each attack is compared with benign events using only
    # the adaptive unsupervised channel, independent of attack labels at fit.
    zero_label = {}
    for attack in C.ATTACK_TYPES:
        subset = test & df["label"].isin([C.BENIGN_LABEL, attack]).to_numpy()
        zero_label[attack] = EV.ranking_metrics(
            adaptive_unsup[subset], is_attack[subset])

    test_thirds = np.full(n, "", dtype=object)
    test_positions = np.where(test)[0]
    for name, positions in zip(
            ["early", "middle", "late"], np.array_split(test_positions, 3)):
        test_thirds[positions] = name

    results = {
        "project": {
            "name": "SentinelUEBA",
            "version": "2.1",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "seed": C.SEED,
        },
        "dataset": {
            "events": int(n),
            "attacks": int(is_attack.sum()),
            "attack_rate": float(is_attack.mean()),
            "label_distribution": df["label"].value_counts().to_dict(),
            "train": int(train.sum()),
            "validation": int(masks["validation"].sum()),
            "test": int(test.sum()),
            "purged": masks["purged_events"],
        },
        "evaluation_protocol": {
            "type": "chronological train / fusion-validation / "
                    "selection-calibration / untouched test",
            "train_boundary": masks["train_boundary"].isoformat(),
            "test_boundary": masks["test_boundary"].isoformat(),
            "purge_hours": C.PURGE_HOURS,
            "threshold_source": "final calibration segment only",
            "test_used_for_selection": False,
            "all_features_causal": True,
            "sequence_scoring": "event session prefix only",
            "score_normalisation_reference": "normal training events only",
        },
        "ranking": EV.ranking_metrics(test_probability, test_truth),
        "ranking_confidence_interval": EV.bootstrap_ranking_ci(
            test_probability, test_truth,
            df.loc[test, "entity_id"].to_numpy()),
        "calibration": EV.calibration_metrics(
            test_probability, test_truth),
        "alert_budget": top_one,
        "operating_points": operating,
        "thresholds": fitted_thresholds,
        "classification": EV.classification_metrics(
            truth_idx[test], final_prediction[test], C.ALL_LABELS),
        "classification_without_rules": EV.classification_metrics(
            truth_idx[test], classifier_prediction[test], C.ALL_LABELS),
        "classification_strategy": {
            "enabled_rule_overrides": enabled_rules,
            "validation_rule_evidence": rule_evidence,
            "validation_macro_f1_after_rules": validation_rule_f1,
        },
        "cold_start": EV.cold_start_recall(
            risk[test], test_truth, is_cold[test],
            threshold=alert_threshold),
        "concept_drift": {
            **EV.drift_false_positive(
                risk[test], df.loc[test, "scenario"].to_numpy(),
                test_truth, threshold=alert_threshold),
            **drift_stats,
            "test_drift_alarms": int(drift_alarm[test].sum()),
        },
        "per_attack_detection": EV.per_attack_detection(
            risk[test], test_labels, alert_threshold),
        "channel_metrics": channel_metrics,
        "channel_auc": {
            name: metrics["roc_auc"]
            for name, metrics in channel_metrics.items()
        },
        "fusion": {
            "selected_strategy": fusion.selected,
            "validation_candidate_metrics": fusion.candidate_metrics,
            "selection_rule": "highest validation PR-AUC; prefer simpler "
                              "candidate within 0.001",
        },
        "zero_label_resilience": zero_label,
        "slices": {
            "entity_type": EV.slice_metrics(
                risk_probability[test], test_truth,
                df.loc[test, "entity_type"].to_numpy()),
            "test_period": EV.slice_metrics(
                risk_probability[test], test_truth, test_thirds[test]),
        },
        "scalability": scalability,
        "feedback": {
            "records_consumed": int(len(load_feedback())),
            "normal_overrides": int(len(feedback["normal_event_ids"])),
            "attack_overrides": int(len(feedback["attack_labels"])),
            "rebaseline_entities": int(len(feedback["rebaseline_entities"])),
        },
        "generation_timings": generation_timings,
        "runtime_sec": round(time.time() - started, 1),
        "limitations": [
            "Primary evaluation data is synthetic because access logs with "
            "attack ground truth are privacy restricted.",
            "Attack patterns are simulations, so absolute metrics should not be "
            "treated as production guarantees.",
            "The prototype is a chronological replay, not a deployed Kafka service.",
            "Analyst feedback is applied on the next model refresh, not instantly.",
        ],
    }

    log("persisting scored events and reproducible model bundle")
    output = df.copy()
    output["risk"] = risk
    output["risk_probability"] = risk_probability
    output["pred_label"] = [
        C.ALL_LABELS[index] for index in final_prediction]
    output["ae_score"] = ae_score
    output["iso_score"] = iso_score
    output["seq_score"] = seq_score
    output["adaptive_unsup"] = adaptive_unsup
    output["attack_prob"] = attack_probability
    output["reason"] = reasons
    output["drift_alarm"] = drift_alarm
    output["baseline_epoch"] = baseline_epoch
    output["is_cold_start"] = is_cold
    output["is_alert"] = risk >= alert_threshold
    split_name = np.full(n, "purged", dtype=object)
    split_name[train] = "train"
    split_name[masks["validation"]] = "validation"
    split_name[test] = "test"
    output["split"] = split_name
    output["in_test"] = test
    for column in RULE_COLUMNS:
        output[column] = rules[column].to_numpy()

    keep = [
        "event_id", "entity_id", "entity_type", "role", "timestamp",
        "source_ip", "geo_city", "resource_accessed", "auth_result",
        "bytes_out", "device_os", "device_mac", "protocol", "label",
        "scenario", "risk", "risk_probability", "pred_label", "ae_score",
        "iso_score", "seq_score", "adaptive_unsup", "attack_prob", "reason",
        "drift_alarm", "baseline_epoch", "is_cold_start", "is_alert",
        "split", "in_test", "entity_hist_count",
    ] + RULE_COLUMNS
    output[keep].to_parquet(C.SCORED_PARQUET, index=False)

    bundle = {
        "version": "2.1",
        "scaler": scaler,
        "categorical_vocab": vocab,
        "feature_names": feature_names,
        "isolation_forest": isolation_forest,
        "classifier": classifier,
        "fusion": fusion,
        "ae_reference": np.sort(ae_reference),
        "iso_reference": np.sort(iso_reference),
        "seq_reference": np.sort(seq_reference),
        "enabled_rule_overrides": enabled_rules,
        "label_to_idx": label_to_idx,
        "thresholds": fitted_thresholds,
        "autoencoder": {
            "input_dim": int(X_all.shape[1]),
            "hidden": list(C.AE_HIDDEN),
            "weights": os.path.basename(C.AE_WEIGHTS),
        },
        "sequence_autoencoder": {
            "input_dim": int(X_all.shape[1]),
            "hidden": C.LSTM_HIDDEN,
            "seq_len": C.SEQ_LEN,
            "weights": os.path.basename(C.SEQ_WEIGHTS),
        },
    }
    torch.save(autoencoder.state_dict(), C.AE_WEIGHTS)
    torch.save(sequence_autoencoder.state_dict(), C.SEQ_WEIGHTS)
    joblib.dump(bundle, C.MODEL_BUNDLE, compress=3)

    with open(C.RESULTS_JSON, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, default=_json_default)

    source_files = [
        "config.py", "run_all.py", "src/generate_data.py",
        "src/features.py", "src/models.py",
        "src/models_seq.py", "src/classify.py", "src/risk.py",
        "src/drift.py", "src/evaluate.py", "src/explain.py",
        "src/feedback.py", "src/inference.py",
    ]
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "seed": C.SEED,
        "python": sys.version,
        "platform": platform.platform(),
        "dependencies": {
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "lightgbm": lightgbm.__version__,
            "torch": torch.__version__,
        },
        "source_sha256": {
            path: _sha256(os.path.join(C.ROOT, path))
            for path in source_files
        },
        "artifact_sha256": {
            os.path.relpath(path, C.ROOT): _sha256(path)
            for path in [
                C.RESULTS_JSON, C.SCORED_PARQUET, C.MODEL_BUNDLE,
                C.AE_WEIGHTS, C.SEQ_WEIGHTS,
            ]
        },
    }
    with open(C.RUN_MANIFEST, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)

    print("\n" + "=" * 72)
    print("SENTINELUEBA 2.1 - UNTOUCHED TEST RESULTS")
    print("=" * 72)
    print(
        f"Operational risk  ROC-AUC {results['ranking']['roc_auc']:.4f}  "
        f"PR-AUC {results['ranking']['pr_auc']:.4f}")
    print(
        f"Selected strategy: {fusion.selected} "
        f"(chosen on validation, never test)")
    print("Fixed validation thresholds applied to test:")
    for name, point in operating.items():
        print(
            f"  {name:<10} P {point['precision']:.3f} "
            f"R {point['recall']:.3f} FP-rate {point['false_positive_rate']:.4f} "
            f"realized alerts {point['realized_alert_rate']:.2%}")
    print(
        "Attack-type macro-F1: "
        f"{results['classification']['macro_f1_attacks']:.3f}")
    print(
        "Cold-start recall / FP-rate: "
        f"{results['cold_start'].get('cold_attack_recall_at_budget', 0):.3f} / "
        f"{results['cold_start'].get('cold_false_positive_rate', 0):.4f}")
    print(
        "Benign drift FP-rate: "
        f"{results['concept_drift'].get('drift_false_positive_rate', 0):.4f}")
    print("=" * 72)
    print(f"wrote {C.SCORED_PARQUET}")
    print(f"wrote {C.RESULTS_JSON}")
    print(f"wrote {C.MODEL_BUNDLE}")
    print(f"total {results['runtime_sec']}s")
    return results


if __name__ == "__main__":
    main()
