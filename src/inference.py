"""Load the persisted SentinelUEBA bundle and score a chronological log replay.

Example:
    python -m src.inference --input data/access_logs.csv \
        --output data/inference_replay.parquet
"""
from __future__ import annotations

import argparse
import os

import joblib
import numpy as np
import pandas as pd
import torch

import config as C
from src.classify import apply_rule_overrides, predict_proba
from src.drift import adaptive_entity_scores
from src.explain import compose_reason, rule_reasons, shap_top_features
from src.features import build_features
from src.feedback import training_overrides
from src.models import (
    DenseAutoEncoder,
    ae_scores,
    build_matrix,
    iso_scores,
    rank_normalise,
)
from src.models_seq import (
    GRUAutoEncoder,
    build_prefix_index,
    seq_event_scores,
)
from src.risk import RULE_COLUMNS, build_meta_features, rule_signals


def prepare_log(frame):
    frame = frame.copy()
    if "event_id" not in frame:
        frame.insert(0, "event_id", np.arange(len(frame)))
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    if "session_id" not in frame:
        bucket = frame["timestamp"].dt.floor("30min").astype(str)
        frame["session_id"] = frame["entity_id"].astype(str) + "_" + bucket
    if "label" not in frame:
        frame["label"] = C.BENIGN_LABEL
    if "scenario" not in frame:
        frame["scenario"] = "inference"
    return frame.sort_values(["timestamp", "event_id"], kind="stable").reset_index(drop=True)


def load_models(bundle_path=C.MODEL_BUNDLE):
    bundle = joblib.load(bundle_path)
    autoencoder = DenseAutoEncoder(
        bundle["autoencoder"]["input_dim"],
        hidden=bundle["autoencoder"]["hidden"])
    autoencoder.load_state_dict(torch.load(
        C.AE_WEIGHTS, map_location="cpu", weights_only=True))

    sequence = GRUAutoEncoder(
        bundle["sequence_autoencoder"]["input_dim"],
        hidden=bundle["sequence_autoencoder"]["hidden"])
    sequence.load_state_dict(torch.load(
        C.SEQ_WEIGHTS, map_location="cpu", weights_only=True))
    return bundle, autoencoder, sequence


def score(frame, bundle_path=C.MODEL_BUNDLE, policy="top_1pct", *,
          models=None, use_feedback=True):
    raw = prepare_log(frame)
    features = build_features(raw)
    bundle, autoencoder, sequence = models if models is not None else load_models(bundle_path)
    matrix, _, _, feature_names = build_matrix(
        features,
        scaler=bundle["scaler"],
        cat_vocab=bundle["categorical_vocab"])

    ae = rank_normalise(
        ae_scores(autoencoder, matrix), ref=bundle["ae_reference"])
    iso = rank_normalise(
        iso_scores(bundle["isolation_forest"], matrix),
        ref=bundle["iso_reference"])
    prefix = build_prefix_index(features)
    seq = rank_normalise(
        seq_event_scores(sequence, matrix, prefix),
        ref=bundle["seq_reference"])

    rules = rule_signals(features)
    protected = rules[RULE_COLUMNS].max(axis=1).to_numpy() > 0.5
    # Public sessions must never inherit another analyst's local feedback.
    feedback = training_overrides() if use_feedback else {"rebaseline_entities": []}
    adaptive, drift_alarm, baseline_epoch, _ = adaptive_entity_scores(
        features, np.maximum.reduce([ae, iso, seq]),
        protected_mask=protected,
        reset_entities=feedback["rebaseline_entities"])

    probabilities = predict_proba(bundle["classifier"], matrix)
    label_to_idx = bundle["label_to_idx"]
    attack_probability = 1.0 - probabilities[:, label_to_idx[C.BENIGN_LABEL]]
    classifier_prediction = probabilities.argmax(axis=1)
    meta = build_meta_features(
        ae, iso, seq, adaptive, attack_probability, rules,
        cold_start_weight=features["cold_start_weight"].to_numpy())
    risk_probability = bundle["fusion"].predict_proba(meta)
    risk = 100.0 * risk_probability
    final_prediction = apply_rule_overrides(
        classifier_prediction, rules,
        bundle["enabled_rule_overrides"], label_to_idx)

    threshold = float(bundle["thresholds"][policy]["threshold"])
    explain_positions = np.where(risk >= threshold)[0]
    reasons = np.full(len(features), "", dtype=object)
    if len(explain_positions):
        local_rules = rules.iloc[explain_positions].reset_index(drop=True)
        local_features = features.iloc[explain_positions].reset_index(drop=True)
        fired, counterfactuals = rule_reasons(local_rules, local_features)
        shap = shap_top_features(
            bundle["classifier"], matrix[explain_positions],
            classifier_prediction[explain_positions], feature_names, k=3)
        labels = {index: label for label, index in label_to_idx.items()}
        for local, position in enumerate(explain_positions):
            reasons[position] = compose_reason(
                fired[local], shap[local], labels[final_prediction[position]],
                counterfactuals[local])

    output = raw.copy()
    output["risk"] = risk
    output["pred_label"] = [
        C.ALL_LABELS[index] for index in final_prediction]
    output["is_alert"] = risk >= threshold
    output["reason"] = reasons
    output["ae_score"] = ae
    output["iso_score"] = iso
    output["seq_score"] = seq
    output["adaptive_unsup"] = adaptive
    output["attack_prob"] = attack_probability
    output["drift_alarm"] = drift_alarm
    output["baseline_epoch"] = baseline_epoch
    output["entity_hist_count"] = features["entity_hist_count"].to_numpy()
    output["is_cold_start"] = (
        features["entity_hist_count"].to_numpy() < C.COLD_HISTORY)
    for column in RULE_COLUMNS:
        output[column] = rules[column].to_numpy()
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--policy", default="top_1pct",
        choices=["top_0.5pct", "top_1pct", "top_2pct", "top_5pct"])
    args = parser.parse_args()

    frame = (pd.read_parquet(args.input)
             if args.input.lower().endswith(".parquet")
             else pd.read_csv(args.input))
    output = score(frame, policy=args.policy)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    if args.output.lower().endswith(".parquet"):
        output.to_parquet(args.output, index=False)
    else:
        output.to_csv(args.output, index=False)
    print(
        f"[inference] scored {len(output):,} events; "
        f"alerts={int(output['is_alert'].sum()):,}; wrote {args.output}")


if __name__ == "__main__":
    main()
