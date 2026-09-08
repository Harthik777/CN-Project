"""Evaluate the saved model bundle on an independently generated seed."""
from __future__ import annotations

from datetime import datetime, timezone
import argparse
import json
import os

import joblib

import config as C
from src import evaluate as EV
from src.generate_data import generate
from src.inference import score


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20260725)
    args = parser.parse_args()

    temp_path = os.path.join(C.ROOT, "tmp", f"cross_seed_{args.seed}.csv")
    os.makedirs(os.path.dirname(temp_path), exist_ok=True)
    raw = generate(seed=args.seed, output_path=temp_path)
    scored = score(raw)

    truth = (scored["label"] != C.BENIGN_LABEL).to_numpy()
    risk_probability = scored["risk"].to_numpy() / 100.0
    bundle_thresholds = {
        name: values
        for name, values in joblib.load(C.MODEL_BUNDLE)["thresholds"].items()
    }
    operating = EV.operating_points(
        scored["risk"].to_numpy(), truth, thresholds=bundle_thresholds)
    label_to_idx = {label: index for index, label in enumerate(C.ALL_LABELS)}
    true_idx = scored["label"].map(label_to_idx).to_numpy()
    pred_idx = scored["pred_label"].map(label_to_idx).to_numpy()
    top_threshold = bundle_thresholds["top_1pct"]["threshold"]

    results = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "events": int(len(scored)),
        "attacks": int(truth.sum()),
        "attack_rate": float(truth.mean()),
        "ranking": EV.ranking_metrics(risk_probability, truth),
        "operating_points": operating,
        "classification": EV.classification_metrics(
            true_idx, pred_idx, C.ALL_LABELS),
        "cold_start": EV.cold_start_recall(
            scored["risk"].to_numpy(), truth,
            scored["is_cold_start"].to_numpy(),
            threshold=top_threshold),
        "concept_drift": EV.drift_false_positive(
            scored["risk"].to_numpy(), scored["scenario"].to_numpy(),
            truth, threshold=top_threshold),
        "method": "Unmodified saved seed-42 model bundle and validation "
                  "thresholds applied to independently generated seed.",
        "scope_note": "This tests entity-profile and campaign-draw variation "
                      "within the same documented generator family; it is not "
                      "external real-world validation.",
    }
    destination = os.path.join(C.ARTIFACT_DIR, "cross_seed_results.json")
    with open(destination, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    if os.path.exists(temp_path):
        os.remove(temp_path)
    print(
        f"[cross-seed] PR-AUC={results['ranking']['pr_auc']:.4f} "
        f"ROC-AUC={results['ranking']['roc_auc']:.4f} "
        f"macro-F1={results['classification']['macro_f1_attacks']:.4f}")
    print(f"[cross-seed] wrote {destination}")


if __name__ == "__main__":
    main()
