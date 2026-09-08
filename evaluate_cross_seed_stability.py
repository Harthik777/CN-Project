"""
Reproducible multi-seed generalisation test.

Applies the FROZEN seed-42 model bundle and its validation-fitted thresholds to
several independently generated seeds (never used in training or selection) and
reports the mean +/- std of the headline metrics INCLUDING cold-start, so the
cold-start number is not judged on a single small sample.

    python evaluate_cross_seed_stability.py --seeds 101 202 303 404 505

Writes artifacts/cross_seed_stability.json.
"""
from __future__ import annotations

import argparse
import json
import os

import joblib
import numpy as np

import config as C
from src import evaluate as EV
from src.generate_data import generate
from src.inference import score

LABEL_TO_IDX = {label: i for i, label in enumerate(C.ALL_LABELS)}


def one_seed(seed, thresholds):
    raw = generate(seed=seed, output_path=os.path.join(C.ROOT, "tmp", f"stab_{seed}.csv"),
                   verbose=False)
    sc = score(raw)
    truth = (sc["label"] != C.BENIGN_LABEL).to_numpy()
    risk = sc["risk"].to_numpy()
    rk = EV.ranking_metrics(risk, truth)
    op = EV.operating_points(risk, truth, thresholds=thresholds)["top_1pct"]
    ti = sc["label"].map(LABEL_TO_IDX).to_numpy()
    pi = sc["pred_label"].map(LABEL_TO_IDX).to_numpy()
    cm = EV.classification_metrics(ti, pi, C.ALL_LABELS)
    # cold-start recall at the frozen top-1% threshold
    thr = thresholds["top_1pct"]["threshold"]
    cold_atk = sc["is_cold_start"].to_numpy() & truth
    cold_recall = float(((risk >= thr) & cold_atk).sum() / max(1, int(cold_atk.sum())))
    return dict(seed=int(seed), roc=rk["roc_auc"], pr=rk["pr_auc"],
                f1=cm["macro_f1_attacks"], prec=op["precision"], rec=op["recall"],
                fp=op["false_positives"], cold_recall=cold_recall,
                cold_attacks=int(cold_atk.sum()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[101, 202, 303, 404, 505])
    args = ap.parse_args()
    thresholds = {n: v for n, v in joblib.load(C.MODEL_BUNDLE)["thresholds"].items()}

    rows = [one_seed(s, thresholds) for s in args.seeds]
    for r in rows:
        print(f"seed {r['seed']}: ROC {r['roc']:.4f} PR {r['pr']:.4f} macroF1 {r['f1']:.3f} "
              f"top1 P {r['prec']:.3f} R {r['rec']:.3f} FP {r['fp']} "
              f"cold-recall {r['cold_recall']:.3f} (n={r['cold_attacks']})")

    def agg(key):
        a = np.array([r[key] for r in rows], dtype=float)
        return {"mean": float(a.mean()), "std": float(a.std()),
                "min": float(a.min()), "max": float(a.max())}

    out = dict(
        seeds=args.seeds, per_seed=rows,
        roc_auc=agg("roc"), pr_auc=agg("pr"), macro_f1=agg("f1"),
        top1_precision=agg("prec"), top1_recall=agg("rec"),
        top1_false_positives=agg("fp"), cold_start_recall=agg("cold_recall"),
        total_cold_attacks=int(sum(r["cold_attacks"] for r in rows)),
        method="Frozen seed-42 bundle and validation thresholds applied to independently "
               "generated seeds (never used in training or selection). Cold-start recall "
               "is reported per seed because a single run has too few cold-start attacks "
               "to be stable.")
    with open(os.path.join(C.ARTIFACT_DIR, "cross_seed_stability.json"), "w",
              encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print("\n=== 5-SEED STABILITY (frozen bundle, independent seeds) ===")
    for k in ["roc_auc", "pr_auc", "macro_f1", "top1_precision", "top1_recall",
              "top1_false_positives", "cold_start_recall"]:
        m = out[k]
        print(f"  {k:22s} {m['mean']:.4f} +/- {m['std']:.4f}  [{m['min']:.3f}, {m['max']:.3f}]")
    print(f"  total cold-start attacks across seeds: {out['total_cold_attacks']}")


if __name__ == "__main__":
    main()
