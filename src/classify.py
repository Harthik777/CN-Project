"""
Deliverable 4 — supervised attack-type classifier.

A LightGBM gradient-boosted multiclass model that answers "not just anomalous,
but which attack category does this resemble?" (normal + the six attack types).

Model choice rationale (interview-ready):
  * Tabular, mixed-scale behavioural features -> gradient-boosted trees beat deep
    nets: stronger with less data, robust to feature scaling, and they expose
    exact feature attributions (SHAP) for the explainability layer.
  * Extreme class imbalance is handled with per-class balanced sample weights and
    evaluated with PR / per-class F1 (never raw accuracy).
"""
from __future__ import annotations

import numpy as np
import lightgbm as lgb
from sklearn.metrics import f1_score

import config as C
from src.risk import RULE_TO_LABEL


def balanced_weights(y):
    classes, counts = np.unique(y, return_counts=True)
    w = {c: len(y) / (len(classes) * cnt) for c, cnt in zip(classes, counts)}
    return np.array([w[v] for v in y], dtype=np.float32)


def train_classifier(X_train, y_train_idx, n_classes, X_valid=None,
                     y_valid_idx=None, verbose=True):
    sw = balanced_weights(y_train_idx)
    dtrain = lgb.Dataset(X_train, label=y_train_idx, weight=sw)
    params = dict(
        objective="multiclass", num_class=n_classes, metric="multi_logloss",
        learning_rate=0.08, num_leaves=48, min_data_in_leaf=40,
        feature_fraction=0.85, bagging_fraction=0.85, bagging_freq=1,
        max_depth=-1, seed=C.SEED, verbosity=-1, num_threads=1,
        deterministic=True, force_col_wise=True,
    )
    valid_sets = None
    callbacks = None
    if X_valid is not None and y_valid_idx is not None:
        dvalid = lgb.Dataset(X_valid, label=y_valid_idx, reference=dtrain)
        valid_sets = [dvalid]
        callbacks = [lgb.early_stopping(30, verbose=False)]
    model = lgb.train(
        params, dtrain, num_boost_round=350, valid_sets=valid_sets,
        callbacks=callbacks)
    if verbose:
        print(f"  [CLF] trained LightGBM rounds={model.current_iteration()} "
              f"classes={n_classes}")
    return model


def predict_proba(model, X):
    p = model.predict(X)
    # Keep float64: saturated attack probabilities need their remaining
    # precision so fixed-budget thresholds do not collapse into large tie blocks.
    return np.asarray(p, dtype=np.float64)


def apply_rule_overrides(pred_idx, rules, enabled_rules, label_to_idx):
    """Apply only rule-to-label overrides approved on validation data."""
    final = np.asarray(pred_idx).copy()
    for column, label in reversed(RULE_TO_LABEL):
        if column not in enabled_rules:
            continue
        final[rules[column].to_numpy() > 0.5] = label_to_idx[label]
    return final


def select_rule_overrides(y_true, pred_idx, rules, label_to_idx):
    """Greedily keep a rule override only when validation macro-F1 improves."""
    attack_indices = [label_to_idx[label] for label in C.ATTACK_TYPES]

    def score(prediction):
        return f1_score(
            y_true, prediction, labels=attack_indices,
            average="macro", zero_division=0)

    current = np.asarray(pred_idx).copy()
    current_score = score(current)
    enabled = []
    evidence = {}
    for column, label in RULE_TO_LABEL:
        fired = rules[column].to_numpy() > 0.5
        support = int(fired.sum())
        precision = float((np.asarray(y_true)[fired] == label_to_idx[label]).mean()) if support else 0.0
        candidate = current.copy()
        candidate[fired] = label_to_idx[label]
        candidate_score = score(candidate)
        accepted = support >= 5 and precision >= 0.80 and candidate_score > current_score + 1e-5
        evidence[column] = {
            "target": label,
            "support": support,
            "precision": precision,
            "macro_f1_if_applied": float(candidate_score),
            "accepted": bool(accepted),
        }
        if accepted:
            enabled.append(column)
            current = candidate
            current_score = candidate_score
    return enabled, evidence, float(current_score)
