"""Leakage-resistant evaluation utilities for imbalanced anomaly detection."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

import config as C


def threshold_at_budget(reference_risk, budget):
    """Fit an alert threshold on a validation reference distribution."""
    values = np.asarray(reference_risk, dtype=float)
    return float(np.quantile(values, 1.0 - budget, method="higher"))


def fit_budget_thresholds(reference_risk, budgets=C.ALERT_BUDGETS):
    return {
        f"top_{budget * 100:g}pct": {
            "budget": float(budget),
            "threshold": threshold_at_budget(reference_risk, budget),
            "threshold_source": "validation_window",
        }
        for budget in budgets
    }


def alert_budget_metrics(risk, is_attack, budget=C.ALERT_BUDGET,
                         threshold=None):
    """Evaluate a fixed threshold; derive one only for backwards compatibility."""
    scores = np.asarray(risk, dtype=float)
    truth = np.asarray(is_attack, dtype=bool)
    fitted_here = threshold is None
    threshold = threshold_at_budget(scores, budget) if threshold is None else float(threshold)
    flagged = scores >= threshold
    tp = int((flagged & truth).sum())
    fp = int((flagged & ~truth).sum())
    attacks = int(truth.sum())
    benign = int((~truth).sum())
    return {
        "budget": float(budget),
        "threshold": threshold,
        "threshold_source": "evaluation_window" if fitted_here else "validation_window",
        "n_flagged": int(flagged.sum()),
        "realized_alert_rate": float(flagged.mean()),
        "precision": tp / max(1, tp + fp),
        "recall": tp / max(1, attacks),
        "false_positives": fp,
        "false_positive_rate": fp / max(1, benign),
    }


def operating_points(risk, is_attack, thresholds=None,
                     budgets=C.ALERT_BUDGETS):
    if thresholds is None:
        return {
            f"top_{budget * 100:g}pct": alert_budget_metrics(
                risk, is_attack, budget=budget)
            for budget in budgets
        }
    result = {}
    for name, fitted in thresholds.items():
        result[name] = alert_budget_metrics(
            risk, is_attack, budget=fitted["budget"],
            threshold=fitted["threshold"])
    return result


def ranking_metrics(risk, is_attack):
    truth = np.asarray(is_attack, dtype=bool)
    scores = np.asarray(risk, dtype=float)
    return {
        "roc_auc": float(roc_auc_score(truth, scores)),
        "pr_auc": float(average_precision_score(truth, scores)),
    }


def bootstrap_ranking_ci(risk, is_attack, groups, n_boot=200, seed=C.SEED):
    """Entity-cluster bootstrap confidence intervals for ROC-AUC and PR-AUC."""
    scores = np.asarray(risk)
    truth = np.asarray(is_attack, dtype=bool)
    groups = np.asarray(groups)
    unique = np.unique(groups)
    by_group = {group: np.where(groups == group)[0] for group in unique}
    rng = np.random.default_rng(seed)
    roc, pr = [], []
    for _ in range(n_boot):
        sampled = rng.choice(unique, size=len(unique), replace=True)
        idx = np.concatenate([by_group[group] for group in sampled])
        if np.unique(truth[idx]).size < 2:
            continue
        roc.append(roc_auc_score(truth[idx], scores[idx]))
        pr.append(average_precision_score(truth[idx], scores[idx]))

    def interval(values):
        return {
            "low": float(np.quantile(values, 0.025)),
            "high": float(np.quantile(values, 0.975)),
            "bootstrap_replicates": int(len(values)),
            "cluster": "entity_id",
        }

    return {"roc_auc": interval(roc), "pr_auc": interval(pr)}


def calibration_metrics(probability, is_attack, bins=10):
    probability = np.clip(np.asarray(probability, dtype=float), 0, 1)
    truth = np.asarray(is_attack, dtype=int)
    edges = np.linspace(0, 1, bins + 1)
    expected_error = 0.0
    rows = []
    for lower, upper in zip(edges[:-1], edges[1:]):
        include = ((probability >= lower) & (probability < upper)
                   if upper < 1 else (probability >= lower) & (probability <= upper))
        if not include.any():
            continue
        confidence = float(probability[include].mean())
        observed = float(truth[include].mean())
        weight = float(include.mean())
        expected_error += weight * abs(confidence - observed)
        rows.append({
            "lower": float(lower), "upper": float(upper),
            "count": int(include.sum()), "mean_risk": confidence,
            "observed_attack_rate": observed,
        })
    return {
        "brier_score": float(brier_score_loss(truth, probability)),
        "expected_calibration_error": float(expected_error),
        "bins": rows,
    }


def classification_metrics(y_true_idx, y_pred_idx, labels):
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true_idx, y_pred_idx, labels=list(range(len(labels))),
        zero_division=0)
    per_class = {}
    for index, label in enumerate(labels):
        per_class[label] = {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
        }
    macro = float(np.mean([per_class[label]["f1"] for label in C.ATTACK_TYPES]))
    matrix = confusion_matrix(
        y_true_idx, y_pred_idx, labels=list(range(len(labels)))).tolist()
    return {
        "per_class": per_class,
        "macro_f1_attacks": macro,
        "confusion_matrix": matrix,
        "labels": labels,
    }


def cold_start_recall(risk, is_attack, is_cold, budget=C.ALERT_BUDGET,
                      threshold=None):
    scores = np.asarray(risk)
    truth = np.asarray(is_attack, dtype=bool)
    cold = np.asarray(is_cold, dtype=bool)
    if cold.sum() == 0:
        return {"note": "no cold-start events in test"}
    threshold = (threshold_at_budget(scores, budget)
                 if threshold is None else float(threshold))
    flagged = scores >= threshold
    cold_attacks = cold & truth
    cold_benign = cold & ~truth
    return {
        "cold_events": int(cold.sum()),
        "cold_attack_events": int(cold_attacks.sum()),
        "cold_attack_recall_at_budget": float(
            (flagged & cold_attacks).sum() / max(1, cold_attacks.sum())),
        "cold_false_positive_rate": float(
            (flagged & cold_benign).sum() / max(1, cold_benign.sum())),
        "threshold_source": "validation_window" if threshold is not None else "evaluation_window",
    }


def drift_false_positive(risk, scenario, is_attack, budget=C.ALERT_BUDGET,
                         threshold=None):
    scores = np.asarray(risk)
    truth = np.asarray(is_attack, dtype=bool)
    scenario = np.asarray(scenario)
    drift = (scenario == "insider_drift") & (~truth)
    if drift.sum() == 0:
        return {"note": "no insider-drift events in test"}
    threshold = (threshold_at_budget(scores, budget)
                 if threshold is None else float(threshold))
    flagged = scores >= threshold
    return {
        "drift_events": int(drift.sum()),
        "drift_flagged": int((flagged & drift).sum()),
        "drift_false_positive_rate": float(
            (flagged & drift).sum() / max(1, drift.sum())),
    }


def per_attack_detection(risk, labels, threshold):
    scores = np.asarray(risk)
    labels = np.asarray(labels)
    flagged = scores >= threshold
    result = {}
    for attack in C.ATTACK_TYPES:
        target = labels == attack
        result[attack] = {
            "events": int(target.sum()),
            "recall_at_operating_threshold": float(
                (flagged & target).sum() / max(1, target.sum())),
        }
    return result


def slice_metrics(risk, is_attack, values):
    values = np.asarray(values)
    result = {}
    for value in np.unique(values):
        mask = values == value
        truth = np.asarray(is_attack)[mask]
        if truth.sum() == 0 or (~truth.astype(bool)).sum() == 0:
            continue
        result[str(value)] = {
            **ranking_metrics(np.asarray(risk)[mask], truth),
            "events": int(mask.sum()),
            "attacks": int(truth.sum()),
        }
    return result
