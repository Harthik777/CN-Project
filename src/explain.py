"""
Deliverable 5 — explainability layer.

A SOC analyst needs to know *why* an event was flagged, not just a score. We
provide two complementary explanations per alert:

  * RULE-DRIVEN reason codes  — plain-English statements tied to the deterministic
    rules ("impossible travel: 6,300 km in 1.1 h => 5,700 km/h"). High precision,
    instantly trustworthy.
  * SHAP feature attribution   — for the supervised classifier's predicted class,
    the top features pushing this event towards its attack label. Uses LightGBM's
    native SHAP (pred_contrib) so it is exact and fast, no extra fit required.
"""
from __future__ import annotations

import numpy as np

import config as C
from src.risk import RULE_COLUMNS

_RULE_TEXT = {
    "rule_impossible_travel": "impossible travel (implausible geo-velocity)",
    "rule_brute_force": "brute-force burst (many failed logins, one source)",
    "rule_device_spoofing": "device spoofing (fingerprint mismatch vs history)",
    "rule_credential_stuffing": "credential stuffing (one IP, many accounts, high failure)",
    "rule_lateral_movement": "lateral movement (unusual breadth of new resources)",
    "rule_exfiltration": "possible exfiltration (off-hours high-volume read)",
}

# Rule conditions are investigation guidance, not verified model counterfactuals.
_COUNTERFACTUAL = {
    "rule_impossible_travel": "review geo-velocity, VPN use and location accuracy",
    "rule_brute_force": "review the failure rate against the entity baseline",
    "rule_device_spoofing": "verify whether the fingerprint change was authorised",
    "rule_credential_stuffing": "review account fan-out and shared-IP context",
    "rule_lateral_movement": "verify access to the newly observed resources",
    "rule_exfiltration": "review off-hours volume and approved data transfers",
}


def rule_reasons(rules_df, feature_df=None):
    """Per row: quantified reasons and an actionable counterfactual."""
    fired, cfs = [], []
    arr = {c: rules_df[c].to_numpy() for c in RULE_COLUMNS}
    for i in range(len(rules_df)):
        hits = [c for c in RULE_COLUMNS if arr[c][i] > 0.5]
        descriptions = []
        for hit in hits:
            if feature_df is None:
                descriptions.append(_RULE_TEXT[hit])
                continue
            row = feature_df.iloc[i]
            if hit == "rule_impossible_travel":
                descriptions.append(
                    f"impossible travel: {row['geo_velocity_kmh']:.0f} km/h")
            elif hit == "rule_brute_force":
                descriptions.append(
                    "brute-force burst: "
                    f"{np.expm1(row['entity_event_count_5min']):.0f} events/5m, "
                    f"{row['entity_fail_rate_1h']:.0%} failures")
            elif hit == "rule_credential_stuffing":
                descriptions.append(
                    "credential stuffing: "
                    f"{np.expm1(row['ip_distinct_entities_1h']):.0f} accounts/IP, "
                    f"{row['ip_fail_rate_1h']:.0%} failures")
            elif hit == "rule_lateral_movement":
                descriptions.append(
                    "lateral movement: "
                    f"{row['session_breadth']:.0f} resources, "
                    f"{row['session_new_resource_rate']:.0%} new")
            elif hit == "rule_device_spoofing":
                descriptions.append(
                    "device fingerprint differs from established history")
            elif hit == "rule_exfiltration":
                descriptions.append(
                    "exfiltration pattern: "
                    f"24h off-hours volume log={row['offhour_bytes_24h_log']:.1f}, "
                    f"peer z={row['peer_bytes_z']:.1f}")
        fired.append(descriptions)
        cfs.append(_COUNTERFACTUAL[hits[0]] if hits else "")
    return fired, cfs


def shap_top_features(model, X, pred_idx, feat_names, k=3):
    """Top-k contributing features per row for the predicted class (LightGBM SHAP)."""
    n_feat = len(feat_names)
    contrib = model.predict(X, pred_contrib=True)          # (n, (n_feat+1)*n_class)
    contrib = np.asarray(contrib)
    n_class = contrib.shape[1] // (n_feat + 1)
    contrib = contrib.reshape(len(X), n_class, n_feat + 1)
    tops = []
    for i in range(len(X)):
        c = contrib[i, pred_idx[i], :n_feat]
        idx = np.argsort(np.abs(c))[::-1][:k]
        tops.append([(feat_names[j], float(c[j])) for j in idx])
    return tops


def compose_reason(fired_rules, shap_top, pred_label, counterfactual=""):
    """One human-readable explanation string per alert (with counterfactual)."""
    parts = []
    if fired_rules:
        parts.append("; ".join(fired_rules))
    if not fired_rules and shap_top:
        drivers = ", ".join(f"{n}" for n, _ in shap_top if _ > 0)
        if drivers:
            parts.append(f"behavioural deviation driven by {drivers}")
    label = pred_label if pred_label != C.BENIGN_LABEL else "anomaly"
    base = f"[{label}] " + (" | ".join(parts) if parts else "off-profile behaviour")
    if counterfactual:
        base += f" | Investigation guidance: {counterfactual}; benign status is not established"
    return base
