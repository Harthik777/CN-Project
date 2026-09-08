"""Build the dependency-free offline SentinelUEBA console."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pandas as pd

import config as C


def _event(row):
    return {
        "id": int(row.event_id),
        "timestamp": str(row.timestamp),
        "entity": row.entity_id,
        "entity_type": row.entity_type,
        "role": row.role,
        "classification": row.pred_label,
        "truth": row.label,
        # Preserve threshold-level precision. Display formatting belongs in the UI;
        # rounding here can move an event across a validation-fitted policy boundary.
        "risk": float(row.risk),
        "source_ip": row.source_ip,
        "city": row.geo_city,
        "resource": row.resource_accessed,
        "auth": row.auth_result,
        "reason": row.reason,
        "baseline_epoch": int(row.baseline_epoch),
        "drift_alarm": bool(row.drift_alarm),
        "scores": {
            "Autoencoder": round(float(row.ae_score), 4),
            "Isolation Forest": round(float(row.iso_score), 4),
            "Causal GRU": round(float(row.seq_score), 4),
            "Adaptive": round(float(row.adaptive_unsup), 4),
            "Classifier": round(float(row.attack_prob), 4),
        },
    }


def build(build_frontend=True):
    with open(C.RESULTS_JSON, encoding="utf-8") as handle:
        results = json.load(handle)
    cold_ms = None
    real_probe = None
    stab_path = os.path.join(C.ARTIFACT_DIR, "cross_seed_stability.json")
    if os.path.exists(stab_path):
        with open(stab_path, encoding="utf-8") as sf:
            cold_ms = json.load(sf).get("cold_start_recall")
    probe_path = os.path.join(C.ARTIFACT_DIR, "real_data_probe.json")
    if os.path.exists(probe_path):
        with open(probe_path, encoding="utf-8") as pf:
            real_probe = json.load(pf)
    scored = pd.read_parquet(C.SCORED_PARQUET)
    test = scored[scored["split"] == "test"].copy()
    operating_points = results["operating_points"]
    # Ship every event reachable by the widest supported policy. The UI applies the
    # exact validation-fitted threshold for the selected budget; no rounded proxy or
    # synthetic queue count is used.
    widest_threshold = min(float(point["threshold"])
                           for point in operating_points.values())
    alerts = test[test["risk"] >= widest_threshold].sort_values(
        ["risk", "timestamp"], ascending=[False, False]).head(10000)

    top_entities = alerts["entity_id"].drop_duplicates().head(50)
    timeline = {}
    for entity in top_entities:
        rows = scored[scored["entity_id"] == entity].sort_values("timestamp").tail(180)
        timeline[entity] = [
            {
                "timestamp": str(row.timestamp),
                "risk": float(row.risk),
                "classification": row.pred_label,
                "baseline_epoch": int(row.baseline_epoch),
            }
            for row in rows.itertuples()
        ]

    payload = {
        "default_policy": "top_1pct",
        "threshold": results["thresholds"]["top_1pct"]["threshold"],
        "policy_alert_count": int(test["is_alert"].sum()),
        "kpis": {
            "pr_auc": results["ranking"]["pr_auc"],
            "roc_auc": results["ranking"]["roc_auc"],
            "precision": results["alert_budget"]["precision"],
            "recall": results["alert_budget"]["recall"],
            "fp_rate": results["alert_budget"]["false_positive_rate"],
            "macro_f1": results["classification"]["macro_f1_attacks"],
        },
        "selected_strategy": results["fusion"]["selected_strategy"],
        "cold_start": {
            "events": results["cold_start"]["cold_events"],
            # headline recall is the 5-seed mean (single run n=29 is too small to quote)
            "recall": (cold_ms["mean"] if cold_ms
                       else results["cold_start"]["cold_attack_recall_at_budget"]),
            "recall_std": (cold_ms["std"] if cold_ms else None),
            "recall_single_run": results["cold_start"]["cold_attack_recall_at_budget"],
            "recall_is_multiseed": bool(cold_ms),
            "false_positive_rate": results["cold_start"]["cold_false_positive_rate"],
        },
        "drift": {
            "test_drift_alarms": results["concept_drift"]["test_drift_alarms"],
            "drift_alarms": results["concept_drift"]["drift_alarms"],
            "entities_with_drift": results["concept_drift"]["entities_with_drift"],
        },
        "real_data_probe": real_probe,
        "channels": results["channel_metrics"],
        "operating_points": operating_points,
        "per_class": {
            attack: results["classification"]["per_class"][attack]
            for attack in C.ATTACK_TYPES
        },
        "alerts": [_event(row) for row in alerts.itertuples()],
        "timeline": timeline,
    }
    with open(os.path.join(C.ASSET_DIR, "dashboard_data.json"), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print(f"[console] wrote {os.path.join(C.ASSET_DIR, 'dashboard_data.json')}")

    frontend_dir = os.path.join(C.ROOT, "frontend")
    npm = shutil.which("npm")
    dependencies_ready = os.path.isdir(
        os.path.join(frontend_dir, "node_modules"))
    if build_frontend and npm and dependencies_ready:
        subprocess.run([npm, "run", "build"], cwd=frontend_dir, check=True)
    elif build_frontend:
        print(
            "[console] React data refreshed. Run `npm ci && npm run build` "
            "from frontend/ to rebuild the offline console.")


if __name__ == "__main__":
    build()
