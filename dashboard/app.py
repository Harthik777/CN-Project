"""SentinelUEBA analyst console.

Run:
    streamlit run dashboard/app.py
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config as C
from src.feedback import append_feedback, load_feedback


st.set_page_config(
    page_title="SentinelUEBA | SOC Console",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      :root { --sentinel-red: #d3202f; --sentinel-ink: #17212b; }
      .block-container { padding-top: 1.25rem; padding-bottom: 2rem; }
      h1, h2, h3 { letter-spacing: 0 !important; }
      h1 { font-size: 1.65rem !important; color: var(--sentinel-ink); }
      h2 { font-size: 1.15rem !important; }
      div[data-testid="stMetric"] {
        border-top: 2px solid #dfe4e8;
        padding-top: 0.65rem;
      }
      div[data-testid="stMetric"]:first-child { border-top-color: var(--sentinel-red); }
      .stTabs [data-baseweb="tab-list"] { gap: 1.25rem; }
      .stTabs [data-baseweb="tab"] { padding-left: 0; padding-right: 0; }
      div[data-testid="stForm"] { border: 1px solid #dfe4e8; border-radius: 6px; }
    </style>
    """,
    unsafe_allow_html=True,
)

MITRE = {
    "brute_force": "T1110",
    "credential_stuffing": "T1110.004",
    "impossible_travel": "T1078",
    "lateral_movement": "T1021",
    "device_spoofing": "T1036",
    "low_and_slow_exfiltration": "T1030",
    "normal": "-",
}


@st.cache_data(show_spinner=False)
def load_artifacts():
    scored = pd.read_parquet(C.SCORED_PARQUET)
    scored["timestamp"] = pd.to_datetime(scored["timestamp"])
    with open(C.RESULTS_JSON, encoding="utf-8") as handle:
        metrics = json.load(handle)
    return scored, metrics


if not os.path.exists(C.SCORED_PARQUET) or not os.path.exists(C.RESULTS_JSON):
    st.error("Run `python run_all.py --fresh` to create the scored artifacts.")
    st.stop()

df, results = load_artifacts()
policy_labels = {
    "top_0.5pct": "Top 0.5% | maximum precision",
    "top_1pct": "Top 1% | precision first",
    "top_2pct": "Top 2% | balanced coverage",
    "top_5pct": "Top 5% | maximum coverage",
}
policy_names = [
    name for name in policy_labels if name in results["operating_points"]
]
st.sidebar.header("Operating policy")
policy = st.sidebar.selectbox(
    "Analyst alert budget",
    policy_names,
    index=policy_names.index("top_1pct"),
    format_func=policy_labels.get,
    help="Thresholds were fitted once on the validation window. Changing this "
         "control applies that frozen policy to the selected data window.",
)
selected_point = results["operating_points"][policy]
threshold = float(selected_point["threshold"])
threshold_label = f"{threshold:.4f}" if threshold < 1 else f"{threshold:.1f}"

st.title("SentinelUEBA")
st.caption(
    "Behavioural anomaly detection console | "
    f"Model v{results.get('project', {}).get('version', '2.1')} | "
    f"{policy_labels[policy]} | Threshold {threshold_label}/100"
)

metrics = st.columns(6)
metrics[0].metric("PR-AUC", f"{results['ranking']['pr_auc']:.3f}")
metrics[1].metric("ROC-AUC", f"{results['ranking']['roc_auc']:.3f}")
metrics[2].metric(
    "Precision",
    f"{selected_point['precision']:.1%}",
    help=f"At the validation-fitted {policy_labels[policy].split(' | ')[0].lower()} "
         "operating threshold.",
)
metrics[3].metric("Recall", f"{selected_point['recall']:.1%}")
metrics[4].metric(
    "False-positive rate",
    f"{selected_point['false_positive_rate']:.3%}",
)
metrics[5].metric(
    "Attack-type F1",
    f"{results['classification']['macro_f1_attacks']:.3f}",
)

st.sidebar.header("Scope")
split = st.sidebar.radio(
    "Data window", ["test", "validation", "all"], horizontal=True)
entity_types = st.sidebar.multiselect(
    "Entity type",
    sorted(df["entity_type"].unique()),
    default=sorted(df["entity_type"].unique()),
)
risk_floor = st.sidebar.slider(
    # Secondary analyst filter within the selected frozen operating policy.
    "Minimum risk (focus filter)", 0.0, 100.0, 0.0, 0.5)
predicted_types = st.sidebar.multiselect(
    "Predicted class",
    C.ALL_LABELS,
    default=C.ALL_LABELS,
    help="Wider alert budgets can include low-confidence review events whose "
         "most likely class remains normal. They stay visible so the queue count "
         "and false-positive trade-off remain honest.",
)
validation_view = st.sidebar.toggle(
    "Show ground truth", value=False,
    help="Evaluation-only field. Keep disabled in an operational SOC.")

scope = df.copy()
if split != "all":
    scope = scope[scope["split"] == split]
policy_total = int((scope["risk"] >= threshold).sum())
# Apply the selected validation-fitted policy first, then analyst focus filters.
scope = scope[
    (scope["risk"] >= threshold) &
    scope["entity_type"].isin(entity_types) &
    scope["pred_label"].isin(predicted_types) &
    (scope["risk"] >= risk_floor)
]

queue_tab, entity_tab, evaluation_tab, adaptation_tab = st.tabs(
    ["Alert queue", "Entity investigation", "Model evaluation", "Adaptation"])

with queue_tab:
    heading, count = st.columns([4, 1])
    heading.subheader("Prioritized alerts")
    count.metric(
        "Visible alerts", f"{len(scope):,}",
        help=f"{policy_total:,} events are flagged by the selected "
             f"{policy_labels[policy].split(' | ')[0].lower()} policy on the "
             f"'{split}' window; this count also reflects your focus filters.")

    alerts = scope.sort_values(["risk", "timestamp"], ascending=[False, False])
    queue_columns = [
        "timestamp", "event_id", "entity_id", "entity_type", "pred_label",
        "risk", "geo_city", "resource_accessed", "auth_result", "reason",
    ]
    if validation_view:
        queue_columns.append("label")
    queue = alerts.head(500)[queue_columns].copy()
    queue["risk"] = queue["risk"].round(1)
    queue = queue.rename(columns={
        "pred_label": "classification",
        "label": "ground_truth",
    })
    st.dataframe(
        queue,
        use_container_width=True,
        hide_index=True,
        height=390,
        column_config={
            "risk": st.column_config.ProgressColumn(
                "risk", min_value=0, max_value=100, format="%.1f"),
            "event_id": st.column_config.NumberColumn(format="%d"),
        },
    )

    if alerts.empty:
        st.info("No alerts match the current filters.")
    else:
        options = alerts["event_id"].astype(int).tolist()
        selected_id = st.selectbox(
            "Open alert",
            options,
            format_func=lambda event_id: (
                f"#{event_id} | "
                f"{alerts.loc[alerts.event_id == event_id, 'entity_id'].iloc[0]} | "
                f"{alerts.loc[alerts.event_id == event_id, 'pred_label'].iloc[0]}"
            ),
        )
        selected = alerts[alerts["event_id"] == selected_id].iloc[0]
        left, right = st.columns([3, 2])
        with left:
            st.subheader(f"Alert #{int(selected.event_id)}")
            st.info(selected.reason or "Off-profile behaviour")
            detail = pd.DataFrame({
                "Field": [
                    "Entity", "Role", "Source IP", "Location", "Resource",
                    "Authentication", "MITRE ATT&CK", "Baseline epoch",
                ],
                "Value": [
                    selected.entity_id, selected.role, selected.source_ip,
                    selected.geo_city, selected.resource_accessed,
                    selected.auth_result, MITRE.get(selected.pred_label, "-"),
                    int(selected.baseline_epoch),
                ],
            })
            st.dataframe(detail, hide_index=True, use_container_width=True)

        with right:
            st.subheader("Evidence")
            channels = pd.DataFrame({
                "channel": ["Autoencoder", "Isolation Forest", "Causal GRU",
                            "Adaptive unsupervised", "Classifier"],
                "score": [
                    selected.ae_score, selected.iso_score, selected.seq_score,
                    selected.adaptive_unsup, selected.attack_prob,
                ],
            })
            fig = px.bar(
                channels, x="score", y="channel", orientation="h",
                range_x=[0, 1], color="score",
                color_continuous_scale=["#d7dde2", "#d3202f"],
            )
            fig.update_layout(
                height=260, margin=dict(l=0, r=0, t=5, b=0),
                coloraxis_showscale=False, yaxis_title=None, xaxis_title=None,
            )
            st.plotly_chart(fig, use_container_width=True)

        feedback = load_feedback()
        existing = feedback[
            feedback["event_id"].astype(str) == str(int(selected.event_id))]
        if not existing.empty:
            latest = existing.iloc[-1]
            st.success(
                f"Disposition recorded: {latest.disposition} by {latest.analyst}")

        with st.form("analyst_disposition", clear_on_submit=True):
            st.subheader("Analyst disposition")
            form_columns = st.columns([2, 1, 3])
            disposition = form_columns[0].selectbox(
                "Decision",
                [
                    "confirmed_" + selected.pred_label,
                    "false_positive",
                    "expected_behavior",
                    "needs_investigation",
                ],
            )
            analyst = form_columns[1].text_input(
                "Analyst", value="campus_demo")
            note = form_columns[2].text_input("Case note")
            submitted = st.form_submit_button("Submit disposition")
            if submitted:
                append_feedback(
                    selected, disposition=disposition,
                    analyst=analyst, note=note)
                st.success(
                    "Disposition saved. It will be consumed by the next "
                    "auditable model refresh.")

with entity_tab:
    st.subheader("Entity investigation")
    ranked_entities = (
        df[df["split"] == "test"].groupby("entity_id")["risk"]
        .max().sort_values(ascending=False)
    )
    entity_id = st.selectbox("Entity", ranked_entities.index.tolist())
    entity = df[df["entity_id"] == entity_id].sort_values("timestamp")
    profile, timeline = st.columns([1, 3])
    with profile:
        st.metric("Maximum risk", f"{entity['risk'].max():.1f}")
        st.metric("Events", f"{len(entity):,}")
        st.metric("Alerts", f"{entity['is_alert'].sum():,}")
        st.metric("Baseline epochs", f"{entity['baseline_epoch'].max() + 1}")
        st.write(f"**Type:** {entity.entity_type.iloc[0]}")
        st.write(f"**Role:** {entity.role.iloc[0]}")
        st.write(f"**Recent location:** {entity.geo_city.iloc[-1]}")
    with timeline:
        figure = px.scatter(
            entity, x="timestamp", y="risk", color="pred_label",
            hover_data=[
                "event_id", "resource_accessed", "geo_city",
                "reason", "baseline_epoch",
            ],
            title=f"Risk history | {entity_id}",
        )
        figure.add_hline(
            y=threshold, line_dash="dash", line_color="#d3202f",
            annotation_text="operating threshold")
        figure.update_layout(
            height=430, legend_title_text="Classification",
            yaxis_range=[0, 102])
        st.plotly_chart(figure, use_container_width=True)

    st.dataframe(
        entity.sort_values("timestamp", ascending=False)[[
            "timestamp", "event_id", "pred_label", "risk", "geo_city",
            "resource_accessed", "reason", "baseline_epoch", "drift_alarm",
        ]].head(250),
        hide_index=True,
        use_container_width=True,
    )

with evaluation_tab:
    st.subheader("Untouched test evaluation")
    protocol = results["evaluation_protocol"]
    st.caption(
        f"{protocol['type']} | purge={protocol['purge_hours']}h | "
        "thresholds fitted on validation"
    )

    channel_rows = [
        {
            "channel": name.replace("_", " ").title(),
            "ROC-AUC": values["roc_auc"],
            "PR-AUC": values["pr_auc"],
        }
        for name, values in results["channel_metrics"].items()
    ]
    channel_frame = pd.DataFrame(channel_rows)
    chart = go.Figure()
    chart.add_bar(
        name="PR-AUC", x=channel_frame["channel"],
        y=channel_frame["PR-AUC"], marker_color="#d3202f")
    chart.add_bar(
        name="ROC-AUC", x=channel_frame["channel"],
        y=channel_frame["ROC-AUC"], marker_color="#667684")
    chart.update_layout(
        barmode="group", height=390, yaxis_range=[0, 1.05],
        margin=dict(l=0, r=0, t=20, b=0), legend_orientation="h")
    st.plotly_chart(chart, use_container_width=True)

    selected_strategy = results["fusion"]["selected_strategy"]
    st.info(
        f"Operational champion selected on validation: "
        f"{selected_strategy.replace('_', ' ')}")

    points = pd.DataFrame([
        {
            "policy": name.replace("top_", "top ").replace("pct", "%"),
            "validation threshold": point["threshold"],
            "realized test alert rate": point["realized_alert_rate"],
            "precision": point["precision"],
            "recall": point["recall"],
            "false-positive rate": point["false_positive_rate"],
            "false positives": point["false_positives"],
        }
        for name, point in results["operating_points"].items()
    ])
    st.dataframe(
        points, hide_index=True, use_container_width=True,
        column_config={
            "validation threshold": st.column_config.NumberColumn(format="%.2f"),
            "realized test alert rate": st.column_config.NumberColumn(format="%.2%%"),
            "precision": st.column_config.NumberColumn(format="%.3f"),
            "recall": st.column_config.NumberColumn(format="%.3f"),
            "false-positive rate": st.column_config.NumberColumn(format="%.4f"),
        },
    )

    probe_path = os.path.join(C.ARTIFACT_DIR, "real_data_probe.json")
    if os.path.exists(probe_path):
        with open(probe_path, encoding="utf-8") as handle:
            probe = json.load(handle)
        st.subheader("External evidence boundary")
        probe_metrics = st.columns(3)
        probe_metrics[0].metric(
            "Real telemetry holdout", f"{probe['test_events']:,} events")
        probe_metrics[1].metric(
            "Behaviour vs rule proxy", f"PR-AUC {probe['pr_auc']:.3f}")
        probe_metrics[2].metric("Protocol", "Chronological 60/40")
        st.caption(
            "SPEDIA Wazuh telemetry. The proxy label is rule severity, not attack "
            "ground truth. Low behavioural agreement is a negative-control result "
            "supporting hybrid signature + behavioural detection, not a real-data "
            "performance claim."
        )

    st.subheader("Attack classification")
    attack_rows = []
    for attack in C.ATTACK_TYPES:
        values = results["classification"]["per_class"][attack]
        attack_rows.append({"attack": attack, **values})
    st.dataframe(
        pd.DataFrame(attack_rows),
        hide_index=True,
        use_container_width=True,
        column_config={
            "precision": st.column_config.NumberColumn(format="%.3f"),
            "recall": st.column_config.NumberColumn(format="%.3f"),
            "f1": st.column_config.NumberColumn(format="%.3f"),
        },
    )

    cm = np.asarray(results["classification"]["confusion_matrix"])
    labels = results["classification"]["labels"]
    matrix = px.imshow(
        cm, x=labels, y=labels, text_auto=True, aspect="auto",
        labels={"x": "Predicted", "y": "Actual", "color": "Events"},
        color_continuous_scale="Reds",
    )
    matrix.update_layout(height=500)
    st.plotly_chart(matrix, use_container_width=True)

with adaptation_tab:
    st.subheader("Cold start and concept drift")
    adaptation_metrics = st.columns(5)
    cold = results["cold_start"]
    drift = results["concept_drift"]
    # Prefer the multi-seed cold-start mean; the single run has too few attacks (n=29) to be stable.
    _single = cold.get("cold_attack_recall_at_budget", 0)
    _stab_path = os.path.join(os.path.dirname(__file__), "..", "artifacts",
                              "cross_seed_stability.json")
    _cs_ms = None
    if os.path.exists(_stab_path):
        with open(_stab_path) as _sf:
            _cs_ms = json.load(_sf).get("cold_start_recall")
    if _cs_ms:
        adaptation_metrics[0].metric(
            "Cold-start recall (5-seed)",
            f"{_cs_ms['mean']:.1%}",
            help=f"Mean ± {_cs_ms['std']:.1%} across 5 seeds / 227 attacks. "
                 f"Single main run: {_single:.1%} on 29 attacks — too few to quote.")
    else:
        adaptation_metrics[0].metric("Cold-start recall", f"{_single:.1%}")
    adaptation_metrics[1].metric(
        "Cold-start FP rate",
        f"{cold.get('cold_false_positive_rate', 0):.3%}")
    adaptation_metrics[2].metric(
        "Benign-drift FP rate",
        f"{drift.get('drift_false_positive_rate', 0):.3%}")
    adaptation_metrics[3].metric(
        "Drift alarms", f"{drift.get('test_drift_alarms', 0):,}")
    adaptation_metrics[4].metric(
        "Re-baselined entities", f"{drift.get('entities_with_drift', 0):,}")

    drift_entities = (
        df[(df["split"] == "test") & (df["scenario"] == "insider_drift")]
        ["entity_id"].drop_duplicates().tolist()
    )
    if drift_entities:
        drift_entity = st.selectbox("Benign drift entity", drift_entities)
        drift_history = df[df["entity_id"] == drift_entity].sort_values("timestamp")
        drift_chart = px.line(
            drift_history, x="timestamp", y="risk",
            color="baseline_epoch", markers=True,
            title=f"Adaptive baseline history | {drift_entity}",
        )
        drift_chart.add_hline(
            y=threshold, line_dash="dash", line_color="#d3202f")
        drift_chart.update_layout(height=390, yaxis_range=[0, 102])
        st.plotly_chart(drift_chart, use_container_width=True)

    st.subheader("Analyst feedback audit")
    feedback = load_feedback()
    if feedback.empty:
        st.caption("No dispositions recorded.")
    else:
        st.dataframe(
            feedback.sort_values("submitted_at_utc", ascending=False),
            hide_index=True, use_container_width=True)
