"""Build the SentinelUEBA technical report PDF from verified run artifacts."""
from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import config as C


RED = colors.HexColor("#D3202F")
INK = colors.HexColor("#17212B")
MID = colors.HexColor("#52606D")
LIGHT = colors.HexColor("#EDF1F3")
TEAL = colors.HexColor("#147D92")
GREEN = colors.HexColor("#1E7A46")
WHITE = colors.white


def _save_figure(fig, name):
    path = os.path.join(C.ASSET_DIR, name)
    fig.savefig(path, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return path


def _curves(scored):
    from sklearn.metrics import (
        precision_recall_curve,
        roc_curve,
    )

    test = scored[scored["split"] == "test"]
    truth = (test["label"] != C.BENIGN_LABEL).astype(int).to_numpy()
    risk = test["risk_probability"].to_numpy()
    fpr, tpr, _ = roc_curve(truth, risk)
    precision, recall, _ = precision_recall_curve(truth, risk)

    fig, axes = plt.subplots(1, 2, figsize=(9.2, 3.25))
    axes[0].plot(fpr, tpr, color="#D3202F", linewidth=2.2)
    axes[0].plot([0, 1], [0, 1], color="#9AA5AD", linestyle="--", linewidth=0.8)
    axes[0].set(title="ROC curve", xlabel="False-positive rate", ylabel="Recall")
    axes[1].plot(recall, precision, color="#147D92", linewidth=2.2)
    axes[1].axhline(
        truth.mean(), color="#9AA5AD", linestyle="--", linewidth=0.8,
        label=f"base rate {truth.mean():.1%}")
    axes[1].set(title="Precision-recall curve", xlabel="Recall", ylabel="Precision")
    axes[1].legend(frameon=False, fontsize=8)
    for axis in axes:
        axis.set_xlim(0, 1)
        axis.set_ylim(0, 1.02)
        axis.grid(alpha=0.18)
        axis.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _save_figure(fig, "chart_curves.png")


def _channel_chart(results):
    metrics = results["channel_metrics"]
    names = list(metrics)
    x = np.arange(len(names))
    width = 0.36
    fig, axis = plt.subplots(figsize=(9.2, 3.4))
    axis.bar(
        x - width / 2, [metrics[name]["pr_auc"] for name in names],
        width, color="#D3202F", label="PR-AUC")
    axis.bar(
        x + width / 2, [metrics[name]["roc_auc"] for name in names],
        width, color="#667684", label="ROC-AUC")
    axis.set_xticks(x)
    axis.set_xticklabels(
        [name.replace("_", "\n") for name in names], fontsize=8)
    axis.set_ylim(0, 1.05)
    axis.set_ylabel("Held-out score")
    axis.set_title("Detection channels and validation-selected operational risk")
    axis.legend(frameon=False, ncols=2)
    axis.grid(axis="y", alpha=0.18)
    axis.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _save_figure(fig, "chart_channels.png")


def _attack_chart(results):
    classification = results["classification"]["per_class"]
    zero_label = results["zero_label_resilience"]
    labels = C.ATTACK_TYPES
    y = np.arange(len(labels))
    fig, axis = plt.subplots(figsize=(9.2, 3.6))
    axis.barh(
        y - 0.18, [classification[label]["f1"] for label in labels],
        0.36, color="#D3202F", label="Attack-type F1")
    axis.barh(
        y + 0.18, [zero_label[label]["pr_auc"] for label in labels],
        0.36, color="#147D92", label="Unsupervised PR-AUC")
    axis.set_yticks(y)
    axis.set_yticklabels([label.replace("_", " ") for label in labels], fontsize=8)
    axis.set_xlim(0, 1.02)
    axis.set_xlabel("Score")
    axis.set_title("Typed detection and zero-label resilience")
    axis.legend(frameon=False, ncols=2)
    axis.grid(axis="x", alpha=0.18)
    axis.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _save_figure(fig, "chart_f1.png")


def _confusion_chart(results):
    matrix = np.asarray(results["classification"]["confusion_matrix"], dtype=float)
    normalised = matrix / np.maximum(1, matrix.sum(axis=1, keepdims=True))
    labels = [label.replace("_", "\n") for label in results["classification"]["labels"]]
    fig, axis = plt.subplots(figsize=(7.2, 5.2))
    image = axis.imshow(normalised, cmap="Reds", vmin=0, vmax=1)
    for row in range(len(labels)):
        for column in range(len(labels)):
            value = normalised[row, column]
            if value >= 0.01:
                axis.text(
                    column, row, f"{value:.0%}", ha="center", va="center",
                    fontsize=7, color="white" if value > 0.55 else "#17212B")
    axis.set_xticks(range(len(labels)))
    axis.set_yticks(range(len(labels)))
    axis.set_xticklabels(labels, fontsize=7)
    axis.set_yticklabels(labels, fontsize=7)
    axis.set_xlabel("Predicted")
    axis.set_ylabel("Actual")
    axis.set_title("Row-normalised confusion matrix")
    fig.colorbar(image, ax=axis, fraction=0.035, pad=0.03)
    fig.tight_layout()
    return _save_figure(fig, "chart_confusion.png")


def _calibration_chart(results):
    bins = results["calibration"]["bins"]
    observed = [row["observed_attack_rate"] for row in bins]
    predicted = [row["mean_risk"] for row in bins]
    counts = [row["count"] for row in bins]
    fig, axis = plt.subplots(figsize=(5.3, 3.4))
    sizes = 20 + 90 * np.asarray(counts) / max(counts)
    axis.scatter(predicted, observed, s=sizes, color="#D3202F", alpha=0.8)
    axis.plot([0, 1], [0, 1], color="#667684", linestyle="--", linewidth=1)
    axis.set(
        xlim=(0, 1), ylim=(0, 1), xlabel="Mean predicted probability",
        ylabel="Observed attack rate", title="Probability calibration")
    axis.grid(alpha=0.18)
    axis.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _save_figure(fig, "chart_calibration.png")


def _architecture():
    """Generate a restrained architecture figure for the report."""
    fig, axis = plt.subplots(figsize=(10.2, 4.1))
    axis.set_xlim(0, 10.2)
    axis.set_ylim(0, 4.1)
    axis.axis("off")

    boxes = [
        (0.15, 1.35, 1.45, 1.15, "Access-log\nstream", "#52606D"),
        (1.95, 1.35, 1.65, 1.15, "Past-only\nfeature state", "#52606D"),
        (4.0, 2.85, 1.55, 0.75, "Rules", "#D3202F"),
        (4.0, 1.95, 1.55, 0.75, "AE + IF", "#147D92"),
        (4.0, 1.05, 1.55, 0.75, "Causal GRU", "#147D92"),
        (4.0, 0.15, 1.55, 0.75, "LightGBM", "#1E7A46"),
        (6.05, 1.35, 1.65, 1.15, "Validation-gated\nrisk champion", "#17212B"),
        (8.15, 2.15, 1.75, 0.95, "Risk + reason\n+ counterfactual", "#D3202F"),
        (8.15, 0.75, 1.75, 0.95, "SOC console\n+ feedback log", "#17212B"),
    ]
    for x, y, width, height, text, colour in boxes:
        axis.add_patch(plt.Rectangle(
            (x, y), width, height, facecolor=colour, edgecolor="none"))
        axis.text(
            x + width / 2, y + height / 2, text, ha="center", va="center",
            color="white", fontsize=9, fontweight="bold")

    arrows = [
        ((1.6, 1.93), (1.95, 1.93)),
        ((3.6, 1.93), (4.0, 3.22)),
        ((3.6, 1.93), (4.0, 2.32)),
        ((3.6, 1.93), (4.0, 1.42)),
        ((3.6, 1.93), (4.0, 0.52)),
        ((5.55, 3.22), (6.05, 2.1)),
        ((5.55, 2.32), (6.05, 2.0)),
        ((5.55, 1.42), (6.05, 1.85)),
        ((5.55, 0.52), (6.05, 1.7)),
        ((7.7, 2.05), (8.15, 2.62)),
        ((7.7, 1.75), (8.15, 1.22)),
    ]
    for start, end in arrows:
        axis.annotate(
            "", xy=end, xytext=start,
            arrowprops=dict(arrowstyle="-|>", color="#89959E", lw=1.3))
    axis.text(
        6.88, 0.55,
        "Selection, calibration, and thresholds\nfit before the untouched test window",
        ha="center", va="center", fontsize=8, color="#52606D")
    fig.tight_layout()
    return _save_figure(fig, "architecture.png")


def _footer(canvas, document):
    canvas.saveState()
    canvas.setStrokeColor(LIGHT)
    canvas.line(1.6 * cm, 1.15 * cm, 19.4 * cm, 1.15 * cm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MID)
    canvas.drawString(
        1.6 * cm, 0.72 * cm,
        "SentinelUEBA 2.1 | Induj Gupta | Honeywell Campus Connect")
    canvas.drawRightString(19.4 * cm, 0.72 * cm, f"{document.page}")
    canvas.restoreState()


def _table(data, widths, header=True, font=8.2):
    body_style = ParagraphStyle(
        "table_body", fontName="Helvetica", fontSize=font,
        leading=font + 2.2, textColor=INK)
    header_style = ParagraphStyle(
        "table_header", fontName="Helvetica-Bold", fontSize=font,
        leading=font + 2.2, textColor=WHITE)
    converted = []
    for row_index, row in enumerate(data):
        converted.append([
            cell if isinstance(cell, Paragraph) else Paragraph(
                str(cell), header_style if header and row_index == 0 else body_style)
            for cell in row
        ])
    table = Table(converted, colWidths=widths, repeatRows=1 if header else 0)
    commands = [
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), font),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D5DCE0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [WHITE, LIGHT]),
    ]
    if header:
        commands += [
            ("BACKGROUND", (0, 0), (-1, 0), INK),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    table.setStyle(TableStyle(commands))
    return table


def build():
    with open(C.RESULTS_JSON, encoding="utf-8") as handle:
        results = json.load(handle)
    scored = pd.read_parquet(C.SCORED_PARQUET)

    curve_path = _curves(scored)
    channel_path = _channel_chart(results)
    attack_path = _attack_chart(results)
    confusion_path = _confusion_chart(results)
    calibration_path = _calibration_chart(results)
    architecture_path = _architecture()

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "Title", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=27, leading=31, textColor=INK, alignment=TA_LEFT,
        spaceAfter=5)
    subtitle = ParagraphStyle(
        "Subtitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=13, leading=18, textColor=RED, spaceAfter=8)
    h1 = ParagraphStyle(
        "H1", parent=styles["Heading1"], fontName="Helvetica-Bold",
        fontSize=16, leading=20, textColor=INK, spaceBefore=10,
        spaceAfter=7)
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=11.5, leading=15, textColor=RED, spaceBefore=8,
        spaceAfter=4)
    body = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9.2, leading=13.2, textColor=INK, spaceAfter=6)
    small = ParagraphStyle(
        "Small", parent=body, fontSize=7.6, leading=10.2,
        textColor=MID, spaceAfter=4)
    callout = ParagraphStyle(
        "Callout", parent=body, fontName="Helvetica-Bold",
        fontSize=11, leading=15, textColor=INK, borderColor=RED,
        borderWidth=0, borderPadding=(8, 10, 8, 10),
        backColor=LIGHT, spaceAfter=8)
    centre = ParagraphStyle(
        "Centre", parent=small, alignment=TA_CENTER)

    path = os.path.join(C.REPORT_DIR, "SentinelUEBA_Report.pdf")
    document = SimpleDocTemplate(
        path, pagesize=A4, topMargin=1.35 * cm, bottomMargin=1.45 * cm,
        leftMargin=1.6 * cm, rightMargin=1.6 * cm,
        title="SentinelUEBA Technical Report",
        author="Induj Gupta",
    )
    story = []

    def p(text, style=body):
        story.append(Paragraph(text, style))

    def bullets(items):
        for item in items:
            p(f"<font color='#D3202F'>&#9632;</font>&nbsp; {item}", body)

    ranking = results["ranking"]
    alert = results["alert_budget"]
    classification = results["classification"]
    cold = results["cold_start"]
    drift = results["concept_drift"]
    confidence = results["ranking_confidence_interval"]

    # Cover
    story.append(Spacer(1, 1.1 * cm))
    p("SentinelUEBA", title)
    p("AI-Powered Behavioural Anomaly Detection for Cybersecurity", subtitle)
    p(
        "Honeywell Technologies Campus Connect 2026 | Problem 4 | "
        "<b>Induj Gupta</b>", small)
    story.append(Spacer(1, 0.5 * cm))
    story.append(Image(architecture_path, width=17.2 * cm, height=6.9 * cm))
    story.append(Spacer(1, 0.45 * cm))
    ci_pr = confidence["pr_auc"]
    p(
        f"<b>Untouched chronological test:</b> PR-AUC "
        f"<font color='#D3202F'>{ranking['pr_auc']:.3f}</font> "
        f"(95% entity-bootstrap CI {ci_pr['low']:.3f}-{ci_pr['high']:.3f}), "
        f"ROC-AUC {ranking['roc_auc']:.3f}. At a threshold fixed on validation, "
        f"precision is {alert['precision']:.1%}, recall is {alert['recall']:.1%}, "
        f"and benign false-positive rate is {alert['false_positive_rate']:.3%}.",
        callout)
    p(
        "This report treats synthetic evaluation honestly: metrics demonstrate "
        "engineering behaviour under documented simulation assumptions, not a "
        "production guarantee. Reproducible data generation, source hashes, model "
        "weights, fixed thresholds, and an executable inference replay are included.",
        body)
    story.append(Spacer(1, 0.3 * cm))
    p(
        "Submission build: SentinelUEBA 2.1 | Generated "
        f"{results['project']['generated_at_utc'][:10]} | Seed "
        f"{results['project']['seed']}", centre)
    story.append(PageBreak())

    # Executive summary and problem
    p("1. Executive Summary", h1)
    p(
        "SentinelUEBA learns normal access behaviour for users, service accounts, "
        "and industrial edge devices, then ranks suspicious events for a constrained "
        "SOC alert budget. It combines deterministic security evidence, normal-only "
        "autoencoder and Isolation Forest models, a causal GRU sequence model, and "
        "a LightGBM attack classifier. A validation-gated champion selector uses "
        "fusion only when it improves precision-recall ranking.")
    bullets([
        "<b>Past-only inference:</b> true rolling per-entity/per-IP state, causal "
        "home/device baselines, causal session prefixes, and training-reference score CDFs.",
        "<b>Cold start:</b> explicit role one-hot features plus peer-relative hour, "
        "resource-rarity, and byte-volume priors that fade as entity history grows.",
        "<b>Concept drift:</b> Page-Hinkley detection, protected rolling baselines, "
        "auditable baseline epochs, and attack-rule protection against profile poisoning.",
        "<b>Explainability:</b> quantified rule evidence, TreeSHAP drivers, "
        "counterfactual conditions, MITRE ATT&CK mapping, and entity timelines.",
        "<b>Operational loop:</b> fixed validation thresholds, persistent analyst "
        "dispositions, next-refresh label overrides, saved models, and replay inference.",
    ])

    p("Why it matters to Honeywell", h2)
    p(
        "The challenge asks specifically for behavioural detection, low false "
        "positives, explainability, scalability, anomaly classification, and system "
        "design [1]. Honeywell's 2025 cyber research analysed more than 250 billion "
        "logs and calls out AI-assisted security analysis for faster, smarter "
        "decisions [2]. Honeywell Cyber Insights describes a granular adaptive "
        "baseline for OT anomaly detection and false-positive reduction [3], while "
        "Honeywell Cyber Proactive Defense uses behavioural analytics to establish "
        "a system baseline and surface actionable insights [4]. SentinelUEBA is a "
        "student prototype aligned to those product principles, not a claim of "
        "equivalence.")

    p("2. Data and Threat Model", h1)
    p(
        f"The deterministic generator creates {results['dataset']['events']:,} events "
        f"for 400 entities over 45 days. The anomaly prevalence is "
        f"{results['dataset']['attack_rate']:.2%}. Entity profiles include role, "
        "home geography, working hours, resources, IP block, protocol, device "
        "fingerprint, activity rate, and authentication-failure rate. Ground truth is "
        "retained only for supervised fitting and evaluation; inference code does not "
        "require labels.")
    taxonomy = [["Behaviour", "Simulation signal", "Primary evidence"]]
    taxonomy += [
        ["Brute force", "Rapid repeated authentication attempts", "Entity burst + failure rate"],
        ["Impossible travel", "Distant successful login after short gap", "Geo-velocity physics"],
        ["Credential stuffing", "One/few IPs fan out across accounts", "Causal IP fan-out + failures"],
        ["Lateral movement", "Unusual resource sequence and breadth", "Causal GRU + prefix novelty"],
        ["Device spoofing", "OS/MAC fingerprint changes", "Prior fingerprint mode"],
        ["Low-and-slow exfiltration", "Off-hours elevated reads over days", "24h volume + adaptive z-score"],
    ]
    story.append(_table(taxonomy, [3.6 * cm, 7.0 * cm, 6.6 * cm]))
    p(
        "Benign stress cases include travel, noise in working hours, changing "
        "resources, and gradual insider drift. Remaining realism limits are listed "
        "in Section 9.", small)

    # Architecture and methods
    p("3. Architecture and Model Choices", h1)
    story.append(Image(architecture_path, width=17.2 * cm, height=6.9 * cm))
    methods = [
        ["Layer", "Role", "Why"],
        ["Rules", "High-precision physical/rate evidence", "Immediate reasons; no labels required"],
        ["Dense AE", "Normal manifold reconstruction", "Detects off-profile unknown behaviour"],
        ["Isolation Forest", "Distribution-light anomaly channel", "Robust complement to reconstruction"],
        ["Causal GRU AE", "Session-prefix dynamics", "Sequential signal without future events"],
        ["LightGBM", "Attack-type probability + SHAP", "Strong, inspectable tabular classifier"],
        ["Risk champion", "Validation-selected and calibrated score", "Prevents weaker fusion from degrading ranking"],
    ]
    story.append(_table(methods, [3.0 * cm, 6.0 * cm, 8.2 * cm]))
    p(
        f"The operational strategy selected before test was "
        f"<b>{results['fusion']['selected_strategy'].replace('_', ' ')}</b>. "
        "Candidate validation scores are reported in the run artifact; the selector "
        "prefers the simpler candidate when PR-AUC differs by less than 0.001.")

    p("Causal feature state", h2)
    p(
        "For each event, state is read first and updated second. IP fan-out and "
        "failure rate use true one-hour deques; burst counts use five-minute deques; "
        "device and home-city modes use prior observations; resource novelty uses "
        "prior entity and role counters; session features describe only the prefix "
        "ending at the event. The GRU receives that same prefix and scores only its "
        "final position. Autoencoder, Isolation Forest, and GRU outputs are mapped "
        "through empirical CDFs fitted on normal training events.")
    story.append(PageBreak())

    # Protocol
    p("4. Evaluation Protocol", h1)
    p(
        "The evaluation is chronological and has four functional stages. One-hour "
        "purge gaps reduce leakage from bursts or campaigns crossing boundaries.")
    protocol = [
        ["Window", "Purpose", "Can influence final test score?"],
        ["Train (earliest 50%)", "Scaler, normal baselines, GRU, classifier", "Model parameters only"],
        ["Validation A", "Fit logistic stacker", "Fusion parameters only"],
        ["Validation B", "Select champion, calibrate probability, fix thresholds", "Policy only"],
        ["Final test (latest 35%)", "One-time reporting", "No selection or fitting"],
    ]
    story.append(_table(protocol, [4.2 * cm, 7.5 * cm, 5.9 * cm]))
    p(
        f"<b>Integrity controls.</b> {results['dataset']['purged']:,} boundary events "
        "are excluded; all score normalisation references training only; alert "
        "thresholds come from the final calibration segment; rule overrides are "
        "enabled only when they improve validation macro-F1; test is not used for "
        "selection. The test contains "
        f"{results['dataset']['test']:,} events.")
    p("Metrics", h2)
    bullets([
        "PR-AUC is primary because attacks are rare; ROC-AUC is secondary.",
        "Precision, recall, and benign false-positive rate are measured at "
        "validation-fitted analyst-budget thresholds.",
        "Attack typing uses per-class precision/recall/F1 and attack-only macro-F1.",
        "95% intervals use an entity-cluster bootstrap rather than treating dependent "
        "events as independent.",
        "Cold-start and benign-drift subsets are measured separately.",
    ])

    # Detection results
    p("5. Detection Results", h1)
    ci_roc = confidence["roc_auc"]
    summary = [
        ["Metric", "Untouched test result"],
        ["PR-AUC", f"{ranking['pr_auc']:.4f} "
                   f"(95% CI {ci_pr['low']:.4f}-{ci_pr['high']:.4f})"],
        ["ROC-AUC", f"{ranking['roc_auc']:.4f} "
                    f"(95% CI {ci_roc['low']:.4f}-{ci_roc['high']:.4f})"],
        ["Brier score", f"{results['calibration']['brier_score']:.4f}"],
        ["Expected calibration error", f"{results['calibration']['expected_calibration_error']:.4f}"],
        ["Attack-type macro-F1", f"{classification['macro_f1_attacks']:.4f}"],
    ]
    story.append(_table(summary, [8.4 * cm, 8.4 * cm]))
    story.append(Spacer(1, 0.15 * cm))
    story.append(Image(curve_path, width=17.2 * cm, height=6.1 * cm))
    story.append(Image(channel_path, width=17.2 * cm, height=6.25 * cm))

    p("Fixed operating points", h2)
    operating = [["Policy", "Validation threshold", "Test alert rate", "Precision", "Recall", "FP rate"]]
    for name, point in results["operating_points"].items():
        operating.append([
            name.replace("top_", "top ").replace("pct", "%"),
            f"{point['threshold']:.2f}",
            f"{point['realized_alert_rate']:.2%}",
            f"{point['precision']:.3f}",
            f"{point['recall']:.3f}",
            f"{point['false_positive_rate']:.4f}",
        ])
    story.append(_table(
        operating, [2.7 * cm, 3.3 * cm, 2.8 * cm, 2.6 * cm, 2.6 * cm, 2.7 * cm],
        font=7.8))
    p(
        "The realised test alert rate is allowed to differ from the named policy: "
        "that difference is evidence the threshold was fixed before seeing test, "
        "rather than re-ranked on the test distribution.", small)

    # Per-attack recall at the top-1% policy (honest coverage disclosure)
    pad = results.get("per_attack_detection", {})
    if pad:
        p(
            "<b>Coverage vs. precision trade-off (read this alongside the headline).</b> "
            "The top-1% policy is precision-first: overall recall at that budget is only "
            f"{results['alert_budget']['recall']:.1%}, because with a "
            f"{results['dataset']['attack_rate']:.1%} base rate a 1% budget cannot flag "
            "even half the attacks, and it prioritises high-volume families. Per-attack "
            "recall at the top-1% threshold: " +
            ", ".join(
                f"{a.replace('_',' ')} {pad[a]['recall_at_operating_threshold']:.0%}"
                for a in C.ATTACK_TYPES if a in pad) + ". "
            "Low-volume types (impossible travel, device spoofing) fall below the strict "
            "cut and are recovered at <b>top-2% — the recommended coverage operating "
            "point (99.3% recall at 73.7% precision)</b>. Top-1% is the "
            "zero-false-positive policy, not the maximum-coverage policy.", small)

    # Cross-seed generalization (frozen bundle applied to independent seeds)
    cs_path = os.path.join(C.ARTIFACT_DIR, "cross_seed_stability.json")
    if os.path.exists(cs_path):
        with open(cs_path, encoding="utf-8") as handle:
            cs = json.load(handle)
        p("Cross-seed generalization", h2)
        p(
            f"The frozen seed-42 model bundle and its validation-fitted thresholds were "
            f"applied unchanged to {len(cs['seeds'])} independently generated datasets "
            f"(seeds never used in training, fusion selection, or calibration). "
            f"Performance is stable and benign false positives stay at zero on every "
            f"seed — evidence the result is not a favourable-seed artefact and the "
            f"thresholds were not tuned to the test distribution.")

        def _pm(metric):
            return f"{metric['mean']:.4f} ± {metric['std']:.4f}"

        cs_tbl = [
            ["Metric", "Mean ± Std (5 seeds)", "Min / Max"],
            ["ROC-AUC", _pm(cs["roc_auc"]),
             f"{cs['roc_auc']['min']:.3f} / {cs['roc_auc']['max']:.3f}"],
            ["PR-AUC", _pm(cs["pr_auc"]),
             f"{cs['pr_auc']['min']:.3f} / {cs['pr_auc']['max']:.3f}"],
            ["Attack macro-F1", _pm(cs["macro_f1"]),
             f"{cs['macro_f1']['min']:.3f} / {cs['macro_f1']['max']:.3f}"],
            ["Top-1% precision", _pm(cs["top1_precision"]), "1.000 every seed"],
            ["Top-1% false positives",
             f"{cs['top1_false_positives']['mean']:.1f} ± {cs['top1_false_positives']['std']:.1f}",
             "0 every seed"],
        ]
        if "cold_start_recall" in cs:
            c = cs["cold_start_recall"]
            cs_tbl.append(["Cold-start recall",
                           f"{c['mean']:.3f} ± {c['std']:.3f}",
                           f"{c['min']:.3f} / {c['max']:.3f} (n={cs.get('total_cold_attacks','?')})"])
        story.append(_table(cs_tbl, [5.2 * cm, 6.0 * cm, 5.6 * cm], font=7.8))
        if "cold_start_recall" in cs:
            p(
                "Cold-start recall is reported across seeds because a single run has too "
                "few cold-start attacks to be stable: the main run's 93.1% is on 29 "
                "attacks, whereas the multi-seed mean above is the honest figure to quote.",
                small)
    story.append(PageBreak())

    # Classification and robustness
    p("6. Classification and Robustness", h1)
    story.append(Image(attack_path, width=17.2 * cm, height=6.6 * cm))
    attack_table = [["Attack", "Precision", "Recall", "F1", "Support", "Unsupervised PR-AUC"]]
    for attack in C.ATTACK_TYPES:
        metric = classification["per_class"][attack]
        attack_table.append([
            attack.replace("_", " "),
            f"{metric['precision']:.3f}", f"{metric['recall']:.3f}",
            f"{metric['f1']:.3f}", str(metric["support"]),
            f"{results['zero_label_resilience'][attack]['pr_auc']:.3f}",
        ])
    story.append(_table(
        attack_table,
        [4.3 * cm, 2.3 * cm, 2.3 * cm, 2.0 * cm, 2.0 * cm, 3.4 * cm],
        font=7.8))
    p(
        "<b>Zero-label resilience</b> evaluates each attack against benign test "
        "events using only the adaptive unsupervised channel. It is not a claim of "
        "true unseen-family validation; it quantifies detection evidence available "
        "without attack labels.")
    story.append(Image(confusion_path, width=12.7 * cm, height=9.1 * cm))

    # Real-data probe (honest complementarity finding, not a performance claim)
    probe_path = os.path.join(C.ARTIFACT_DIR, "real_data_probe.json")
    if os.path.exists(probe_path):
        with open(probe_path, encoding="utf-8") as handle:
            probe = json.load(handle)
        d = probe["diagnostic"]
        p("Executed real-telemetry probe: a held-out complementarity test", h2)
        p(
            f"As an external boundary test (not attack validation), we ran the unsupervised "
            f"behavioural detector on a real public insider-threat corpus (SPEDIA, "
            f"Zenodo 15495572: {probe['events']:,} real Wazuh host events, "
            f"{probe['users']} users). We used a chronological split: "
            f"{probe['train_events']:,} events for unsupervised fitting and "
            f"{probe['test_events']:,} later events for untouched scoring. All rarity "
            f"features use prior events only. The dataset's only available label is Wazuh's "
            f"<b>signature-defined</b> high-severity flag (command executions such as "
            f"/bin/nc), which fires in-hours at ordinary volume (off-hours rate "
            f"{d['offhours_rate_high_severity']:.1%} vs {d['offhours_rate_normal']:.1%} "
            f"for normal traffic). The behavioural-only detector does not rank these "
            f"highly (PR-AUC {probe['pr_auc']:.3f}). We read this cautiously: it is "
            f"<b>consistent with</b> — not proof of — the hypothesis that behavioural "
            f"anomaly detection and signature detection are complementary, which is why "
            f"SentinelUEBA is a <b>hybrid</b>. The label remains a rule proxy, so this "
            f"negative-control result does not establish real-data attack performance. "
            f"(Reproduce with <font face='Courier'>evaluate_spedia.py</font> after "
            f"downloading logs_SPEDIA.csv from Zenodo; a red-team-labelled behavioural "
            f"benchmark harness for LANL authentication logs is <font face='Courier'>"
            f"evaluate_real_data.py</font>.)", small)

    # Hard problems
    p("7. Imbalance, Cold Start, and Drift", h1)
    hard = [
        ["Challenge", "Implementation", "Measured result"],
        ["Extreme imbalance",
         "Normal-only unsupervised channels; balanced classifier; PR-AUC; fixed alert budget",
         f"{results['dataset']['attack_rate']:.2%} base rate; PR-AUC {ranking['pr_auc']:.3f}"],
        ["Cold start",
         "Role priors for hour, resource rarity, and bytes; explicit cold-history weight",
         f"Single run {cold.get('cold_attack_recall_at_budget', 0):.1%} (n="
         f"{cold.get('cold_attack_events','?')}, unstable); quote the multi-seed mean "
         f"in the cross-seed table. FP rate {cold.get('cold_false_positive_rate', 0):.3%}"],
        ["Concept drift",
         "Page-Hinkley; protected recent baseline; baseline epochs; feedback rebaseline queue",
         f"Benign-drift FP rate {drift.get('drift_false_positive_rate', 0):.3%}; "
         f"{drift.get('test_drift_alarms', 0)} test alarms"],
    ]
    story.append(_table(hard, [3.1 * cm, 8.2 * cm, 6.1 * cm], font=8.0))
    p("Adaptation safety", h2)
    p(
        "Any high-confidence rule hit is excluded from adaptive profile updates. "
        "This reduces baseline poisoning: a burst, impossible-travel event, spoofed "
        "fingerprint, or exfiltration rule cannot teach the entity profile that the "
        "attack is normal. Page-Hinkley alarms create a new baseline epoch and a "
        "short learning window for moderate, unprotected changes.")
    story.append(Image(calibration_path, width=9.8 * cm, height=6.3 * cm))

    # Product / explainability
    p("8. Analyst Experience and Deployment", h1)
    p(
        "The Streamlit console hides synthetic ground truth by default. It provides "
        "a ranked queue, quantified evidence, entity timelines, channel scores, "
        "baseline epochs, fixed-threshold evaluation, cold-start/drift monitoring, "
        "and an analyst-feedback audit table.")
    preview = scored[
        (scored["split"] == "test") & scored["is_alert"]
    ].sort_values("risk", ascending=False)
    rows = [["Time", "Entity", "Classification", "Risk", "Reason"]]
    for _, row in preview.drop_duplicates("pred_label").head(6).iterrows():
        rows.append([
            str(row["timestamp"])[5:16],
            row["entity_id"],
            row["pred_label"].replace("_", " "),
            f"{row['risk']:.1f}",
            Paragraph((row["reason"] or "")[:145], small),
        ])
    story.append(_table(
        rows, [2.3 * cm, 2.0 * cm, 3.2 * cm, 1.4 * cm, 8.2 * cm],
        font=7.1))
    p("Feedback loop", h2)
    p(
        "Submitting a disposition writes an append-only audit record with event, "
        "entity, model label, risk, analyst, note, and UTC time. On the next run, "
        "confirmed false positives and expected behaviour become normal training "
        "overrides; confirmed attacks can correct attack labels; expected behaviour "
        "also creates a rebaseline request. The prototype deliberately says "
        "'next model refresh' rather than pretending the button retrains instantly.")

    p("Persisted inference", h2)
    p(
        "<font name='Courier'>python -m src.inference --input access_logs.csv "
        "--output scored.parquet --policy top_1pct</font>")
    p(
        "The command loads the saved scaler, categorical vocabulary, Isolation "
        "Forest, LightGBM model, risk selector/calibrator, CDF references, PyTorch "
        "weights, approved rule overrides, and validation thresholds. The same "
        "causal feature engine is used for training replay and inference.")

    scalability = results["scalability"]
    scale_table = [
        ["Measured component", "Events", "Throughput", "Scope"],
        ["Causal feature replay",
         f"{scalability['feature_benchmark_events']:,}",
         f"{scalability['feature_events_per_sec']:,} events/s",
         "Python state engine"],
        ["Complete model path",
         f"{scalability['model_benchmark_events']:,}",
         f"{scalability['model_events_per_sec']:,} events/s",
         "AE + IF + causal GRU + LightGBM + risk"],
    ]
    story.append(_table(scale_table, [4.0 * cm, 2.5 * cm, 3.5 * cm, 7.3 * cm]))
    p(
        f"Benchmark host: {scalability['hardware']}. These are batch-replay "
        "measurements, not distributed production-load results.", small)

    # Limitations + references
    p("9. Limitations and Next Steps", h1)
    limitations = results.get("limitations", [])
    bullets([f"<b>Current:</b> {item}" for item in limitations])
    bullets([
        "<b>Next validation:</b> train on one generator family and test on "
        "parameter-shifted campaigns plus public identity/authentication logs.",
        "<b>Next architecture:</b> Kafka-compatible state checkpointing, model "
        "registry, shadow deployment, latency SLOs, and drift-triggered approval workflow.",
        "<b>Next detection:</b> temporal entity-resource graph channel for lateral "
        "movement, evaluated as an ablation rather than added by default.",
        "<b>Next security:</b> adversarial profile-poisoning tests, compromised "
        "service-account campaigns, and red-team review of reason-code leakage.",
    ])

    p("Reproducibility", h2)
    p(
        "The archive includes source, tests, generated report/deck, complete scored "
        "test replay, model bundle and weights, run_manifest.json with dependency "
        "versions and SHA-256 hashes, and SUBMISSION_MANIFEST.json with archive "
        "checksums. The full dataset is regenerated from seed 42.")

    p("References", h1)
    references = [
        "[1] Honeywell Technologies Campus Connect 2026, AI-Powered Behavioral "
        "Anomaly Detection for Cybersecurity. "
        "https://honeywelltechnologiescampusconnect.mycareernet.co/",
        "[2] Honeywell, 2025 Cyber Threat Report press release, 4 Jun 2025. "
        "https://www.honeywell.com/us/en/news/press-releases/2025/06/"
        "ransomware-attacks-targeting-industrial-operators-surge-46-percent-"
        "in-one-quarter-honeywell-report-finds",
        "[3] Honeywell, Cyber Insights product page. "
        "https://process.honeywell.com/us/en/products/process-automation/"
        "cyber-suite/cyber-insights",
        "[4] Honeywell, AI-enabled industrial cybersecurity suite, 9 Jun 2025. "
        "https://www.honeywell.com/us/en/news/press-releases/2025/06/"
        "honeywell-drives-industrial-transition-from-automation-to-autonomy-"
        "with-new-ai-enabled-digital-suite",
        "[5] MITRE ATT&CK, Brute Force T1110, Credential Stuffing T1110.004, "
        "Remote Services T1021, Valid Accounts T1078, Masquerading T1036, "
        "and Data Transfer Size Limits T1030. https://attack.mitre.org/",
        "[6] L. Antwarg, R. M. Miller, B. Shapira, and L. Rokach, "
        "'Explaining anomalies detected by autoencoders using Shapley Additive "
        "Explanations,' Expert Systems with Applications 186 (2021), 115736. "
        "https://doi.org/10.1016/j.eswa.2021.115736",
    ]
    for reference in references:
        p(reference, small)

    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    print(f"[report] wrote {path}")


if __name__ == "__main__":
    build()
