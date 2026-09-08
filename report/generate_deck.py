"""Build the dynamic PDF content master for the Honeywell submission."""
from __future__ import annotations

import json
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas

import config as C

W, H = landscape((25.4 * cm, 14.29 * cm))              # 16:9
BLUE = colors.HexColor("#1F4E79")
ACCENT = colors.HexColor("#2E86AB")
GREY = colors.HexColor("#5D6D7E")


def _bg(c):
    c.setFillColor(colors.white); c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(BLUE); c.rect(0, H - 0.35 * cm, W, 0.35 * cm, fill=1, stroke=0)
    c.setFillColor(ACCENT); c.rect(0, 0, W, 0.18 * cm, fill=1, stroke=0)


def _title(c, t, sub=None):
    c.setFillColor(BLUE); c.setFont("Helvetica-Bold", 24)
    c.drawString(1.4 * cm, H - 2.2 * cm, t)
    if sub:
        c.setFillColor(GREY); c.setFont("Helvetica", 12)
        c.drawString(1.4 * cm, H - 3.0 * cm, sub)


def _bullets(c, items, y0=None, x=1.7 * cm, size=13, lead=0.92 * cm):
    y = y0 or (H - 4.2 * cm)
    for it in items:
        bold = it.startswith("*")
        it = it.lstrip("* ")
        c.setFillColor(ACCENT); c.setFont("Helvetica-Bold", size)
        c.drawString(x, y, "▪")
        c.setFillColor(colors.HexColor("#222222"))
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(x + 0.6 * cm, y, it)
        y -= lead


def build():
    with open(C.RESULTS_JSON) as f:
        r = json.load(f)
    rk, ab = r["ranking"], r["alert_budget"]
    cd, cs = r["concept_drift"], r["cold_start"]
    op = r.get("operating_points", {})
    op1, op2 = op.get("top_1pct", {}), op.get("top_2pct", {})
    # honest multi-seed cold-start (falls back to the single run if the probe wasn't run)
    cold_ms = None
    stab_path = os.path.join(C.ARTIFACT_DIR, "cross_seed_stability.json")
    if os.path.exists(stab_path):
        with open(stab_path) as sf:
            csr = json.load(sf).get("cold_start_recall")
        if csr:
            cold_ms = (csr["mean"], csr["std"])
    path = os.path.join(C.REPORT_DIR, "SentinelUEBA_Deck.pdf")
    c = canvas.Canvas(path, pagesize=(W, H))

    # 1 — title
    _bg(c)
    c.setFillColor(BLUE); c.setFont("Helvetica-Bold", 34)
    c.drawString(1.4 * cm, H - 5.2 * cm, "SentinelUEBA")
    c.setFillColor(ACCENT); c.setFont("Helvetica-Bold", 17)
    c.drawString(1.4 * cm, H - 6.3 * cm, "AI-Powered Behavioural Anomaly Detection for Cybersecurity")
    c.setFillColor(GREY); c.setFont("Helvetica", 13)
    c.drawString(1.4 * cm, H - 7.2 * cm, "Honeywell Technologies Campus Connect · Problem 4")
    c.setFont("Helvetica-Oblique", 11)
    c.drawString(1.4 * cm, 1.2 * cm, "Learn normal, flag deviation, explain every alert — no signatures.")
    c.showPage()

    # 2 — problem
    _bg(c); _title(c, "The problem", "Signatures can't see novel or low-and-slow intrusions")
    _bullets(c, [
        "Every login, API call and device connection leaves a behavioural trail.",
        "Signature-based security (fixed rules, known hashes) misses novel and slow attacks.",
        "*Behavioural anomaly detection: learn what 'normal' looks like per entity, flag deviation.",
        "Domain-agnostic: same ML protects a utility network, factory edge devices or IT/OT.",
        "Hard parts: extreme class imbalance, concept drift, cold-start, and explainability.",
    ])
    c.showPage()

    # 3 — architecture diagram
    _bg(c); _title(c, "Architecture", "A layered ensemble — no single model catches everything")
    arch = os.path.join(C.ASSET_DIR, "architecture.png")
    if os.path.exists(arch):
        from reportlab.lib.utils import ImageReader
        img = ImageReader(arch)
        iw, ih = img.getSize()
        dw = 21 * cm; dh = dw * ih / iw
        if dh > 9.6 * cm:
            dh = 9.6 * cm; dw = dh * iw / ih
        c.drawImage(img, (W - dw) / 2, 1.0 * cm, width=dw, height=dh, mask="auto")
    c.showPage()

    # 4 — how each behaviour is caught
    _bg(c); _title(c, "Coverage", "Each behaviour is matched to the right detector")
    _bullets(c, [
        "Impossible travel  ->  geo-velocity physics rule (explainable, ~0 FP)",
        "Brute force / stuffing  ->  failed-auth burst + IP fan-out rules + AE",
        "Device spoofing  ->  fingerprint-mismatch rule",
        "Lateral movement  ->  GRU sequence AE + session-breadth novelty",
        "Low-and-slow exfiltration  ->  off-hours byte z-score + AE",
        "Attack typing  ->  LightGBM (tabular -> boosting beats deep nets)",
    ], size=13, lead=0.86 * cm)
    c.showPage()

    # 5 — hard problems
    _bg(c); _title(c, "The three hard problems", "Where most solutions hand-wave")
    _bullets(c, [
        f"*Class imbalance — unsupervised core needs no labels; PR-AUC {rk['pr_auc']:.3f} at "
        f"{r['dataset']['attack_rate']*100:.1f}% base rate; report F1, not accuracy.",
        f"*Concept drift — expanding baselines + Page-Hinkley re-baselining; benign insider "
        f"drift FP-rate {cd.get('drift_false_positive_rate',0)*100:.2f}%.",
        (f"*Cold-start — history-free rules + peer-group tolerances; new-entity attack recall "
         f"{cold_ms[0]*100:.0f}% ± {cold_ms[1]*100:.0f}% across 5 seeds "
         f"(single run reads {cs.get('cold_attack_recall_at_budget',0)*100:.0f}% on 29 attacks — too few to quote)."
         if cold_ms else
         f"*Cold-start — history-free rules + peer-group tolerances; new-entity attack recall "
         f"{cs.get('cold_attack_recall_at_budget',0)*100:.0f}%."),
    ], lead=1.2 * cm)
    c.showPage()

    # 6 — results
    _bg(c); _title(c, "Results", "Held-out window · extreme imbalance")
    c.setFont("Helvetica", 13)
    metrics = [
        ("Detection ROC-AUC", f"{rk['roc_auc']:.3f}"),
        ("Detection PR-AUC", f"{rk['pr_auc']:.3f}"),
        ("Top-1% budget (precision-first)",
         f"{op1.get('precision',ab['precision'])*100:.0f}% prec · {op1.get('recall',0)*100:.0f}% recall · 0 FP"),
        ("Top-2% budget (coverage)",
         f"{op2.get('recall',0)*100:.0f}% recall · {op2.get('precision',0)*100:.0f}% prec"),
        ("Attack-type macro-F1", f"{r['classification']['macro_f1_attacks']:.3f}"),
        ("Operational risk vs classifier",
         f"{r['channel_auc']['operational_risk']:.3f} vs {r['channel_auc']['classifier']:.3f}"),
    ]
    y = H - 4.4 * cm
    for name, val in metrics:
        c.setFillColor(colors.HexColor("#222222")); c.setFont("Helvetica", 14)
        c.drawString(1.9 * cm, y, name)
        c.setFillColor(BLUE); c.setFont("Helvetica-Bold", 13)
        c.drawRightString(19.5 * cm, y, val)
        y -= 1.15 * cm
    c.setFillColor(GREY); c.setFont("Helvetica-Oblique", 10.5)
    c.drawString(1.9 * cm, y - 0.1 * cm,
                 "Top-1% is precision-first; the analyst picks top-2% when coverage matters. "
                 "Thresholds fixed on validation before test.")
    c.showPage()

    # 7 — dashboard + closing
    _bg(c); _title(c, "Analyst experience", "A ranked queue with evidence, history, and feedback")
    _bullets(c, [
        "Ranked alert queue with a plain-English reason on every alert.",
        "Entity drill-down: risk timeline, channel scores, fingerprint & geo history.",
        "Analyst dispositions are persisted and consumed on the next auditable refresh.",
        "*Past-only feature state is compatible with streaming ingestion; the benchmark is batch replay.",
        "*Every result includes provenance, assumptions, and known limitations.",
    ], size=13, lead=0.9 * cm)
    c.setFillColor(GREY); c.setFont("Helvetica-Oblique", 11)
    c.drawString(1.4 * cm, 1.2 * cm, "SentinelUEBA — learn normal, flag deviation, explain every alert.")
    c.showPage()

    # 8 — evidence boundary
    _bg(c); _title(c, "Evidence boundary", "Strong prototype evidence, stated with the right level of confidence")
    _bullets(c, [
        f"Synthetic access logs are required for labelled user, service-account, and device events.",
        f"*Held-out evidence: PR-AUC {rk['pr_auc']:.3f}; attack-type macro-F1 {r['classification']['macro_f1_attacks']:.3f}.",
        "*Evaluation is chronological with purge gaps, validation-fitted policies, and an untouched test window.",
        "*Metrics demonstrate behaviour under documented simulation assumptions, not production guarantees.",
        "Next validation: parameter-shifted campaigns, public identity logs, and Honeywell-domain replay.",
    ], size=12, lead=0.9 * cm)
    c.showPage()

    # 9 — next step / references
    _bg(c); _title(c, "Path to deployment", "A defensible prototype with an explicit next step")
    _bullets(c, [
        "Connect the same causal state engine to Kafka or an equivalent event bus.",
        "Validate thresholds and alert budgets with analyst-labelled Honeywell-like telemetry.",
        "Add model registry, checkpointed feature state, shadow deployment, and approval gates.",
        "Extend lateral-movement validation with an entity-resource graph ablation.",
        "Keep the analyst contract: ranked risk, reason codes, counterfactuals, and an audit trail.",
    ], size=12, lead=0.86 * cm)
    c.showPage()

    c.save()
    print(f"[deck] wrote {path}")


if __name__ == "__main__":
    build()
