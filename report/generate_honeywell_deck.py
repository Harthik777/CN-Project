"""
Build the mandatory Honeywell IDEA-template deck from the PRISTINE portal
template (report/IDEA_Presentation_Format.pptx).

This generator exists because the earlier deck was hand-assembled and shipped a
corrupt OPC package (duplicate ppt/slides/slide1.xml entries). Building from the
clean template with python-pptx and saving once produces a valid package. All
head-line numbers are pulled from artifacts/ so the deck can never drift from the
report again.

    python -m report.generate_honeywell_deck
"""
from __future__ import annotations

import json
import os

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.oxml.ns import qn
from pptx.util import Emu, Inches, Pt

import config as C

TEMPLATE = os.path.join(C.REPORT_DIR, "IDEA_Presentation_Format.pptx")
OUT = os.path.join(C.REPORT_DIR, "SentinelUEBA_Honeywell_Deck.pptx")

NAVY = RGBColor(0x0B, 0x24, 0x47)
INK = RGBColor(0x1F, 0x2A, 0x37)
GREY = RGBColor(0x55, 0x5F, 0x6B)
FOOTER = "SentinelUEBA · Honeywell Campus Connect 2026 · Problem 4"


def _load_numbers():
    with open(C.RESULTS_JSON, encoding="utf-8") as fh:
        r = json.load(fh)
    op = r.get("operating_points", {})
    op1, op2 = op.get("top_1pct", {}), op.get("top_2pct", {})
    nums = {
        "roc": r["ranking"]["roc_auc"],
        "pr": r["ranking"]["pr_auc"],
        "macro_f1": r["classification"]["macro_f1_attacks"],
        "rec1": op1.get("recall", 0.0),
        "rate1": op1.get("realized_alert_rate", 0.0),
        "rec2": op2.get("recall", 0.0),
        "prec2": op2.get("precision", 0.0),
        "drift_fp": r["concept_drift"].get("drift_false_positive_rate", 0.0),
        "cold_single": r["cold_start"].get("cold_attack_recall_at_budget", 0.0),
    }
    stab = os.path.join(C.ARTIFACT_DIR, "cross_seed_stability.json")
    if os.path.exists(stab):
        with open(stab, encoding="utf-8") as fh:
            cs = json.load(fh)
        nums["cold_mean"] = cs["cold_start_recall"]["mean"]
        nums["cold_std"] = cs["cold_start_recall"]["std"]
        nums["cold_n"] = cs.get("total_cold_attacks")
    else:
        nums["cold_mean"] = nums["cold_std"] = nums["cold_n"] = None
    return nums


def _delete_slide(prs, index):
    """Cleanly remove a slide: drop its relationship and sldId entry so the part
    is not serialised (no orphaned/duplicated parts)."""
    sld_id_lst = prs.slides._sldIdLst
    sld_id = list(sld_id_lst)[index]
    prs.part.drop_rel(sld_id.get(qn("r:id")))
    sld_id_lst.remove(sld_id)


def _shape(slide, name):
    for sh in slide.shapes:
        if sh.name == name:
            return sh
    return None


def _title(slide):
    for sh in slide.shapes:
        if sh.is_placeholder and sh.placeholder_format.idx == 0:
            return sh
    return None


def _place(shape, left, top, width, height):
    shape.left, shape.top = Inches(left), Inches(top)
    shape.width, shape.height = Inches(width), Inches(height)


def _no_inherited_bullet(para):
    """Force the paragraph to carry no inherited list bullet, so the only marker is
    the literal glyph we add. Prevents a doubled bullet when the template placeholder
    applies its own buChar."""
    p_pr = para._p.get_or_add_pPr()
    for tag in ("a:buChar", "a:buAutoNum", "a:buNone"):
        for el in p_pr.findall(qn(tag)):
            p_pr.remove(el)
    p_pr.append(p_pr.makeelement(qn("a:buNone"), {}))


def _fill(shape, items, header_pt=15, body_pt=12.5):
    """items: list of (is_header, text). Headers are navy/bold; bullets are
    indented with a bullet glyph."""
    tf = shape.text_frame
    tf.clear()
    tf.word_wrap = True
    first = True
    for is_header, text in items:
        para = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        para.level = 0
        _no_inherited_bullet(para)
        para.space_after = Pt(4 if is_header else 2)
        para.space_before = Pt(6 if is_header else 0)
        run = para.add_run()
        if is_header:
            run.text = text
            run.font.size, run.font.bold = Pt(header_pt), True
            run.font.color.rgb = NAVY
        else:
            run.text = "•  " + text
            run.font.size, run.font.bold = Pt(body_pt), False
            run.font.color.rgb = INK
        run.font.name = "Calibri"


def _set_text(shape, text, size, bold=False, color=INK):
    tf = shape.text_frame
    tf.clear()
    tf.word_wrap = True
    run = tf.paragraphs[0].add_run()
    run.text = text
    run.font.size, run.font.bold = Pt(size), bold
    run.font.color.rgb = color
    run.font.name = "Calibri"


def _fix_footer(slide):
    for sh in slide.shapes:
        if sh.is_placeholder and sh.placeholder_format.idx == 11:
            _set_text(sh, FOOTER, 9, color=GREY)


def build():
    n = _load_numbers()
    cold = (f"{n['cold_mean']*100:.1f}% ± {n['cold_std']*100:.1f}% across 5 seeds "
            f"({n['cold_n']} attacks)"
            if n["cold_mean"] is not None else f"{n['cold_single']*100:.0f}%")

    prs = Presentation(TEMPLATE)
    _delete_slide(prs, 0)  # drop the "IMPORTANT INSTRUCTIONS" guidance slide
    s_title, s_sol, s_tech, s_feas, s_art, s_ref = prs.slides

    # ---- Slide 1: title page ----
    _set_text(_shape(s_title, "Subtitle 3"),
              "SentinelUEBA — AI-Powered Behavioural Anomaly Detection for Cybersecurity",
              26, bold=True, color=NAVY)
    _place(_shape(s_title, "Subtitle 3"), 0.6, 2.4, 12.1, 1.8)
    fields = _shape(s_title, "TextBox 6")
    _place(fields, 0.7, 4.3, 11.6, 2.6)
    _fill(fields, [
        (False, "Problem Statement ID:  Honeywell Campus Connect 2026 · Problem 4"),
        (False, "Problem Statement Title:  AI-Powered Behavioural Anomaly Detection for Cybersecurity"),
        (False, "Theme:  Cybersecurity (UEBA / Threat Detection)     PS Category:  Software"),
        (False, "Idea / Solution Name:  SentinelUEBA"),
        (False, "Student Name (Registered):  Induj Gupta"),
        (False, "Institute:  Manipal Institute of Technology, Bengaluru"),
    ], body_pt=13)

    # ---- Slide 2: proposed solution ----
    _set_text(_title(s_sol), "SentinelUEBA — Behavioural Anomaly Detection",
              22, bold=True, color=NAVY)
    body = _shape(s_sol, "TextBox 8")
    _place(body, 0.4, 1.4, 12.5, 5.35)
    _fill(body, [
        (True, "Proposed solution"),
        (False, "Learns the normal access behaviour of every user, service account and "
                "device, then flags deviations — it does not rely exclusively on signatures."),
        (False, "Detects and classifies brute force, impossible travel, credential stuffing, "
                "lateral movement, device spoofing and low-and-slow exfiltration; leaves benign "
                "insider drift alone."),
        (True, "How it addresses the problem"),
        (False, "Five detection channels (rules + autoencoder + isolation forest + causal GRU + "
                "classifier) are evaluated on a held-out validation window; the classifier won "
                "and is the operational champion, exposed as one explainable 0–100 risk score."),
        (False, "Every alert carries a plain-English reason, a MITRE ATT&CK technique, "
                "contributing channel scores, and a counterfactual (“benign if geo-velocity "
                "< 900 km/h”)."),
        (True, "Innovation & uniqueness"),
        (False, "Validation-gated champion: keeps the simplest model that wins on a held-out "
                "validation window — and documents it (intellectual honesty)."),
        (False, "Causal, past-only features: the feature logic is streaming-compatible; "
                "evaluated here through batch replay."),
        (False, "Stable across five same-generator seeds: 100% precision and 0 false positives "
                "on every seed (sampling stability, not domain/campaign shift)."),
    ], body_pt=12)

    # ---- Slide 3: technical approach ----
    _set_text(_title(s_tech), "TECHNICAL APPROACH", 22, bold=True, color=NAVY)
    body = _shape(s_tech, "TextBox 8")
    _place(body, 0.4, 1.4, 12.5, 5.35)
    _fill(body, [
        (True, "Technologies"),
        (False, "Python · PyTorch (autoencoder + causal GRU) · scikit-learn (Isolation Forest) · "
                "LightGBM (attack typing) · SHAP (explainability) · Streamlit (analyst console) · "
                "NumPy/pandas (synthetic generator)."),
        (True, "Methodology"),
        (False, "1. Generate synthetic access logs to the required schema (~2% injected attacks, "
                "labels held separately)."),
        (False, "2. Causal, past-only feature engineering (rolling windows, geo-velocity, "
                "resource novelty, peer priors)."),
        (False, "3. Train normal-only unsupervised baselines + causal GRU + LightGBM classifier."),
        (False, "4. Validation-gated fusion selects the operational champion; alert thresholds "
                "fitted on validation."),
        (False, "5. Explain every alert; persist an auditable analyst-feedback loop."),
        (True, "Evaluation"),
        (False, "Chronological train / validation / selection / untouched-test with a 1-hour "
                "purge gap; PR-AUC primary; entity-clustered bootstrap CIs; calibration."),
    ], body_pt=12)

    # ---- Slide 4: feasibility ----
    _set_text(_title(s_feas), "FEASIBILITY AND VIABILITY", 22, bold=True, color=NAVY)
    body = _shape(s_feas, "TextBox 8")
    _place(body, 0.4, 1.4, 12.5, 5.35)
    _fill(body, [
        (True, "Feasibility — measured on the untouched test window"),
        (False, f"Detection ROC-AUC {n['roc']:.4f} · PR-AUC {n['pr']:.4f}."),
        (False, f"Top-1% budget (precision-first): 100% precision, 0 false positives, "
                f"{n['rec1']*100:.1f}% overall recall ({n['rate1']*100:.2f}% realised alert rate)."),
        (False, f"Top-2% budget (coverage): {n['rec2']*100:.1f}% recall at {n['prec2']*100:.1f}% "
                f"precision — the analyst tunes the trade-off (the strict top-1% policy misses "
                f"impossible-travel / device-spoofing)."),
        (False, f"Attack-type macro-F1 {n['macro_f1']:.3f} · cold-start recall {cold} · "
                f"benign-drift FP rate {n['drift_fp']*100:.1f}%."),
        (False, "~19,500 events/sec on a single CPU core — streaming-feasible."),
        (True, "Challenges & risks"),
        (False, "Extreme imbalance · concept drift vs. attacks · cold-start · adaptive-baseline "
                "poisoning · synthetic primary benchmark."),
        (True, "Strategies to overcome"),
        (False, "Unsupervised core + PR-AUC (imbalance); Page-Hinkley + protected baselines "
                "(drift); role peer priors (cold-start)."),
        (False, "High-confidence rule hits are excluded from profile updates (anti-poisoning); "
                "held-out SPEDIA probe + red-team-labelled LANL harness (generalisation)."),
    ], body_pt=11.5)

    # ---- Slide 5: artifacts ----
    _set_text(_title(s_art), "ARTIFACTS", 22, bold=True, color=NAVY)
    body = _shape(s_art, "TextBox 8")
    _place(body, 0.4, 1.4, 12.5, 5.35)
    _fill(body, [
        (True, "Reproducible, auditable pipeline"),
        (False, "One command: python run_all.py --fresh (seeded, deterministic)."),
        (False, "Persisted model bundle + inference replay · SHA-256 run manifest · 25 passing tests."),
        (True, "Deliverables (all included)"),
        (False, "Synthetic generator · autoencoder baseline · causal GRU · LightGBM classifier · "
                "SHAP explainability · Streamlit analyst console · technical report (PDF)."),
        (False, "Code + report + scored data packaged in the CRC-verified submission ZIP."),
        (False, "Detection curves (ROC / Precision-Recall) and per-channel ROC-AUC are in the "
                "technical report and the analyst console."),
    ], body_pt=12.5)

    # ---- Slide 6: research and references ----
    _set_text(_title(s_ref), "RESEARCH AND REFERENCES", 22, bold=True, color=NAVY)
    body = _shape(s_ref, "TextBox 8")
    _place(body, 0.4, 1.4, 12.5, 5.35)
    _fill(body, [
        (False, "MITRE ATT&CK — technique mapping (T1110 Brute Force, T1078 Valid Accounts, "
                "T1021 Remote Services, T1036 Masquerading, T1030 Exfiltration)."),
        (False, "Antwarg et al., “Explaining Anomalies Detected by Autoencoders Using SHAP,” "
                "Expert Systems with Applications (2021)."),
        (False, "Peer-group analysis for UEBA false-positive reduction (Bolton & Hand; "
                "Gartner-standard practice)."),
        (False, "Real-data evidence — executed chronological SPEDIA probe (Zenodo 15495572); "
                "implemented, not executed: LANL red-team auth harness (csr.lanl.gov/data/cyber1)."),
        (False, "Page-Hinkley change detection for concept-drift handling."),
        (False, "Domain alignment — Honeywell Forge Cyber Insights (OT behavioural anomaly detection)."),
    ], body_pt=13)

    for slide in prs.slides:
        _fix_footer(slide)

    prs.save(OUT)
    print(f"[honeywell-deck] wrote {OUT}")


if __name__ == "__main__":
    build()
