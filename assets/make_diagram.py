"""Render a clean architecture diagram (assets/architecture.png) for the report & deck."""
from __future__ import annotations
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import config as C

BLUE = "#1F4E79"; ACCENT = "#2E86AB"; GREEN = "#27AE60"; RED = "#C0392B"; GREY = "#5D6D7E"


def box(ax, x, y, w, h, text, fc, tc="white", fs=10, bold=True):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                                fc=fc, ec="white", lw=1.5, zorder=3))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", color=tc,
            fontsize=fs, fontweight="bold" if bold else "normal", zorder=4, wrap=True)


def arrow(ax, x1, y1, x2, y2, color=GREY):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=14,
                                 lw=1.6, color=color, zorder=2))


def main():
    fig, ax = plt.subplots(figsize=(12, 6.8))
    ax.set_xlim(0, 12); ax.set_ylim(0, 7); ax.axis("off")
    ax.text(6, 6.7, "SentinelUEBA — Layered Behavioural Anomaly Detection",
            ha="center", fontsize=15, fontweight="bold", color=BLUE)

    # ingest
    box(ax, 0.3, 3.0, 1.9, 1.0, "Synthetic\nAccess Logs", GREY, fs=10)
    box(ax, 0.3, 1.6, 1.9, 1.0, "Causal\nBehavioural\nFeatures", GREY, fs=9)
    arrow(ax, 1.25, 3.0, 1.25, 2.6)

    # 5 detection channels
    ch = [
        ("Rule / Physics\nimpossible travel,\nbrute force, spoofing", RED, 5.6),
        ("Autoencoder\nper-entity\nbaseline", ACCENT, 4.35),
        ("Isolation Forest\nrobust\nunsupervised", ACCENT, 3.10),
        ("GRU Sequence AE\nlateral\nmovement", ACCENT, 1.85),
        ("LightGBM\nattack-type\nclassifier", GREEN, 0.60),
    ]
    for txt, fc, y in ch:
        box(ax, 3.0, y, 2.5, 1.05, txt, fc, fs=8.5)
        arrow(ax, 2.2, 2.1, 3.0, y + 0.5)

    # fusion
    box(ax, 6.2, 2.7, 2.2, 1.5, "Calibrated\nMeta-Fusion\n→ Risk 0–100", BLUE, fs=11)
    for _, _, y in ch:
        arrow(ax, 5.5, y + 0.5, 6.2, 3.45)

    # explain + dashboard
    box(ax, 9.0, 3.7, 2.6, 1.1, "SHAP + Rule\nReason Codes", ACCENT, fs=10)
    box(ax, 9.0, 2.1, 2.6, 1.1, "SOC Analyst\nDashboard", BLUE, fs=10)
    arrow(ax, 8.4, 3.7, 9.0, 4.25)
    arrow(ax, 8.4, 3.1, 9.0, 2.65)

    # feedback loop
    ax.add_patch(FancyArrowPatch((9.0, 2.1), (7.3, 2.7), connectionstyle="arc3,rad=0.35",
                                 arrowstyle="-|>", mutation_scale=12, lw=1.4,
                                 color=GREEN, ls="--", zorder=2))
    ax.text(8.0, 1.55, "analyst feedback → next refresh / re-baseline (drift)",
            ha="center", fontsize=8, color=GREEN, style="italic")

    # hard-problems footer
    ax.text(6, 0.15, "Handles: extreme class imbalance  ·  concept drift (Page-Hinkley)  "
            "·  cold-start (peer-group + rules)  ·  explainable  ·  streaming-ready",
            ha="center", fontsize=9, color=BLUE, fontweight="bold")

    out = os.path.join(C.ASSET_DIR, "architecture.png")
    plt.tight_layout(); plt.savefig(out, dpi=160, bbox_inches="tight"); plt.close()
    print(f"[diagram] wrote {out}")


if __name__ == "__main__":
    main()
