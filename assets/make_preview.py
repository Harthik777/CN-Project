"""Render a compact current-data alert preview for the report/package."""
from __future__ import annotations

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

import config as C


def main():
    scored = pd.read_parquet(C.SCORED_PARQUET)
    test = scored[scored["split"] == "test"].sort_values(
        ["risk", "timestamp"], ascending=[False, False])
    preview = test.drop_duplicates("pred_label").head(6)
    columns = ["time", "entity", "predicted type", "risk", "reason"]
    rows = []
    for row in preview.itertuples():
        reason = str(row.reason or "off-profile behaviour").replace("\n", " ")
        rows.append([
            str(row.timestamp)[5:16],
            str(row.entity_id),
            str(row.pred_label).replace("_", " "),
            f"{float(row.risk):.1f}",
            reason[:105],
        ])

    figure, axis = plt.subplots(figsize=(16.5, 3.5))
    axis.axis("off")
    axis.set_title(
        "SOC console - current ranked test alerts",
        loc="left", fontsize=17, fontweight="bold", color="#1F4E79", pad=12)
    table = axis.table(
        cellText=rows, colLabels=columns, loc="center", cellLoc="left",
        colWidths=[0.11, 0.10, 0.17, 0.07, 0.55])
    table.auto_set_font_size(False)
    table.set_fontsize(9.5)
    table.scale(1, 1.9)
    for (row, column), cell in table.get_celld().items():
        cell.set_edgecolor("#17212B")
        if row == 0:
            cell.set_facecolor("#1F4E79")
            cell.set_text_props(color="white", weight="bold")
        else:
            cell.set_facecolor("#FFFFFF" if row % 2 else "#F5F7F8")
            if column == 3:
                cell.set_facecolor("#F5C5C5")
    output = os.path.join(C.ASSET_DIR, "preview_alerts.png")
    figure.savefig(output, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(figure)
    print(f"[preview] wrote {output}")


if __name__ == "__main__":
    main()
