"""Controlled concept-drift experiment -> assets/chart_drift.png.

Demonstrates the drift-handling mechanism used in features.py / drift.py:
a legitimate, gradual behavioural shift (insider drift) must NOT be permanently
flagged. A static baseline keeps alerting after the shift (false positives); the
adaptive expanding/EWMA baseline absorbs the new normal, and Page-Hinkley marks
the point where the entity is re-baselined.
"""
from __future__ import annotations
import os
import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import config as C
from src.drift import PageHinkley

def build():
    rng = np.random.default_rng(C.SEED)
    n = 320; drift_start, drift_end = 150, 210
    # signal: stable, then gradual legitimate shift to a new normal, then stable
    mean = np.zeros(n)
    mean[drift_start:drift_end] = np.linspace(0, 3.0, drift_end - drift_start)
    mean[drift_end:] = 3.0
    x = mean + rng.normal(0, 0.6, n)

    # static baseline: mean/std fixed from the first 100 steps
    m0, s0 = x[:100].mean(), x[:100].std()
    static_z = np.abs((x - m0) / s0)

    # adaptive baseline: EWMA mean/std -> re-centres on recent behaviour
    a = 0.03; ew_m = x[0]; ew_v = 1.0; adapt_z = np.zeros(n)
    for i in range(n):
        adapt_z[i] = abs((x[i] - ew_m) / (np.sqrt(ew_v) + 1e-6))
        ew_m = (1 - a) * ew_m + a * x[i]
        ew_v = (1 - a) * ew_v + a * (x[i] - ew_m) ** 2

    # Page-Hinkley monitors the RAW signal to detect a sustained shift and fire
    # the re-baseline trigger (can't trip during the stable warm-up region).
    ph = PageHinkley(delta=0.4, lam=4.0, min_history=drift_start - 5); trip = None
    for i in range(n):
        if ph.update(x[i]) and trip is None:
            trip = i

    thr = 3.0
    plt.figure(figsize=(8, 3.1))
    plt.axvspan(drift_start, drift_end, color="#94A3B8", alpha=0.12, label="legitimate drift")
    plt.plot(static_z, color="#DC2626", lw=1.6, label="static baseline (keeps alerting → FPs)")
    plt.plot(adapt_z, color="#1E8449", lw=1.8, label="adaptive baseline (absorbs new normal)")
    plt.axhline(thr, color="#94A3B8", ls="--", lw=0.8)
    plt.text(2, thr + 0.15, "alert threshold", fontsize=7, color="#64748B")
    if trip is not None:
        plt.axvline(trip, color="#2563EB", ls=":", lw=1.2)
        plt.text(trip + 2, plt.ylim()[1]*0.86, "Page-Hinkley → re-baseline", fontsize=7, color="#2563EB")
    plt.xlabel("event (time) ->"); plt.ylabel("anomaly score (|z|)")
    plt.title("Concept-drift handling: adaptive baseline absorbs legitimate insider drift")
    plt.legend(fontsize=7, loc="upper right", framealpha=.9); plt.ylim(0, max(6, static_z.max()*1.05))
    plt.tight_layout()
    p = os.path.join(C.ASSET_DIR, "chart_drift.png"); plt.savefig(p, dpi=150); plt.close()
    # numbers for the caption
    post = slice(drift_end + 10, n)
    static_fp = float((static_z[post] > thr).mean()); adapt_fp = float((adapt_z[post] > thr).mean())
    print(f"[drift] static post-drift alert rate {static_fp:.0%}  vs  adaptive {adapt_fp:.0%}  "
          f"(PH re-baseline at t={trip})")
    print(f"[drift] wrote {p}")
    return static_fp, adapt_fp

if __name__ == "__main__":
    build()
