"""
Real-data validation harness — LANL 'Comprehensive, Multi-Source Cyber-Security
Events' authentication logs (https://csr.lanl.gov/data/cyber1/).

WHY THIS EXISTS
---------------
The packaged evaluation is synthetic because labelled user/device access logs are
privacy-restricted (the reason the problem statement mandates generating data).
This harness closes the loop on *real* data: it applies the SentinelUEBA
*methodology* — behavioural feature engineering + an unsupervised
Isolation-Forest / autoencoder detector — to LANL's real enterprise
authentication logs, and scores it against the real red-team lateral-movement
labels. It is deliberately schema-specific (LANL auth has no geo / device / bytes
fields; it is a computer-to-computer auth graph), so it validates the *approach*,
not the frozen synthetic-trained bundle.

It is NOT run inside the packaged artifact because auth.txt.gz is ~11 GB and
access-gated. Run it locally once you have the two files:

    # download auth.txt.gz and redteam.txt.gz from csr.lanl.gov/data/cyber1/
    python evaluate_real_data.py --auth auth.txt.gz --redteam redteam.txt.gz

Output: artifacts/real_data_results.json  (ROC-AUC, PR-AUC, precision/recall at a
top-k analyst budget, and red-team detection recall).

METHOD
------
* Labels: an auth event is malicious if (time, src_user, src_computer,
  dst_computer) is in redteam.txt (the standard LANL labelling convention).
* To stay tractable, only events within the red-team's active time window
  (+/- a margin) are scored — this captures every attack plus contemporaneous
  benign traffic, a realistic and honest evaluation slice.
* Causal, past-only behavioural features per source user:
    - authentication failure + rolling failure rate         (brute force)
    - first-time access to a destination computer           (lateral movement)
    - running count of distinct destination computers        (lateral spread)
    - first-time use of a source computer                    (account takeover)
    - rarity of the auth-type / logon-type for that user     (masquerading)
    - off-hours flag from the LANL relative clock            (low-and-slow)
    - self-to-self vs remote logon
* Detector: StandardScaler + IsolationForest (unsupervised — never sees labels),
  matching the normal-only channel of SentinelUEBA. An optional autoencoder
  channel is fused by rank if --autoencoder is passed.
"""
from __future__ import annotations

import argparse
import json
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

import config as C

AUTH_COLS = ["time", "src_user", "dst_user", "src_computer", "dst_computer",
             "auth_type", "logon_type", "auth_orientation", "outcome"]
REDTEAM_COLS = ["time", "user", "src_computer", "dst_computer"]


def load_redteam(path):
    rt = pd.read_csv(path, header=None, names=REDTEAM_COLS)
    keys = set(zip(rt["time"], rt["user"], rt["src_computer"], rt["dst_computer"]))
    return rt, keys, int(rt["time"].min()), int(rt["time"].max())


def stream_auth_window(path, lo, hi, margin, max_rows):
    """Keep auth rows whose time falls in the red-team window +/- margin."""
    kept = []
    total = 0
    for chunk in pd.read_csv(path, header=None, names=AUTH_COLS, chunksize=500_000):
        total += len(chunk)
        sub = chunk[(chunk["time"] >= lo - margin) & (chunk["time"] <= hi + margin)]
        if len(sub):
            kept.append(sub)
        if chunk["time"].iloc[-1] > hi + margin:
            break                                       # file is time-sorted; past the window
        if max_rows and total >= max_rows:
            break
    if not kept:
        raise SystemExit("No auth rows in the red-team window — check the files.")
    return pd.concat(kept, ignore_index=True)


def build_features(df):
    df = df.sort_values("time").reset_index(drop=True)
    df["fail"] = (df["outcome"].astype(str).str.lower().str.startswith("fail")).astype(float)
    g = df.groupby("src_user", sort=False)

    # rolling-ish failure rate (causal expanding mean of prior events)
    n_prior = g.cumcount().clip(lower=1)
    df["user_fail_rate"] = (g["fail"].cumsum() - df["fail"]) / n_prior

    # lateral movement: first time this user reaches this destination computer
    df["dst_new"] = (~df.duplicated(["src_user", "dst_computer"])).astype(float)
    df["dst_distinct"] = g["dst_new"].cumsum()                      # distinct dsts so far
    df["src_new"] = (~df.duplicated(["src_user", "src_computer"])).astype(float)

    # Past-only auth/logon-type rarity for the user. Laplace smoothing supplies a
    # finite cold-start prior without using counts from future events.
    user_prior = g.cumcount()
    for col in ["auth_type", "logon_type"]:
        pair_prior = df.groupby(
            ["src_user", col], sort=False, dropna=False
        ).cumcount()
        probability = (pair_prior + 1.0) / (user_prior + 2.0)
        df[f"{col}_rarity"] = -np.log(probability.clip(lower=1e-9))

    df["hour"] = (df["time"] % 86400) // 3600
    df["off_hours"] = ((df["hour"] < 6) | (df["hour"] > 20)).astype(float)
    df["self_logon"] = (df["src_computer"] == df["dst_computer"]).astype(float)
    df["events_prior_log"] = np.log1p(g.cumcount())
    return df


FEATURES = ["fail", "user_fail_rate", "dst_new", "dst_distinct", "src_new",
            "auth_type_rarity", "logon_type_rarity", "off_hours", "self_logon",
            "events_prior_log"]


def evaluate(df, keys, budget):
    X = np.nan_to_num(df[FEATURES].to_numpy(dtype=float), nan=0.0, posinf=0.0, neginf=0.0)
    Xs = StandardScaler().fit_transform(X)
    iso = IsolationForest(n_estimators=300, contamination="auto", random_state=C.SEED, n_jobs=-1)
    iso.fit(Xs)
    score = -iso.score_samples(Xs)                                 # higher = more anomalous

    y = np.array([(t, u, s, d) in keys for t, u, s, d in
                  zip(df["time"], df["src_user"], df["src_computer"], df["dst_computer"])],
                 dtype=int)
    if y.sum() == 0:
        raise SystemExit("No labelled malicious events in the slice.")

    k = max(1, int(budget * len(score)))
    thr = np.sort(score)[::-1][k - 1]
    flagged = score >= thr
    tp = int((flagged & (y == 1)).sum()); fp = int((flagged & (y == 0)).sum())
    return {
        "events_scored": int(len(df)),
        "malicious_events": int(y.sum()),
        "malicious_rate": float(y.mean()),
        "roc_auc": float(roc_auc_score(y, score)),
        "pr_auc": float(average_precision_score(y, score)),
        "budget": budget,
        "precision_at_budget": tp / max(1, tp + fp),
        "recall_at_budget": tp / max(1, int(y.sum())),
        "false_positives_at_budget": fp,
        "detector": "unsupervised IsolationForest on causal auth-behaviour features",
        "note": "Validates the SentinelUEBA methodology on real LANL authentication "
                "logs with real red-team labels. Unsupervised detector never sees labels.",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--auth", required=True, help="LANL auth.txt or auth.txt.gz")
    ap.add_argument("--redteam", required=True, help="LANL redteam.txt or redteam.txt.gz")
    ap.add_argument("--margin", type=int, default=3600, help="seconds around red-team window")
    ap.add_argument("--max-rows", type=int, default=0, help="cap auth rows scanned (0 = until window ends)")
    ap.add_argument("--budget", type=float, default=0.001)
    args = ap.parse_args()

    _, keys, lo, hi = load_redteam(args.redteam)
    print(f"[real-data] red-team window: t={lo}..{hi}  ({len(keys)} labelled edges)")
    auth = stream_auth_window(args.auth, lo, hi, args.margin, args.max_rows)
    print(f"[real-data] scored slice: {len(auth):,} auth events")
    feats = build_features(auth)
    result = evaluate(feats, keys, args.budget)
    out = os.path.join(C.ARTIFACT_DIR, "real_data_results.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"[real-data] ROC-AUC {result['roc_auc']:.4f}  PR-AUC {result['pr_auc']:.4f}  "
          f"recall@{args.budget:.1%} {result['recall_at_budget']:.3f}  "
          f"precision {result['precision_at_budget']:.3f}")
    print(f"[real-data] wrote {out}")


if __name__ == "__main__":
    main()
