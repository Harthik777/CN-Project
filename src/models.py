"""
Deliverables 2 & 3 — unsupervised behavioural models.

Two complementary unsupervised detectors learn what "normal" looks like without
ever seeing attack labels (this is how we survive extreme class imbalance and
catch novel attacks):

  * DenseAutoEncoder  — reconstructs a per-event behavioural vector; high
                        reconstruction error = the event doesn't fit learned
                        normal behaviour. This is the per-entity baseline model.
  * IsolationForest   — isolates points that are easy to separate from the mass
                        of normal events; robust, fast, few assumptions.

They are combined as an OR-style ensemble (max of the two normalised scores),
mirroring the AE + Isolation-Forest ensemble validated in the author's
`secstate-controller` intrusion-detection work: the AE catches off-manifold
behaviour, the forest adds robustness.

A GRU sequence auto-encoder (models_seq.py) adds the temporal channel for
lateral movement.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import config as C
from src.features import NUMERIC_FEATURES, CATEGORICAL_FEATURES

torch.manual_seed(C.SEED)


# ----------------------------------------------------------------------------
# feature matrix assembly (numeric + one-hot categoricals)
# ----------------------------------------------------------------------------
def build_matrix(df: pd.DataFrame, scaler: StandardScaler | None = None,
                 cat_vocab: dict | None = None):
    """Return (X, scaler, cat_vocab, feature_names). Fits scaler/vocab if None."""
    num = df[NUMERIC_FEATURES].to_numpy(dtype=np.float32)
    num = np.nan_to_num(num, nan=0.0, posinf=0.0, neginf=0.0)
    if scaler is None:
        scaler = StandardScaler().fit(num)
    num_s = scaler.transform(num).astype(np.float32)

    # one-hot categoricals with a fixed vocabulary
    if cat_vocab is None:
        cat_vocab = {
            c: sorted(set(df[c].astype(str).unique()) | {"__UNK__"})
            for c in CATEGORICAL_FEATURES
        }
    onehots, names = [], list(NUMERIC_FEATURES)
    for c in CATEGORICAL_FEATURES:
        vals = df[c].astype(str).to_numpy()
        known = set(cat_vocab[c])
        vals = np.asarray([v if v in known else "__UNK__" for v in vals])
        for v in cat_vocab[c]:
            onehots.append((vals == v).astype(np.float32))
            names.append(f"{c}={v}")
    X = np.column_stack([num_s] + onehots).astype(np.float32) if onehots else num_s
    return X, scaler, cat_vocab, names


# ----------------------------------------------------------------------------
# dense autoencoder
# ----------------------------------------------------------------------------
class DenseAutoEncoder(nn.Module):
    def __init__(self, d_in, hidden=C.AE_HIDDEN):
        super().__init__()
        enc, prev = [], d_in
        for h in hidden:
            enc += [nn.Linear(prev, h), nn.ReLU()]; prev = h
        dec, rev = [], list(reversed(hidden[:-1])) + [d_in]
        for h in rev:
            dec += [nn.Linear(prev, h), nn.ReLU()]; prev = h
        dec = dec[:-1]                                    # drop final ReLU
        self.enc, self.dec = nn.Sequential(*enc), nn.Sequential(*dec)

    def forward(self, x):
        return self.dec(self.enc(x))


def train_autoencoder(X_train, epochs=C.AE_EPOCHS, batch=C.AE_BATCH, lr=C.AE_LR, verbose=True):
    d = X_train.shape[1]
    model = DenseAutoEncoder(d)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    Xt = torch.from_numpy(X_train)
    n = len(Xt)
    model.train()
    for ep in range(epochs):
        perm = torch.randperm(n)
        tot = 0.0
        for i in range(0, n, batch):
            idx = perm[i:i + batch]
            xb = Xt[idx]
            opt.zero_grad()
            out = model(xb)
            loss = loss_fn(out, xb)
            loss.backward(); opt.step()
            tot += loss.item() * len(idx)
        if verbose and (ep % 5 == 0 or ep == epochs - 1):
            print(f"  [AE] epoch {ep+1}/{epochs}  loss={tot/n:.4f}")
    return model


def ae_scores(model, X):
    model.eval()
    with torch.no_grad():
        out = model(torch.from_numpy(X))
        err = ((out - torch.from_numpy(X)) ** 2).mean(dim=1).numpy()
    return err


# ----------------------------------------------------------------------------
# isolation forest
# ----------------------------------------------------------------------------
def train_isoforest(X_train):
    iso = IsolationForest(n_estimators=200, max_samples=min(4096, len(X_train)),
                          contamination="auto", random_state=C.SEED, n_jobs=1)
    iso.fit(X_train)
    return iso


def iso_scores(iso, X):
    # higher = more anomalous
    return -iso.score_samples(X)


# ----------------------------------------------------------------------------
# score normalisation helper (rank -> [0,1], robust to outliers)
# ----------------------------------------------------------------------------
def rank_normalise(scores, ref=None):
    """Map scores through a reference empirical CDF.

    At inference the reference must come from the training window. Ranking the
    test window against itself leaks future distribution information and makes
    a streaming score impossible to reproduce.
    """
    values = np.asarray(scores, dtype=float)
    reference = values if ref is None else np.asarray(ref, dtype=float)
    reference = np.sort(reference[np.isfinite(reference)])
    if len(reference) == 0:
        return np.zeros(len(values), dtype=np.float32)
    ranks = np.searchsorted(reference, values, side="right")
    return np.clip(ranks / len(reference), 0.0, 1.0).astype(np.float32)
