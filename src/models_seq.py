"""
Causal GRU sequence autoencoder.

Each event is scored from its session prefix ending at that event. The previous
implementation assigned a full-session error to every member, which allowed an
early event to inherit evidence from events that had not happened yet.
"""
from __future__ import annotations

from collections import defaultdict, deque

import numpy as np
import torch
import torch.nn as nn

import config as C

torch.manual_seed(C.SEED)


class GRUAutoEncoder(nn.Module):
    def __init__(self, d_in, hidden=C.LSTM_HIDDEN):
        super().__init__()
        self.d_in = int(d_in)
        self.hidden = int(hidden)
        self.enc = nn.GRU(d_in, hidden, batch_first=True)
        self.dec = nn.GRU(hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, d_in)

    def forward(self, x):
        _, h = self.enc(x)
        latent = h.transpose(0, 1).repeat(1, x.size(1), 1)
        decoded, _ = self.dec(latent)
        return self.out(decoded)


def build_prefix_index(df, seq_len=C.SEQ_LEN):
    """Return [n_events, seq_len] row indices for each event's causal prefix."""
    n = len(df)
    prefix = np.full((n, seq_len), -1, dtype=np.int32)
    history = defaultdict(lambda: deque(maxlen=seq_len))
    order = np.lexsort((
        df.get("event_id", np.arange(n)).to_numpy(),
        df["timestamp"].to_numpy(),
    ))
    sessions = df["session_id"].astype(str).to_numpy()
    for pos in order:
        q = history[sessions[pos]]
        q.append(int(pos))
        indices = list(q)
        prefix[pos, -len(indices):] = indices
    return prefix


def materialize_prefixes(X, prefix_index):
    mask = prefix_index >= 0
    safe = np.where(mask, prefix_index, 0)
    sequences = X[safe].astype(np.float32, copy=True)
    sequences[~mask] = 0.0
    return sequences, mask.astype(np.float32)


def clean_training_events(prefix_index, labels, candidate_mask):
    """Keep candidate events whose complete visible prefix is benign."""
    labels = np.asarray(labels)
    positions = np.where(candidate_mask)[0]
    clean = []
    for pos in positions:
        idx = prefix_index[pos]
        idx = idx[idx >= 0]
        if len(idx) and np.all(labels[idx] == C.BENIGN_LABEL):
            clean.append(pos)
    return np.asarray(clean, dtype=np.int64)


def train_seq_ae(X, prefix_index, train_events, epochs=C.LSTM_EPOCHS,
                 batch=C.LSTM_BATCH, lr=C.LSTM_LR, verbose=True):
    sequences, mask = materialize_prefixes(X, prefix_index[train_events])
    model = GRUAutoEncoder(X.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    s_tensor = torch.from_numpy(sequences)
    m_tensor = torch.from_numpy(mask).unsqueeze(-1)
    n = len(s_tensor)
    model.train()
    for epoch in range(epochs):
        permutation = torch.randperm(n)
        total = 0.0
        for start in range(0, n, batch):
            idx = permutation[start:start + batch]
            xb, mb = s_tensor[idx], m_tensor[idx]
            optimizer.zero_grad()
            reconstructed = model(xb)
            loss = (((reconstructed - xb) ** 2) * mb).sum() / (
                mb.sum().clamp(min=1) * xb.shape[2])
            loss.backward()
            optimizer.step()
            total += loss.item() * len(idx)
        if verbose and (epoch % 4 == 0 or epoch == epochs - 1):
            print(f"  [SEQ] epoch {epoch + 1}/{epochs} loss={total / max(1, n):.4f}")
    return model


def seq_event_scores(model, X, prefix_index, batch=1024):
    """Score only the current event at the end of each causal prefix."""
    scores = np.zeros(len(prefix_index), dtype=np.float32)
    model.eval()
    with torch.no_grad():
        for start in range(0, len(prefix_index), batch):
            stop = min(start + batch, len(prefix_index))
            sequences, _ = materialize_prefixes(X, prefix_index[start:stop])
            xb = torch.from_numpy(sequences)
            reconstructed = model(xb)
            current_error = ((reconstructed[:, -1, :] - xb[:, -1, :]) ** 2).mean(dim=1)
            scores[start:stop] = current_error.numpy()
    return scores
