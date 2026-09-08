"""Operational concept-drift detection and adaptive entity baselines."""
from __future__ import annotations

from collections import defaultdict, deque

import numpy as np

import config as C


class PageHinkley:
    """Streaming one-sided Page-Hinkley change detector."""

    def __init__(self, delta=C.PH_DELTA, lam=C.PH_LAMBDA,
                 min_history=C.PH_MIN_HISTORY):
        self.delta = float(delta)
        self.lam = float(lam)
        self.min_history = int(min_history)
        self.reset()

    def reset(self):
        self.mean = 0.0
        self.n = 0
        self.cumulative = 0.0
        self.minimum = 0.0

    def update(self, value):
        value = float(value)
        self.n += 1
        self.mean += (value - self.mean) / self.n
        self.cumulative += value - self.mean - self.delta
        self.minimum = min(self.minimum, self.cumulative)
        return self.n >= self.min_history and (
            self.cumulative - self.minimum > self.lam)


def adaptive_entity_scores(df, anomaly_score, protected_mask=None,
                           history_size=C.PROFILE_HISTORY,
                           reset_entities=None):
    """Adapt a global anomaly channel to each entity's recent score history.

    A Page-Hinkley alarm starts a short re-baselining epoch. High-confidence
    rule hits are protected from profile updates so obvious attacks cannot
    poison the new baseline. The method returns per-event scores and auditable
    drift state rather than merely counting alarms.
    """
    scores = np.asarray(anomaly_score, dtype=float)
    protected = (np.zeros(len(scores), dtype=bool) if protected_mask is None
                 else np.asarray(protected_mask, dtype=bool))
    reset_entities = {str(value) for value in (reset_entities or set())}
    entities = df["entity_id"].astype(str).to_numpy()
    timestamps = df["timestamp"].to_numpy()
    event_ids = df.get("event_id")
    stable = (event_ids.to_numpy() if event_ids is not None
              else np.arange(len(df)))
    order = np.lexsort((stable, timestamps))

    histories = defaultdict(lambda: deque(maxlen=history_size))
    detectors = defaultdict(PageHinkley)
    cooldown = defaultdict(int)
    epochs = defaultdict(int)
    adjusted = np.zeros(len(scores), dtype=np.float32)
    alarm_flag = np.zeros(len(scores), dtype=bool)
    baseline_epoch = np.zeros(len(scores), dtype=np.int16)
    drift_entities = set()
    reset_applied = set()

    for pos in order:
        entity = entities[pos]
        value = float(np.clip(scores[pos], 0.0, 1.0))
        if entity in reset_entities and entity not in reset_applied:
            histories[entity].clear()
            detectors[entity] = PageHinkley()
            cooldown[entity] = 0
            epochs[entity] += 1
            reset_applied.add(entity)
        history = histories[entity]

        if len(history) >= C.PH_MIN_HISTORY:
            reference = np.sort(np.asarray(history))
            percentile = np.searchsorted(reference, value, side="right") / len(reference)
            score = 0.55 * value + 0.45 * percentile
        else:
            score = value

        fired = detectors[entity].update(value)
        if fired and not protected[pos]:
            alarm_flag[pos] = True
            drift_entities.add(entity)
            epochs[entity] += 1
            cooldown[entity] = 20
            histories[entity].clear()
            detectors[entity] = PageHinkley()

        # During an explicitly detected baseline transition, moderate deviations
        # are downgraded while protected attack evidence remains untouched.
        if cooldown[entity] > 0 and not protected[pos]:
            score = min(score, 0.55)
            cooldown[entity] -= 1

        adjusted[pos] = float(np.clip(score, 0.0, 1.0))
        baseline_epoch[pos] = epochs[entity]

        # Robust update: retain normal/moderate observations, never the extreme
        # tail or events protected by a high-confidence rule.
        if not protected[pos] and (len(history) < C.PH_MIN_HISTORY or value < 0.98):
            history.append(value)

    stats = {
        "drift_alarms": int(alarm_flag.sum()),
        "entities_with_drift": int(len(drift_entities)),
        "rebaseline_events": int((baseline_epoch > 0).sum()),
        "feedback_rebaseline_entities": int(len(reset_applied)),
        "method": "Page-Hinkley plus protected rolling entity baseline",
    }
    return adjusted, alarm_flag, baseline_epoch, stats


def detect_entity_drift(df, anomaly_score):
    """Backward-compatible summary helper used by tests and experiments."""
    _, _, _, stats = adaptive_entity_scores(df, anomaly_score)
    return stats
