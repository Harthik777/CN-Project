"""
Causal feature engineering for SentinelUEBA.

The same stateful engine is used for offline replay and online inference. Every
feature for event t is computed from that event and state created by events
strictly before t. No entity modes, IP buckets, session summaries, or score
normalisers are allowed to look into the future.

Run:
    python -m src.features
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
import math

import numpy as np
import pandas as pd

import config as C


NUMERIC_FEATURES = [
    "hour",
    "is_off_hours",
    "hour_deviation",
    "peer_hour_deviation",
    "fail",
    "log_bytes",
    "bytes_z",
    "peer_bytes_z",
    "offhour_bytes_24h_log",
    "entity_fail_rate_1h",
    "entity_event_count_5min",
    "entity_hist_count_log",
    "cold_start_weight",
    "resource_is_new",
    "entity_new_resource_rate",
    "peer_resource_rarity",
    "session_breadth",
    "session_new_resource_rate",
    "geo_velocity_kmh",
    "geo_dist_from_home_km",
    "device_mismatch",
    "ip_distinct_entities_1h",
    "ip_fail_rate_1h",
    "ip_event_count_5min",
]

# Role is deliberately included: it is the peer-group prior for entities with
# little history. An explicit unknown bucket is added by models.build_matrix.
CATEGORICAL_FEATURES = ["entity_type", "role", "protocol"]


def _haversine(lat1, lon1, lat2, lon2):
    if any(pd.isna(v) for v in (lat1, lon1, lat2, lon2)):
        return 0.0
    radius = 6371.0
    p1, p2 = math.radians(float(lat1)), math.radians(float(lat2))
    dphi = math.radians(float(lat2) - float(lat1))
    dlambda = math.radians(float(lon2) - float(lon1))
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(min(1.0, max(0.0, h))))


@dataclass
class EWStats:
    """Exponentially weighted mean/variance using only prior observations."""

    alpha: float = C.PROFILE_EWMA_ALPHA
    n: int = 0
    mean: float = 0.0
    var: float = 1.0

    def update(self, value: float):
        value = float(value)
        if self.n == 0:
            self.mean = value
            self.var = 1.0
        else:
            delta = value - self.mean
            self.mean += self.alpha * delta
            self.var = max(1e-4, (1 - self.alpha) * (self.var + self.alpha * delta * delta))
        self.n += 1

    def z(self, value: float):
        return (float(value) - self.mean) / max(math.sqrt(self.var), 1e-3)


@dataclass
class CircularStats:
    """EWMA profile for hour-of-day, represented on the unit circle."""

    alpha: float = C.PROFILE_EWMA_ALPHA
    n: int = 0
    sin_mean: float = 0.0
    cos_mean: float = 0.0

    def update(self, hour: float):
        angle = 2 * math.pi * float(hour) / 24.0
        s, c = math.sin(angle), math.cos(angle)
        if self.n == 0:
            self.sin_mean, self.cos_mean = s, c
        else:
            self.sin_mean = (1 - self.alpha) * self.sin_mean + self.alpha * s
            self.cos_mean = (1 - self.alpha) * self.cos_mean + self.alpha * c
        self.n += 1

    def deviation(self, hour: float):
        if self.n == 0:
            return 0.0
        current = 2 * math.pi * float(hour) / 24.0
        centre = math.atan2(self.sin_mean, self.cos_mean)
        delta = abs(math.atan2(math.sin(current - centre), math.cos(current - centre)))
        return delta / math.pi


class OnlineFeatureBuilder:
    """Stateful event transformer suitable for chronological stream replay."""

    def __init__(self):
        self.entity_count = defaultdict(int)
        self.entity_bytes = defaultdict(EWStats)
        self.role_bytes = defaultdict(EWStats)
        self.entity_hours = defaultdict(CircularStats)
        self.role_hours = defaultdict(CircularStats)
        self.entity_fingerprints = defaultdict(Counter)
        self.entity_cities = defaultdict(Counter)
        self.entity_resources = defaultdict(Counter)
        self.role_resources = defaultdict(Counter)
        self.role_resource_total = defaultdict(int)
        self.entity_novelty = defaultdict(EWStats)
        self.entity_last_geo = {}

        self.entity_fail_window = defaultdict(deque)
        self.entity_burst_window = defaultdict(deque)
        self.entity_offhour_bytes = defaultdict(deque)

        self.ip_hour_window = defaultdict(deque)
        self.ip_burst_window = defaultdict(deque)
        self.ip_entity_counts = defaultdict(Counter)
        self.ip_fail_sum = defaultdict(float)

        self.session_resources = defaultdict(set)
        self.session_new_count = defaultdict(int)
        self.session_count = defaultdict(int)

    @staticmethod
    def _expire_time(q, cutoff):
        while q and q[0][0] < cutoff:
            q.popleft()

    @staticmethod
    def _mode(counter: Counter):
        return counter.most_common(1)[0][0] if counter else None

    def update(self, row) -> dict[str, float]:
        ts = pd.Timestamp(getattr(row, "timestamp"))
        entity = str(getattr(row, "entity_id"))
        role = str(getattr(row, "role"))
        source_ip = str(getattr(row, "source_ip"))
        session = str(getattr(row, "session_id"))
        resource = str(getattr(row, "resource_accessed"))
        city = str(getattr(row, "geo_city"))
        hour = ts.hour + ts.minute / 60.0 + ts.second / 3600.0
        fail = float(getattr(row, "auth_result") == "FAILURE")
        log_bytes = math.log1p(max(0.0, float(getattr(row, "bytes_out"))))
        off_hours = float(hour < 6 or hour > 21)

        hist = self.entity_count[entity]
        cold_weight = max(0.0, 1.0 - hist / max(1, C.COLD_HISTORY))

        # Peer-shrunk adaptive profiles. A new entity uses its role baseline;
        # the entity profile takes over smoothly as history accumulates.
        e_bytes = self.entity_bytes[entity]
        p_bytes = self.role_bytes[role]
        peer_bytes_z = p_bytes.z(log_bytes) if p_bytes.n >= 5 else 0.0
        if e_bytes.n >= 3:
            own_z = e_bytes.z(log_bytes)
            bytes_z = (1 - cold_weight) * own_z + cold_weight * peer_bytes_z
        else:
            bytes_z = peer_bytes_z

        e_hours = self.entity_hours[entity]
        p_hours = self.role_hours[role]
        peer_hour_dev = p_hours.deviation(hour)
        own_hour_dev = e_hours.deviation(hour)
        hour_dev = ((1 - cold_weight) * own_hour_dev + cold_weight * peer_hour_dev
                    if e_hours.n else peer_hour_dev)

        # Per-entity resource novelty plus role-relative rarity for cold start.
        entity_resource_count = self.entity_resources[entity][resource]
        resource_is_new = float(hist > 0 and entity_resource_count == 0)
        novelty_profile = self.entity_novelty[entity]
        prior_novelty = novelty_profile.mean if novelty_profile.n else 0.0
        entity_new_rate = 0.8 * prior_novelty + 0.2 * resource_is_new
        role_total = self.role_resource_total[role]
        role_seen = self.role_resources[role][resource]
        peer_rarity = -math.log((role_seen + 1.0) / (role_total + len(C.ALL_LABELS) + 1.0))
        peer_rarity = min(peer_rarity, 12.0)

        # Session features are prefixes, never full-session summaries.
        seen_session = self.session_resources[session]
        session_new = int(entity_resource_count == 0 and resource not in seen_session)
        seen_session.add(resource)
        self.session_count[session] += 1
        self.session_new_count[session] += session_new
        session_breadth = float(len(seen_session))
        session_new_rate = self.session_new_count[session] / self.session_count[session]

        # Fingerprint baseline is the most common fingerprint among prior events.
        fingerprint = f"{getattr(row, 'device_os')}|{getattr(row, 'device_mac')}"
        baseline_fp = self._mode(self.entity_fingerprints[entity])
        device_mismatch = float(hist >= 3 and baseline_fp is not None and fingerprint != baseline_fp)

        # Prior location and causal home-city mode.
        lat, lon = C.CITIES.get(city, (float(getattr(row, "geo_lat")),
                                        float(getattr(row, "geo_lon"))))
        previous = self.entity_last_geo.get(entity)
        if previous is None:
            velocity = 0.0
        else:
            prev_ts, prev_lat, prev_lon = previous
            hours = max((ts - prev_ts).total_seconds() / 3600.0, 1e-3)
            velocity = min(20000.0, _haversine(lat, lon, prev_lat, prev_lon) / hours)
        home_city = self._mode(self.entity_cities[entity])
        if home_city is None:
            home_distance = 0.0
        else:
            home_lat, home_lon = C.CITIES.get(home_city, (lat, lon))
            home_distance = _haversine(lat, lon, home_lat, home_lon)

        # Entity rolling windows include the current event and prior events only.
        fail_q = self.entity_fail_window[entity]
        self._expire_time(fail_q, ts - pd.Timedelta(hours=1))
        fail_q.append((ts, fail))
        entity_fail_rate = sum(v for _, v in fail_q) / len(fail_q)

        burst_q = self.entity_burst_window[entity]
        while burst_q and burst_q[0] < ts - pd.Timedelta(minutes=5):
            burst_q.popleft()
        burst_q.append(ts)

        # Per-IP windows are true streaming windows, replacing the leaky fixed
        # bucket transform that exposed events later in the same bucket.
        ip_q = self.ip_hour_window[source_ip]
        ip_counts = self.ip_entity_counts[source_ip]
        while ip_q and ip_q[0][0] < ts - pd.Timedelta(hours=1):
            _, old_entity, old_fail = ip_q.popleft()
            ip_counts[old_entity] -= 1
            if ip_counts[old_entity] <= 0:
                del ip_counts[old_entity]
            self.ip_fail_sum[source_ip] -= old_fail
        ip_q.append((ts, entity, fail))
        ip_counts[entity] += 1
        self.ip_fail_sum[source_ip] += fail

        ip_burst = self.ip_burst_window[source_ip]
        while ip_burst and ip_burst[0] < ts - pd.Timedelta(minutes=5):
            ip_burst.popleft()
        ip_burst.append(ts)

        # Cumulative off-hours volume exposes low-and-slow exfiltration without
        # pretending each individual event must be huge.
        off_q = self.entity_offhour_bytes[entity]
        self._expire_time(off_q, ts - pd.Timedelta(hours=24))
        off_q.append((ts, float(getattr(row, "bytes_out")) * off_hours))
        offhour_bytes_24h = math.log1p(sum(v for _, v in off_q))

        result = {
            "hour": hour / 23.999,
            "is_off_hours": off_hours,
            "hour_deviation": float(np.clip(hour_dev, 0, 1)),
            "peer_hour_deviation": float(np.clip(peer_hour_dev, 0, 1)),
            "fail": fail,
            "log_bytes": log_bytes,
            "bytes_z": float(np.clip(bytes_z, -8, 8)),
            "peer_bytes_z": float(np.clip(peer_bytes_z, -8, 8)),
            "offhour_bytes_24h_log": offhour_bytes_24h,
            "entity_fail_rate_1h": entity_fail_rate,
            "entity_event_count_5min": math.log1p(len(burst_q)),
            "entity_hist_count": hist,
            "entity_hist_count_log": math.log1p(hist),
            "cold_start_weight": cold_weight,
            "resource_is_new": resource_is_new,
            "entity_new_resource_rate": entity_new_rate,
            "peer_resource_rarity": peer_rarity,
            "session_breadth": session_breadth,
            "session_new_resource_rate": session_new_rate,
            "geo_velocity_kmh": velocity,
            "geo_dist_from_home_km": home_distance,
            "device_mismatch": device_mismatch,
            "ip_distinct_entities_1h": math.log1p(len(ip_counts)),
            "ip_fail_rate_1h": self.ip_fail_sum[source_ip] / len(ip_q),
            "ip_event_count_5min": math.log1p(len(ip_burst)),
        }

        # Update adaptive profile state only after computing the current features.
        self.entity_count[entity] += 1
        e_bytes.update(log_bytes)
        p_bytes.update(log_bytes)
        e_hours.update(hour)
        p_hours.update(hour)
        self.entity_fingerprints[entity][fingerprint] += 1
        self.entity_cities[entity][city] += 1
        self.entity_resources[entity][resource] += 1
        self.role_resources[role][resource] += 1
        self.role_resource_total[role] += 1
        novelty_profile.update(resource_is_new)
        self.entity_last_geo[entity] = (ts, lat, lon)
        return result


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Replay a dataframe chronologically through the online feature engine."""
    frame = df.copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=False)
    sort_cols = ["timestamp"] + (["event_id"] if "event_id" in frame.columns else [])
    frame = frame.sort_values(sort_cols, kind="stable").reset_index(drop=True)

    engine = OnlineFeatureBuilder()
    values = defaultdict(list)
    for row in frame.itertuples(index=False):
        event_features = engine.update(row)
        for name, value in event_features.items():
            values[name].append(value)
    for name, column in values.items():
        frame[name] = np.asarray(column)
    return frame


def main():
    raw = pd.read_csv(C.LOGS_CSV)
    features = build_features(raw)
    features.to_parquet(C.FEATURES_PARQUET, index=False)
    print(f"[features] built {len(NUMERIC_FEATURES)} causal numeric features "
          f"for {len(features):,} events")
    print(f"[features] wrote {C.FEATURES_PARQUET}")


if __name__ == "__main__":
    main()
