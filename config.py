"""
Central configuration for SentinelUEBA.

A single source of truth for paths, population sizes, the synthetic-data schema,
the attack taxonomy, and model hyper-parameters. Everything downstream imports
from here so a run is fully reproducible from one seed.
"""
from __future__ import annotations

import os

# ----------------------------------------------------------------------------
# Reproducibility
# ----------------------------------------------------------------------------
SEED = 42

# ----------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
ARTIFACT_DIR = os.path.join(ROOT, "artifacts")
REPORT_DIR = os.path.join(ROOT, "report")
ASSET_DIR = os.path.join(ROOT, "assets")

LOGS_CSV = os.path.join(DATA_DIR, "access_logs.csv")          # full event stream (with labels)
FEATURES_PARQUET = os.path.join(DATA_DIR, "features.parquet")  # engineered per-event features
SCORED_PARQUET = os.path.join(DATA_DIR, "scored_events.parquet")  # events + risk scores + reasons
RESULTS_JSON = os.path.join(ARTIFACT_DIR, "results.json")     # evaluation metrics
MODEL_BUNDLE = os.path.join(ARTIFACT_DIR, "model_bundle.joblib")
AE_WEIGHTS = os.path.join(ARTIFACT_DIR, "autoencoder.pt")
SEQ_WEIGHTS = os.path.join(ARTIFACT_DIR, "sequence_autoencoder.pt")
FEEDBACK_CSV = os.path.join(ARTIFACT_DIR, "analyst_feedback.csv")
RUN_MANIFEST = os.path.join(ARTIFACT_DIR, "run_manifest.json")

for _d in (DATA_DIR, ARTIFACT_DIR, REPORT_DIR, ASSET_DIR):
    os.makedirs(_d, exist_ok=True)

# ----------------------------------------------------------------------------
# Population (entities whose "normal" behaviour we learn)
# ----------------------------------------------------------------------------
N_USERS = 220
N_SERVICE_ACCOUNTS = 40
N_EDGE_DEVICES = 140
DAYS = 45                     # length of the simulated log window
COLD_START_FRACTION = 0.12    # fraction of entities that join late (little/no history)

# Attack volume — the PS asks for extreme class imbalance (0.5–3% of events).
ATTACK_RATE = 0.02            # ~2% of events are anomalous

# ----------------------------------------------------------------------------
# Schema (matches the Honeywell portal's suggested synthetic-data schema)
# ----------------------------------------------------------------------------
#   entity_id           user_id / service_account / device_id
#   entity_type         user | service_account | edge_device
#   role                peer-group tag (drives cold-start baselines)
#   timestamp           access / connection time (UTC ISO8601)
#   source_ip           origin IP
#   geo_city / geo_lat / geo_lon   origin location
#   resource_accessed   file / endpoint / port / device_function
#   auth_result         SUCCESS | FAILURE
#   bytes_out           payload size (drives exfiltration detection)
#   device_os           OS / firmware version   \
#   device_mac          MAC address              } = device_fingerprint
#   protocol            protocol used           /
#   session_id          groups events into sessions (drives sequence model)
#   label               normal | <attack_type>  (ground truth; hidden at inference)
#   scenario            provenance tag for analysis (incl. benign 'insider_drift')

SCHEMA_COLUMNS = [
    "event_id", "entity_id", "entity_type", "role", "timestamp",
    "source_ip", "geo_city", "geo_lat", "geo_lon", "resource_accessed",
    "auth_result", "bytes_out", "device_os", "device_mac", "protocol",
    "session_id", "label", "scenario",
]

# ----------------------------------------------------------------------------
# Attack taxonomy — the injected anomaly classes the model must classify.
# 'normal' is the benign majority (includes legitimate 'insider_drift').
# ----------------------------------------------------------------------------
ATTACK_TYPES = [
    "brute_force",
    "impossible_travel",
    "credential_stuffing",
    "lateral_movement",
    "device_spoofing",
    "low_and_slow_exfiltration",
]
BENIGN_LABEL = "normal"
ALL_LABELS = [BENIGN_LABEL] + ATTACK_TYPES

# ----------------------------------------------------------------------------
# Cities (lat, lon) — used for geo behaviour and impossible-travel physics.
# ----------------------------------------------------------------------------
CITIES = {
    "Bengaluru":  (12.9716, 77.5946),
    "Mumbai":     (19.0760, 72.8777),
    "Delhi":      (28.7041, 77.1025),
    "Hyderabad":  (17.3850, 78.4867),
    "Pune":       (18.5204, 73.8567),
    "Chennai":    (13.0827, 80.2707),
    "Singapore":  (1.3521, 103.8198),
    "London":     (51.5074, -0.1278),
    "New York":   (40.7128, -74.0060),
    "Frankfurt":  (50.1109, 8.6821),
    "Sydney":     (-33.8688, 151.2093),
    "Dubai":      (25.2048, 55.2708),
}

# ----------------------------------------------------------------------------
# Temporal evaluation protocol. The final test window is never used for model
# fitting, channel selection, calibration, rule selection, or thresholds.
TRAIN_FRACTION = 0.50
VALIDATION_FRACTION = 0.15
FUSION_FIT_FRACTION = 0.50
PURGE_HOURS = 1

# Cold-start and adaptive-profile settings.
COLD_HISTORY = 30
PEER_PRIOR_STRENGTH = 30
PROFILE_EWMA_ALPHA = 0.04
PROFILE_HISTORY = 256

# Model hyper-parameters
# ----------------------------------------------------------------------------
# Autoencoder (per-event behavioural baseline)
AE_HIDDEN = [64, 32, 16]
AE_EPOCHS = 25
AE_BATCH = 256
AE_LR = 1e-3

# LSTM sequence auto-encoder (session-level lateral-movement detection)
SEQ_LEN = 12
LSTM_HIDDEN = 48
LSTM_EPOCHS = 12
LSTM_BATCH = 128
LSTM_LR = 1e-3

# Risk fusion — analyst alert budget (FP measured at the top-X fraction of events)
ALERT_BUDGET = 0.01           # top 1% of events by risk (matches the rubric)
ALERT_BUDGETS = (0.005, 0.01, 0.02, 0.05)

# Concept-drift detector (Page-Hinkley) — tuned to fire only on *sustained*
# per-entity shifts (re-baseline triggers), not on every noisy event.
PH_DELTA = 0.02
PH_LAMBDA = 8.0
PH_MIN_HISTORY = 30           # need this many events before drift can trip
