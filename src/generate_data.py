"""
Deliverable 1 — Synthetic access-log generator.

Real intrusion / access-log datasets are scarce, privacy-restricted and
domain-specific, so we generate our own with a documented behavioural model and
an injected attack taxonomy (per the Honeywell problem statement).

BEHAVIOURAL ASSUMPTIONS (the "normal" model)
--------------------------------------------
* Every entity (user / service_account / edge_device) belongs to a ROLE which
  defines a *peer group*. Peer groups give us population priors for the
  cold-start case (a brand-new entity is scored against its peers until it has
  its own history).
* Each entity has a stable habitual profile: a home city + IP block, a set of
  working hours, a small set of resources it usually touches, one device
  fingerprint (OS / MAC / protocol), and a baseline activity rate and auth
  failure rate. Normal events are these profiles sampled with noise.
* Service accounts are highly regular (tight hours, few resources, machine-like).
  Users are noisier. Edge devices are the most regular of all (a sensor phones
  home on a schedule).

INJECTED ATTACK TAXONOMY (the labelled anomalies)
-------------------------------------------------
  brute_force               rapid repeated FAILED auth from one source, short window
  impossible_travel         same entity, two distant geos within an implausible gap
  credential_stuffing       many entities, few source IPs, high failure rate
  lateral_movement          compromised entity touches an unusual breadth/sequence
                            of resources it never accessed before
  device_spoofing           a device_id reappears with a mismatched fingerprint
  low_and_slow_exfiltration gradual, small, off-hours high-byte reads over days

Plus one *benign-but-evolving* scenario used to test concept-drift handling:
  insider_drift             a legitimate entity slowly expands its hours/resources
                            (label stays 'normal' — must NOT be permanently flagged)

Ground-truth labels are written to the `label` column but are intended to be
hidden at inference; every model in this project trains without them except the
supervised attack-type classifier.

Run:  python -m src.generate_data
"""
from __future__ import annotations

import math
import numpy as np
import pandas as pd

import config as C


# ----------------------------------------------------------------------------
# small helpers (dependency-free IP / MAC / fingerprint synthesis)
# ----------------------------------------------------------------------------
OS_POOL = [
    "Windows 10.0.19045", "Windows 11.22631", "Ubuntu 22.04", "Ubuntu 20.04",
    "macOS 14.5", "RHEL 9.3", "Android 14", "iOS 17.5",
    "FreeRTOS 10.4", "Yocto 4.0", "QNX 7.1", "VxWorks 7",
]
PROTO_POOL = ["HTTPS", "SSH", "RDP", "MQTT", "Modbus/TCP", "OPC-UA", "SMB", "LDAP"]

ROLES = {
    "user": ["field_engineer", "plant_operator", "sre", "analyst", "manager", "contractor"],
    "service_account": ["ci_runner", "backup_svc", "etl_svc", "scanner_svc"],
    "edge_device": ["hvac_controller", "fire_panel", "plc", "gateway", "meter", "camera"],
}

# resource vocabulary per entity_type (files / endpoints / ports / device fns)
RESOURCES = {
    "user": [f"/app/{n}" for n in
             ("dashboard", "reports", "billing", "hr", "tickets", "wiki",
              "source", "deploy", "vpn", "email", "crm", "admin_console")],
    "service_account": [f"api:/v1/{n}" for n in
                        ("ingest", "metrics", "backup", "sync", "auth", "jobs",
                         "artifacts", "secrets", "queue")],
    "edge_device": [f"fn:{n}" for n in
                    ("telemetry", "setpoint", "firmware_pull", "heartbeat",
                     "alarm", "config", "diagnostics", "port:502", "port:1883")],
}


def _rand_ip(rng, prefix=None):
    if prefix is None:
        return f"{rng.integers(11,223)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"
    return f"{prefix}.{rng.integers(1,254)}"


def _rand_mac(rng):
    return ":".join(f"{rng.integers(0,255):02x}" for _ in range(6))


def _haversine_km(a, b):
    (lat1, lon1), (lat2, lon2) = a, b
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


# ----------------------------------------------------------------------------
# entity profiles
# ----------------------------------------------------------------------------
def build_entities(rng):
    entities = []
    city_names = list(C.CITIES.keys())

    def make(etype, n, prefix):
        for i in range(n):
            role = rng.choice(ROLES[etype])
            home = rng.choice(city_names[:6]) if etype != "user" else rng.choice(city_names[:8])
            # work hours: (start, length) — service/edge are tighter
            if etype == "service_account":
                start, length, base_rate, fail = rng.integers(0, 6), 24, rng.uniform(20, 60), 0.01
            elif etype == "edge_device":
                start, length, base_rate, fail = 0, 24, rng.uniform(15, 40), 0.005
            else:
                start, length, base_rate, fail = rng.integers(7, 11), rng.integers(8, 11), rng.uniform(4, 18), 0.03
            n_res = {"user": 6, "service_account": 4, "edge_device": 4}[etype]
            typ_res = list(rng.choice(RESOURCES[etype], size=min(n_res, len(RESOURCES[etype])), replace=False))
            joined = 0
            if rng.random() < C.COLD_START_FRACTION:            # cold-start entity: joins late
                joined = int(rng.integers(int(C.DAYS * 0.7), C.DAYS - 2))
            entities.append(dict(
                entity_id=f"{prefix}{i:04d}",
                entity_type=etype,
                role=role,
                home_city=home,
                ip_prefix=f"{rng.integers(11,223)}.{rng.integers(0,255)}.{rng.integers(0,255)}",
                work_start=int(start),
                work_len=int(length),
                base_rate=float(base_rate),
                base_fail=float(fail),
                typ_res=typ_res,
                device_os=rng.choice(OS_POOL),
                device_mac=_rand_mac(rng),
                protocol=rng.choice(PROTO_POOL),
                joined_day=joined,
            ))

    make("user", C.N_USERS, "U")
    make("service_account", C.N_SERVICE_ACCOUNTS, "S")
    make("edge_device", C.N_EDGE_DEVICES, "D")
    return {e["entity_id"]: e for e in entities}


# ----------------------------------------------------------------------------
# normal event sampling
# ----------------------------------------------------------------------------
def _day_seconds(day, hour, rng):
    minute = int(rng.integers(0, 60))
    sec = int(rng.integers(0, 60))
    return day * 86400 + hour * 3600 + minute * 60 + sec


def build_itinerary(ent, rng):
    """Per-day city for an entity. Home on most days; occasionally a multi-day
    trip to another city (a day-scale relocation, so any legitimate geo change
    happens at plane-plausible speed — never continent-hopping within an hour)."""
    itin = {}
    if rng.random() < 0.15 and ent["entity_type"] == "user":   # only users travel
        n_trips = int(rng.integers(1, 3))
        for _ in range(n_trips):
            dest = rng.choice(list(C.CITIES.keys()))
            start = int(rng.integers(0, max(1, C.DAYS - 5)))
            for d in range(start, start + int(rng.integers(2, 6))):
                itin[d] = dest
    return itin


def sample_normal(ent, rng, city, drift_state=None):
    """One normal event for `ent` on a given day-city. drift_state optionally
    widens the profile over time to emulate legitimate insider drift."""
    # working-hour biased, with occasional off-hours noise
    if ent["work_len"] >= 24:
        hour = int(rng.integers(0, 24))
    elif rng.random() < 0.9:
        hour = (ent["work_start"] + int(rng.integers(0, ent["work_len"]))) % 24
    else:
        hour = int(rng.integers(0, 24))

    lat, lon = C.CITIES[city]
    lat += rng.normal(0, 0.01); lon += rng.normal(0, 0.01)

    res_pool = list(ent["typ_res"])
    if drift_state is not None:
        res_pool = res_pool + drift_state["extra_res"]
    resource = rng.choice(res_pool)

    auth = "FAILURE" if rng.random() < ent["base_fail"] else "SUCCESS"
    bytes_out = float(max(0, rng.lognormal(mean=8.5, sigma=1.0)))   # ~5 KB median
    return dict(
        entity_id=ent["entity_id"], entity_type=ent["entity_type"], role=ent["role"],
        hour=hour, geo_city=city, geo_lat=round(lat, 4), geo_lon=round(lon, 4),
        source_ip=_rand_ip(rng, ent["ip_prefix"]), resource_accessed=resource,
        auth_result=auth, bytes_out=round(bytes_out, 1),
        device_os=ent["device_os"], device_mac=ent["device_mac"], protocol=ent["protocol"],
        label=C.BENIGN_LABEL, scenario="normal",
    )


# ----------------------------------------------------------------------------
# attack injectors — each returns a list of event dicts (day-scoped)
# ----------------------------------------------------------------------------
def inj_brute_force(ent, day, rng):
    ev = []
    attacker_ip = _rand_ip(rng)
    hour = int(rng.integers(0, 24))
    n = int(rng.integers(40, 160))
    for _ in range(n):
        lat, lon = C.CITIES[ent["home_city"]]
        ev.append(dict(
            entity_id=ent["entity_id"], entity_type=ent["entity_type"], role=ent["role"],
            hour=hour, geo_city=ent["home_city"], geo_lat=round(lat, 4), geo_lon=round(lon, 4),
            source_ip=attacker_ip, resource_accessed="auth:/login",
            auth_result="FAILURE" if rng.random() < 0.95 else "SUCCESS",
            bytes_out=round(float(rng.uniform(50, 400)), 1),
            device_os=ent["device_os"], device_mac=ent["device_mac"], protocol="HTTPS",
            label="brute_force", scenario="brute_force",
        ))
    return ev


def inj_impossible_travel(ent, day, rng):
    home = ent["home_city"]
    far = rng.choice([c for c in C.CITIES if _haversine_km(C.CITIES[home], C.CITIES[c]) > 4000])
    hour = int(rng.integers(0, 22))
    ev = []
    # The departure login looks perfectly normal; the ANOMALY is the second login,
    # geographically impossible given the time gap. Only the arrival event is labelled
    # the attack — that is the only detectable signal (fixes over-labelling).
    for city, hr, lbl in [(home, hour, "normal"), (far, hour + 1, "impossible_travel")]:
        lat, lon = C.CITIES[city]
        ev.append(dict(
            entity_id=ent["entity_id"], entity_type=ent["entity_type"], role=ent["role"],
            hour=hr % 24, geo_city=city, geo_lat=round(lat, 4), geo_lon=round(lon, 4),
            source_ip=_rand_ip(rng), resource_accessed=rng.choice(ent["typ_res"]),
            auth_result="SUCCESS", bytes_out=round(float(rng.lognormal(8.5, 1.0)), 1),
            device_os=ent["device_os"], device_mac=ent["device_mac"], protocol=ent["protocol"],
            label=lbl, scenario="impossible_travel",
        ))
    return ev


def inj_credential_stuffing(victims, day, rng):
    ev = []
    attacker_ips = [_rand_ip(rng) for _ in range(int(rng.integers(1, 4)))]
    hour = int(rng.integers(0, 24))
    for ent in victims:
        lat, lon = C.CITIES[ent["home_city"]]
        ev.append(dict(
            entity_id=ent["entity_id"], entity_type=ent["entity_type"], role=ent["role"],
            hour=hour, geo_city=ent["home_city"], geo_lat=round(lat, 4), geo_lon=round(lon, 4),
            source_ip=rng.choice(attacker_ips), resource_accessed="auth:/login",
            auth_result="FAILURE" if rng.random() < 0.85 else "SUCCESS",
            bytes_out=round(float(rng.uniform(50, 400)), 1),
            device_os=ent["device_os"], device_mac=ent["device_mac"], protocol="HTTPS",
            label="credential_stuffing", scenario="credential_stuffing",
        ))
    return ev


def inj_lateral_movement(ent, day, rng):
    ev = []
    hour = int(rng.integers(0, 24))
    pool = [r for r in sum(RESOURCES.values(), []) if r not in ent["typ_res"]]
    touched = list(rng.choice(pool, size=int(rng.integers(8, 18)), replace=False))
    for i, res in enumerate(touched):                          # unusual breadth, escalating
        lat, lon = C.CITIES[ent["home_city"]]
        ev.append(dict(
            entity_id=ent["entity_id"], entity_type=ent["entity_type"], role=ent["role"],
            hour=hour, geo_city=ent["home_city"], geo_lat=round(lat, 4), geo_lon=round(lon, 4),
            source_ip=_rand_ip(rng, ent["ip_prefix"]), resource_accessed=res,
            auth_result="SUCCESS", bytes_out=round(float(rng.lognormal(9.0, 1.0)), 1),
            device_os=ent["device_os"], device_mac=ent["device_mac"], protocol=ent["protocol"],
            label="lateral_movement", scenario="lateral_movement",
        ))
    return ev


def inj_device_spoofing(ent, day, rng):
    ev = []
    hour = int(rng.integers(0, 24))
    spoof_os, spoof_mac = rng.choice(OS_POOL), _rand_mac(rng)   # mismatched fingerprint
    for _ in range(int(rng.integers(3, 9))):
        lat, lon = C.CITIES[ent["home_city"]]
        ev.append(dict(
            entity_id=ent["entity_id"], entity_type=ent["entity_type"], role=ent["role"],
            hour=hour, geo_city=ent["home_city"], geo_lat=round(lat, 4), geo_lon=round(lon, 4),
            source_ip=_rand_ip(rng), resource_accessed=rng.choice(ent["typ_res"]),
            auth_result="SUCCESS", bytes_out=round(float(rng.lognormal(8.5, 1.0)), 1),
            device_os=spoof_os, device_mac=spoof_mac, protocol=ent["protocol"],
            label="device_spoofing", scenario="device_spoofing",
        ))
    return ev


def inj_low_and_slow(ent, day, rng, n_events):
    """Small off-hours high-byte reads; caller spreads these across many days."""
    lat, lon = C.CITIES[ent["home_city"]]
    return dict(
        entity_id=ent["entity_id"], entity_type=ent["entity_type"], role=ent["role"],
        hour=int(rng.choice([0, 1, 2, 3, 23])), geo_city=ent["home_city"],
        geo_lat=round(lat, 4), geo_lon=round(lon, 4),
        source_ip=_rand_ip(rng, ent["ip_prefix"]),
        resource_accessed=rng.choice([r for r in ent["typ_res"]] + ["/data/export"]),
        auth_result="SUCCESS",
        bytes_out=round(float(rng.lognormal(11.5, 0.4)), 1),   # elevated but not huge
        device_os=ent["device_os"], device_mac=ent["device_mac"], protocol=ent["protocol"],
        label="low_and_slow_exfiltration", scenario="low_and_slow_exfiltration",
    )


# ----------------------------------------------------------------------------
# main generation loop
# ----------------------------------------------------------------------------
def generate(seed=C.SEED, verbose=True, output_path=None):
    rng = np.random.default_rng(seed)
    entities = build_entities(rng)
    ent_list = list(entities.values())
    rows = []

    # pick drift entities (benign, evolving) up front
    drift_ids = set(rng.choice([e["entity_id"] for e in ent_list],
                               size=max(3, int(0.02 * len(ent_list))), replace=False))
    drift_states = {eid: {"extra_res": []} for eid in drift_ids}

    # per-entity daily itinerary (stable home + occasional legitimate trips)
    itineraries = {e["entity_id"]: build_itinerary(e, rng) for e in ent_list}

    # ---- normal traffic, day by day (so drift can evolve over time) ----
    for day in range(C.DAYS):
        for ent in ent_list:
            if day < ent["joined_day"]:
                continue
            # legitimate insider drift: gradually add a new resource + widen hours
            ds = None
            if ent["entity_id"] in drift_ids:
                ds = drift_states[ent["entity_id"]]
                if day > C.DAYS * 0.5 and rng.random() < 0.06 and len(ds["extra_res"]) < 4:
                    ds["extra_res"].append(rng.choice(RESOURCES[ent["entity_type"]]))
                if ds["extra_res"]:
                    ent = {**ent, "work_len": min(24, ent["work_len"] + 3)}
            city = itineraries[ent["entity_id"]].get(day, ent["home_city"])
            n = rng.poisson(ent["base_rate"])
            for _ in range(int(n)):
                e = sample_normal(ent, rng, city, drift_state=ds)
                if ent["entity_id"] in drift_ids and ds and ds["extra_res"]:
                    e["scenario"] = "insider_drift"            # benign, but tag it
                e["timestamp_s"] = _day_seconds(day, e.pop("hour"), rng)
                rows.append(e)

    n_normal = len(rows)
    target_attack = int(n_normal * C.ATTACK_RATE / (1 - C.ATTACK_RATE))

    # ---- inject attacks until we hit the target imbalance ----
    def add(ev_list, day):
        for e in ev_list:
            e["timestamp_s"] = _day_seconds(day, e.pop("hour"), rng)
            rows.append(e)

    injected = 0

    def active(day):
        """Entities already onboarded by `day` (includes recently-joined ones,
        so a share of attacks naturally target cold-start entities)."""
        return [e for e in ent_list if e["joined_day"] <= day]

    while injected < target_attack:
        day = int(rng.integers(1, C.DAYS))
        pool = active(day)
        kind = rng.choice(["brute_force", "impossible_travel", "credential_stuffing",
                           "lateral_movement", "device_spoofing", "low_and_slow_exfiltration"],
                          p=[0.22, 0.14, 0.16, 0.18, 0.12, 0.18])
        if kind == "brute_force":
            ev = inj_brute_force(rng.choice(pool), day, rng); add(ev, day); injected += len(ev)
        elif kind == "impossible_travel":
            ev = inj_impossible_travel(rng.choice(pool), day, rng); add(ev, day); injected += len(ev)
        elif kind == "credential_stuffing":
            vics = list(rng.choice(pool, size=int(rng.integers(10, 30)), replace=False))
            ev = inj_credential_stuffing(vics, day, rng); add(ev, day); injected += len(ev)
        elif kind == "lateral_movement":
            ev = inj_lateral_movement(rng.choice(pool), day, rng); add(ev, day); injected += len(ev)
        elif kind == "device_spoofing":
            devs = [e for e in pool if e["entity_type"] == "edge_device"]
            ev = inj_device_spoofing(rng.choice(devs), day, rng); add(ev, day); injected += len(ev)
        else:  # low_and_slow spread across several days
            ent = rng.choice(pool)
            span = int(rng.integers(5, 15))
            lo = max(1, ent["joined_day"])                       # earliest day the entity exists
            hi = max(lo + 1, C.DAYS - span)                      # guarantee a valid [lo, hi) window
            start = int(rng.integers(lo, hi))
            for d in range(start, start + span):
                for _ in range(int(rng.integers(1, 4))):
                    e = inj_low_and_slow(ent, d, rng, span)
                    e["timestamp_s"] = _day_seconds(d, e.pop("hour"), rng)
                    rows.append(e); injected += 1

    # ---- assemble dataframe ----
    df = pd.DataFrame(rows)
    df = df.sort_values("timestamp_s").reset_index(drop=True)
    df.insert(0, "event_id", np.arange(len(df)))
    df["timestamp"] = pd.to_datetime(df["timestamp_s"], unit="s", origin="2026-06-01")
    # session id: (entity, 30-min bucket)
    bucket = (df["timestamp_s"] // 1800).astype(int)
    df["session_id"] = df["entity_id"] + "_" + bucket.astype(str)
    df = df.drop(columns=["timestamp_s"])

    df = df[C.SCHEMA_COLUMNS]
    destination = output_path or C.LOGS_CSV
    df.to_csv(destination, index=False)

    if verbose:
        n = len(df)
        atk = df[df.label != C.BENIGN_LABEL]
        print(f"[generate] entities: {len(entities)}  events: {n:,}")
        print(f"[generate] anomalies: {len(atk):,} ({100*len(atk)/n:.2f}%)  "
              f"cold-start entities: {sum(e['joined_day']>0 for e in ent_list)}  "
              f"drift entities: {len(drift_ids)}")
        print("[generate] label distribution:")
        for lbl, c in df.label.value_counts().items():
            print(f"           {lbl:<28} {c:>7,}")
        print(f"[generate] wrote {destination}")
    return df


if __name__ == "__main__":
    generate()
