"""Small synthetic inputs; no stored scores or target labels enter inference."""
from datetime import datetime, timedelta, timezone


def scenarios():
    start = datetime(2026, 9, 1, 9, tzinfo=timezone.utc)
    baseline = []
    for i in range(120):
        user = i % 4
        baseline.append(dict(
            event_id=i, timestamp=(start + timedelta(minutes=i)).isoformat(),
            entity_id=f"demo_user_{user}", entity_type="user", role="analyst",
            source_ip=f"192.0.2.{user+10}", geo_city="Bengaluru",
            geo_lat=12.9716, geo_lon=77.5946, resource_accessed="api:/v1/reports",
            auth_result="SUCCESS", bytes_out=1000 + (i % 7)*100,
            device_os="Windows 11", device_mac=f"02:00:00:00:00:{user+10:02x}",
            protocol="HTTPS", session_id=f"baseline_{user}_{i//30}"))
    attack = []
    for j in range(48):
        user = j % 12
        row = dict(baseline[user % 4])
        row.update(event_id=120+j,
                   timestamp=(start + timedelta(minutes=125, seconds=j*2)).isoformat(),
                   entity_id=f"demo_user_{user}", source_ip="203.0.113.66",
                   auth_result="FAILURE", bytes_out=0,
                   session_id=f"campaign_{user}")
        attack.append(row)
    return {
        "baseline": {"title": "Establish normal activity", "events": baseline,
                     "description": "120 successful accesses from four synthetic principals."},
        "attack": {"title": "Replay credential stuffing", "events": attack,
                   "description": "48 failed logins from one IP across twelve principals. Actual model outputs are computed on submission."},
    }
