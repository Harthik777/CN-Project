"""Reproducible, sequential HTTP experiments against a running Sentinel API.

Uses synthetic access events transported over real HTTP(S), not packet capture.
No automatic retries: failed runs exit nonzero and retain partial evidence.
Session credentials stay in memory and are never included in the report.
"""
import argparse
import hashlib
import json
import math
import platform
import statistics
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parent.parent
NUMERIC_FIELDS = ("risk", "attack_prob", "ae_score", "iso_score", "seq_score",
                  "adaptive_unsup", "entity_hist_count")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def equivalent(expected, actual):
    require(len(expected) == len(actual), "Replay event counts differ")
    maximum = 0.0
    for left, right in zip(expected, actual):
        for key in ("event_id", "pred_label", "is_alert"):
            require(left[key] == right[key], f"Replay differs at event {left['event_id']}: {key}")
        for key in NUMERIC_FIELDS:
            a, b = float(left[key]), float(right[key])
            require(math.isclose(a, b, rel_tol=1e-6, abs_tol=1e-6),
                    f"Replay differs at event {left['event_id']}: {key}")
            maximum = max(maximum, abs(a-b))
    return maximum


class Lab:
    def __init__(self, client, report):
        self.client, self.report = client, report

    def call(self, path, body=None, token=None, expected=200, label=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        content = None if body is None else encoded(body)
        started = time.perf_counter()
        response = self.client.request("GET" if body is None else "POST", path,
                                       content=content, headers=headers)
        elapsed = (time.perf_counter()-started)*1000
        measurement = {"operation": label or path, "status": response.status_code,
                       "http_version": response.http_version, "client_ms": round(elapsed, 3),
                       "request_body_bytes": len(content or b""),
                       "response_body_bytes": len(response.content)}
        self.report["requests"].append(measurement)
        # Do not echo response bodies, URLs with session IDs, or credentials on failure.
        require(response.status_code == expected,
                f"{label or 'request'} expected HTTP {expected}, received {response.status_code}")
        payload = response.json()
        return payload, measurement

    def session(self):
        session, _ = self.call("/api/sessions", {"policy": "top_2pct"},
                               expected=201, label="create_session")
        return "/api/sessions/"+session["session_id"], session["token"]

    def state(self, route, token):
        state, _ = self.call(route, token=token, label="read_session")
        require(state["model_id"] == self.report["model_id"], "Session model identity changed")
        return state

    def check(self, name, observation):
        self.report["checks"].append({"name": name, "passed": True, "observation": observation})
        print(f"PASS {name}", flush=True)

    def delivery_checks(self, events, route, token, reference):
        # The first successful ingest was committed, but its acknowledgement is
        # deliberately ignored by this recovery procedure. This is an application
        # fault simulation; we do not claim to drop TCP packets or close a socket.
        duplicate, _ = self.call(route+"/events", {"events": events}, token, label="retry_after_ignored_ack")
        require((duplicate["accepted"], duplicate["duplicates"]) == (0, len(events)), "Retry duplicated events")
        require(self.state(route, token)["events"] == reference, "Retry changed stored outputs")
        self.check("acknowledgement_ignored_then_retried", f"0 inserts, {len(events)} duplicates; stored outputs unchanged")

        conflict = dict(events[0], bytes_out=events[0]["bytes_out"]+1)
        self.call(route+"/events", {"events": [conflict]}, token, expected=409, label="conflicting_event_id")
        self.check("conflicting_event_id", "HTTP 409")
        late = dict(events[0], event_id=10000)
        self.call(route+"/events", {"events": [late]}, token, expected=409, label="late_event")
        self.check("late_event", "HTTP 409; a new ID does not bypass chronological ordering")

        future = datetime.fromisoformat(events[-1]["timestamp"].replace("Z", "+00:00"))+timedelta(minutes=1)
        first = dict(events[-1], event_id=10001, timestamp=future.isoformat())
        second = dict(first, event_id=10002, timestamp=(future+timedelta(seconds=1)).isoformat())
        self.call(route+"/events", {"events": [second, first]}, token, expected=422, label="reversed_batch")
        self.check("reversed_batch", "HTTP 422")
        self.call(route+"/events", {"events": [first, dict(second, geo_lat=200)]}, token,
                  expected=422, label="mixed_valid_invalid_batch")
        require(self.state(route, token)["events"] == reference, "Rejected requests changed committed events")
        self.check("rejections_are_atomic", "All committed outputs unchanged after conflict, late, reversed and invalid requests")

        self.call(route, expected=401, label="missing_token")
        self.check("missing_token", "HTTP 401")
        other_route, other_token = self.session()
        self.call(route, token=other_token, expected=401, label="another_session_token")
        require(self.state(other_route, other_token)["events"] == [], "Fresh session contains another visitor's events")
        self.check("session_isolation", "Other session token receives HTTP 401; its own session is empty")

        review = {"request_id": "network-lab-review-1", "event_id": events[-1]["event_id"],
                  "disposition": "needs_investigation", "note": "Synthetic networking experiment"}
        self.call(route+"/feedback", review, token, label="save_review")
        retry, _ = self.call(route+"/feedback", review, token, label="retry_review")
        require(retry["duplicate"] and not retry["saved"], "Review retry was not deduplicated")
        self.check("review_retry", "Duplicate acknowledged without another audit row")
        self.call(route+"/feedback", dict(review, note="Conflicting content"), token,
                  expected=409, label="conflicting_review_key")
        self.check("conflicting_review_key", "HTTP 409")
        self.call(route+"/feedback", dict(review, request_id="network-lab-review-2",
                  disposition="confirmed_attack"), token, label="review_revision")
        state = self.state(route, token)
        require([r["disposition"] for r in state["feedback"]] == ["needs_investigation", "confirmed_attack"],
                "Audit revision history differs")
        self.check("audit_readback", "Exactly two revisions retained after duplicate and conflicting requests")


def summarize(report):
    summaries = []
    for size in report["batch_sizes"]:
        runs = [row for row in report["trials"] if row["batch_size"] == size]
        if not runs:
            continue
        row = {"batch_size": size, "repetitions": len(runs), "requests_per_trial": runs[0]["ingest_requests"]}
        for key in ("client_ingest_ms", "server_work_ms", "request_body_bytes", "response_body_bytes"):
            values = [run[key] for run in runs]
            row[key] = {"median": round(statistics.median(values), 3),
                        "min": round(min(values), 3), "max": round(max(values), 3)}
        summaries.append(row)
    report["summary"] = summaries


def write_report(report, target):
    summarize(report)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    lines = ["# HTTP networking experiment", "", f"Status: **{report['status']}**. Target: {report['url']}",
             "", f"Recorded: {report['started_at_utc']}. Model/source identity: `{report.get('model_id', 'unavailable')}`.",
             "", "| Batch size | Repetitions | POSTs / trial | Client total ms, median (min–max) | Server work ms, median | Request body bytes, median |",
             "|---:|---:|---:|---:|---:|---:|"]
    for row in report["summary"]:
        client = row["client_ingest_ms"]
        lines.append(f"| {row['batch_size']} | {row['repetitions']} | {row['requests_per_trial']} | "
                     f"{client['median']:.1f} ({client['min']:.1f}–{client['max']:.1f}) | "
                     f"{row['server_work_ms']['median']:.1f} | {row['request_body_bytes']['median']:.0f} |")
    lines += ["", "All trials replay the same synthetic events into fresh sessions, using sequential requests and one reusable HTTP/1.1 client.",
              "Client time includes HTTP and service work. Server work is the API's scoring_ms timer (inference plus inserts, excluding transaction commit).",
              "Body bytes exclude headers, TLS and TCP/IP framing. The difference between timers is not pure network RTT.",
              "Warm-up is recorded separately; these small samples do not estimate service capacity or tail latency.", "", "## Correctness observations", ""]
    lines += [f"- {item['name']}: {item['observation']}." for item in report["checks"]]
    lines += ["", f"Full measurements and methodology: [{target.name}]({target.name}).", ""]
    target.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="output/network-lab.json")
    parser.add_argument("--repetitions", type=int, choices=range(1, 4), default=3)
    parser.add_argument("--batch-sizes", type=int, nargs="+", default=[42, 84, 168])
    args = parser.parse_args()
    parts = urlsplit(args.url)
    require(parts.scheme in ("http", "https") and parts.hostname and not parts.username
            and not parts.password and not parts.query and not parts.fragment and parts.path in ("", "/"),
            "Use an HTTP(S) origin without credentials, path, query or fragment")
    require(parts.scheme == "https" or parts.hostname in ("localhost", "127.0.0.1", "::1"),
            "Use HTTPS for a public service; plain HTTP is supported only on loopback")
    sizes = sorted(set(args.batch_sizes))
    require(sizes and all(42 <= size <= 168 for size in sizes) and len(sizes) <= 3,
            "Use at most three batch sizes between 42 and 168 to bound demo load")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    report = {"schema_version": 1, "status": "running", "url": args.url.rstrip("/"),
              "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "client_python": platform.python_version(), "client_os": platform.system(), "httpx": httpx.__version__,
              "checkout_revision": revision.stdout.strip() if revision.returncode == 0 else "unavailable",
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "batch_sizes": sizes, "repetitions": args.repetitions,
              "method": {"data": "synthetic /api/scenarios baseline followed by attack", "policy": "top_2pct",
                         "concurrency": 1, "http2": False, "tls_verification": True, "automatic_retries": False,
                         "warmup": "health plus one unmeasured full replay before timed trials",
                         "order": "batch sizes rotate by one position per repetition",
                         "numeric_comparison": {"fields": NUMERIC_FIELDS, "absolute_tolerance": 1e-6, "relative_tolerance": 1e-6},
                         "ignored_ack": "Application discards successful acknowledgement, then resends; no packet loss injected"},
              "requests": [], "trials": [], "checks": []}
    target = Path(args.output)
    try:
        with httpx.Client(base_url=report["url"], timeout=120, http2=False,
                          headers={"Accept-Encoding": "identity"}) as client:
            lab = Lab(client, report)
            health, _ = lab.call("/api/health", label="initial_health")
            require(health["status"] == "ok", "Service health is not ok")
            report["model_id"] = health["model_id"]
            examples, _ = lab.call("/api/scenarios", label="get_synthetic_inputs")
            events = examples["baseline"]["events"]+examples["attack"]["events"]
            require(len(events) == 168, "Experiment expects the documented 168-event fixture")
            report["input_sha256"] = hashlib.sha256(encoded(events)).hexdigest()
            report["events_per_trial"] = len(events)
            route, token = lab.session()
            lab.call(route+"/events", {"events": events}, token, label="warmup_full_replay")
            reference = lab.state(route, token)["events"]
            report["demo_outcomes"] = {"baseline_alerts": sum(e["is_alert"] for e in reference[:120]),
                                       "campaign_alerts": sum(e["is_alert"] for e in reference[120:])}
            for repetition in range(args.repetitions):
                order = sizes[repetition % len(sizes):]+sizes[:repetition % len(sizes)]
                for size in order:
                    trial_route, trial_token = lab.session()
                    measures, server_times = [], []
                    for start in range(0, len(events), size):
                        chunk = events[start:start+size]
                        response, measurement = lab.call(trial_route+"/events", {"events": chunk}, trial_token, label="timed_ingest")
                        require(response["accepted"] == len(chunk) and response["duplicates"] == 0
                                and response["total_events"] == start+len(chunk), "Unexpected ingestion counts")
                        measures.append(measurement)
                        server_times.append(response["scoring_ms"])
                    state = lab.state(trial_route, trial_token)
                    difference = equivalent(reference, state["events"])
                    trial = {"repetition": repetition+1, "batch_size": size, "ingest_requests": len(measures),
                             "client_ingest_ms": round(sum(m["client_ms"] for m in measures), 3),
                             "server_work_ms": round(sum(server_times), 3), "max_numeric_difference": difference,
                             "request_body_bytes": sum(m["request_body_bytes"] for m in measures),
                             "response_body_bytes": sum(m["response_body_bytes"] for m in measures)}
                    report["trials"].append(trial)
                    write_report(report, target)
                    print(f"Trial {repetition+1}, batch {size}: {trial['client_ingest_ms']:.0f} ms; outputs agree", flush=True)
            lab.check("batch_equivalence", f"All {len(report['trials'])} trials agree with full replay on IDs, labels, flags and seven numeric channels")
            lab.delivery_checks(events, route, token, reference)
            end_health, _ = lab.call("/api/health", label="final_health")
            require(end_health["model_id"] == report["model_id"], "Model identity changed during experiment")
            report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        # Generic transport errors may include credential-bearing URLs in other
        # clients. Ours only records the exception type; CLI status remains nonzero.
        report["failure_type"] = type(error).__name__
        raise
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_report(report, target)
    print(f"Saved {target}: {len(report['checks'])} correctness checks passed", flush=True)


if __name__ == "__main__":
    main()
