"""Public/local HTTP verification with independent dpkt header decoding.

Install verification-only dependency: python -m pip install dpkt==1.9.8
Does not log session credentials or upload arbitrary network traffic.
"""
import argparse
import hashlib
import io
import json
import socket
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import dpkt
import httpx


def verify(url, output):
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("Use a service origin without credentials, query, fragment or path")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")):
        raise ValueError("Use HTTPS, or plain HTTP on loopback")
    report = {"origin": url.rstrip("/"), "verified_at": datetime.now(timezone.utc).isoformat(), "checks": []}
    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)
    with httpx.Client(base_url=url.rstrip("/"), timeout=120, follow_redirects=False) as client:
        health = client.get("/api/health"); health.raise_for_status()
        manifest = client.get("/api/packets/model"); manifest.raise_for_status()
        sample = client.get("/api/packets/sample"); sample.raise_for_status()
        data, metadata = sample.content, manifest.json()
        check("sample_sha256", hashlib.sha256(data).hexdigest() == metadata["sample_sha256"])
        check("model_identity", health.json()["flow_model_id"] == metadata["model_id"])
        decoded, grouped, protocols, payloads = {}, Counter(), Counter(), Counter()
        for number, (_, raw) in enumerate(dpkt.pcap.Reader(io.BytesIO(data)), 1):
            ip = dpkt.ethernet.Ethernet(raw).data
            transport = ip.data
            version = socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6
            src, dst = socket.inet_ntop(version, ip.src), socket.inet_ntop(version, ip.dst)
            protocol = "TCP" if isinstance(transport, dpkt.tcp.TCP) else "UDP"
            key = (protocol, tuple(sorted(((src, transport.sport), (dst, transport.dport)))))
            grouped[key] += 1
            protocols[protocol] += 1
            payloads[key] += len(transport.data)
            decoded[number] = dict(ip_bytes=len(ip), payload_bytes=len(transport.data),
                                   seq=transport.seq if protocol == "TCP" else None,
                                   ack=transport.ack if protocol == "TCP" else None,
                                   ttl=ip.ttl if version == socket.AF_INET else ip.hlim)
        auth = client.post("/api/sessions", json={}); auth.raise_for_status()
        credential = auth.json()
        route = f"/api/sessions/{credential['session_id']}/capture"
        headers = {"Authorization": "Bearer " + credential["token"], "Content-Type": "application/vnd.tcpdump.pcap"}
        started = time.perf_counter()
        uploaded = client.post(route, headers=headers, content=data); uploaded.raise_for_status()
        report["upload_http_ms"] = round((time.perf_counter()-started)*1000, 3)
        check("capture_saved", uploaded.json()["saved"])
        readback = client.get(route, headers=headers); readback.raise_for_status()
        saved = readback.json()
        summary = saved["summary"]
        def flow_key(flow):
            return (flow["protocol"], tuple(sorted(((flow["source_ip"], flow["source_port"]),
                                                   (flow["destination_ip"], flow["destination_port"])))))
        check("independent_packet_counts", summary["parsed_packets"] == len(decoded) and summary["protocols"] == dict(protocols))
        check("independent_ip_byte_total", summary["total_ip_bytes"] == sum(p["ip_bytes"] for p in decoded.values()))
        check("independent_bidirectional_flow_counts", len(saved["flows"]) == len(grouped) and all(
            grouped[flow_key(f)] == f["packets"] for f in saved["flows"]))
        check("independent_packet_header_preview", all(all(packet[key] == decoded[packet["packet_number"]][key]
            for key in ("ip_bytes", "payload_bytes", "seq", "ack", "ttl")) for f in saved["flows"] for packet in f["packet_preview"]))
        check("independent_flow_payload_totals", all(payloads[flow_key(f)] == f["payload_bytes"] for f in saved["flows"]))
        retry = client.post(route, headers=headers, content=data); retry.raise_for_status()
        check("idempotent_capture_retry", retry.json()["duplicate"] and not retry.json()["saved"])
        check("missing_token_rejected", client.get(route).status_code == 401)
        another = client.post("/api/sessions", json={}); another.raise_for_status()
        other_headers = {"Authorization": "Bearer " + another.json()["token"]}
        check("cross_session_token_rejected", client.get(route, headers=other_headers).status_code == 401)
        other_route = f"/api/sessions/{another.json()['session_id']}/capture"
        check("malformed_capture_rejected", client.post(other_route, headers=other_headers, content=b"invalid pcap").status_code == 422)
        check("invalid_capture_no_commit", client.get(other_route, headers=other_headers).status_code == 404)
        changed = bytearray(data); changed[-1] ^= 1
        check("conflicting_capture_rejected", client.post(route, headers=headers, content=bytes(changed)).status_code == 409)
        check("saved_report_unchanged", client.get(route, headers=headers).json() == saved)
        report.update(capture_sha256=summary["capture_sha256"], model_id=saved["model"]["model_id"], summary=summary,
                      independent_decoder=f"dpkt {dpkt.__version__}", synthetic_test_metrics=metadata["test_metrics"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, default=Path("output/packet-lab.json"))
    args = parser.parse_args()
    verify(args.url, args.output)
