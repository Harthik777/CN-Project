"""Reproduce the separate packet-flow model and capture-disjoint synthetic evaluation.

All PCAP frames are constructed in memory using documentation-only addresses.
This script never opens a network socket or sends a packet.
"""
import argparse
import hashlib
import json
import random
import socket
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.packets import FEATURE_NAMES, extract_flows, flow_features


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!" + "H" * (len(data)//2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(src, dst, sport, dport, protocol="TCP", flags=16, seq=1, ack=1, payload=0, ipv6=False):
    source = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, src)
    destination = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, dst)
    number = 6 if protocol == "TCP" else 17
    body = bytes(payload)
    transport = (struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) if number == 6
                 else struct.pack("!HHHH", sport, dport, 8 + payload, 0)) + body
    pseudo = source + destination + (struct.pack("!I3xB", len(transport), number) if ipv6 else struct.pack("!BBH", 0, number, len(transport)))
    value = checksum(pseudo + transport) or 65535
    position = 16 if number == 6 else 6
    transport = transport[:position] + struct.pack("!H", value) + transport[position+2:]
    if ipv6:
        ip = struct.pack("!IHBB", 6 << 28, len(transport), number, 64) + source + destination
    else:
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20+len(transport), 0, 0x4000, 64, number, 0) + source + destination
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", 0x86dd if ipv6 else 0x0800) + ip + transport


def pcap(records, endian="<", nano=False, link=1):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    result = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, link))
    resolution = 10**9 if nano else 10**6
    for timestamp, packet in records:
        seconds = int(timestamp)
        fraction = min(resolution-1, int(round((timestamp-seconds)*resolution)))
        result.extend(struct.pack(endian + "IIII", seconds, fraction, len(packet), len(packet)))
        result.extend(packet)
    return bytes(result)


def make_capture(seed, unusual=False):
    rng = random.Random(seed)
    records, labels = [], {}
    base = 1788861600 + seed * 90
    for i in range(24 + (8 if unusual else 0)):
        ipv6 = i % 6 == 0
        src = f"2001:db8:1::{i+1:x}" if ipv6 else f"192.0.2.{i+1}"
        dst = "2001:db8:2::10" if ipv6 else "198.51.100.10"
        sport, dport = rng.randint(10000, 60000), (443 if i % 4 else 53)
        protocol = "TCP" if i % 4 else "UDP"
        t = base + i * 1.8 + rng.uniform(0, .2)
        q, r = rng.randint(100, 100000), rng.randint(100, 100000)
        scenario = "normal" if i < 24 else ("syn_probe", "udp_burst", "bulk_transfer", "repeated_sequence")[i % 4]
        labels[(src, sport)] = scenario
        def add(offset, reverse=False, **kwargs):
            records.append((t+offset, frame(dst if reverse else src, src if reverse else dst,
                                           dport if reverse else sport, sport if reverse else dport,
                                           protocol, ipv6=ipv6, **kwargs)))
        if scenario == "syn_probe":
            protocol = "TCP"
            for step in range(3):
                add(step * .3, flags=2, seq=q, ack=0)
        elif scenario == "udp_burst":
            protocol = "UDP"
            for step in range(60):
                add(step * .0001, payload=rng.randint(80, 200))
        else:
            if protocol == "TCP":
                latency = rng.uniform(.004, .045)
                add(0, flags=2, seq=q, ack=0)
                add(latency, True, flags=18, seq=r, ack=q+1)
                add(latency*1.5, flags=16, seq=q+1, ack=r+1)
                t0 = latency*2
                amount = rng.randint(40, 650)
                if scenario == "bulk_transfer":
                    for step in range(36):
                        add(t0+step*.004, flags=24, seq=q+1+step*1200, ack=r+1, payload=1200)
                elif scenario == "repeated_sequence":
                    for step in range(24):
                        add(t0+step*.015, flags=24, seq=q+1, ack=r+1, payload=400)
                else:
                    add(t0, flags=24, seq=q+1, ack=r+1, payload=amount)
                    response_bytes = rng.randint(80, 1100)
                    add(t0+latency, True, flags=24, seq=r+1, ack=q+1+amount, payload=response_bytes)
                    add(t0+latency*2, flags=17, seq=q+1+amount, ack=r+1+response_bytes)
            else:
                add(0, payload=rng.randint(30, 90))
                add(rng.uniform(.003, .06), True, payload=rng.randint(70, 220))
    records.sort(key=lambda row: row[0])
    data = pcap(records)
    return data, labels


def run(output):
    import joblib
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support
    output.mkdir(parents=True, exist_ok=True)
    splits, manifest = {}, {}
    for name, seeds in (("train", range(1000, 1020)), ("validation", range(2000, 2008)), ("test", range(3000, 3008))):
        rows, targets, captures = [], [], []
        for seed in seeds:
            data, labels = make_capture(seed, name == "test")
            flows = extract_flows(data)["flows"]
            rows.extend(flow_features(flow) for flow in flows)
            targets.extend(labels[(f["source_ip"], f["source_port"])] != "normal" for f in flows)
            captures.append(dict(seed=seed, sha256=hashlib.sha256(data).hexdigest(), flows=len(flows)))
        splits[name] = np.asarray(rows), np.asarray(targets)
        manifest[name] = captures
    model = IsolationForest(n_estimators=100, max_samples=256, random_state=77, n_jobs=1).fit(splits["train"][0])
    validation_scores = -model.score_samples(splits["validation"][0])
    threshold = float(np.quantile(validation_scores, .95))
    scores = -model.score_samples(splits["test"][0])
    predictions, target = scores > threshold, splits["test"][1]
    precision, recall, f1, _ = precision_recall_fscore_support(target, predictions, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(target, predictions, labels=[False, True]).ravel()
    metadata = dict(version="packet-flow-v1", model="Isolation Forest", training_scope="synthetic packet captures; not validated on operational traffic",
                    features=FEATURE_NAMES, feature_count=len(FEATURE_NAMES), train_flows=len(splits["train"][0]),
                    validation_flows=len(splits["validation"][0]), test_flows=len(target),
                    train_captures=20, validation_captures=8, test_captures=8,
                    threshold=threshold, threshold_selection="95th percentile of scores on benign validation captures",
                    sklearn_version=sklearn.__version__, random_state=77,
                    test_metrics=dict(true_positive=int(tp), false_positive=int(fp), false_negative=int(fn), true_negative=int(tn),
                                      precision=float(precision), recall=float(recall), f1=float(f1),
                                      average_precision=float(average_precision_score(target, scores)),
                                      false_positive_rate=float(fp/(fp+tn))),
                    captures=manifest)
    model_path = output / "flow_model.joblib"
    joblib.dump(model, model_path, compress=3)
    metadata["artifact_sha256"] = hashlib.sha256(model_path.read_bytes()).hexdigest()
    metadata["training_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    metadata["extractor_sha256"] = hashlib.sha256((ROOT / "backend" / "packets.py").read_bytes()).hexdigest()
    sample, _ = make_capture(4000, True)
    (output / "sample_capture.pcap").write_bytes(sample)
    metadata["sample_sha256"] = hashlib.sha256(sample).hexdigest()
    (output / "flow_model.json").write_text(json.dumps(metadata, indent=2)+"\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in metadata.items() if k != "captures"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "packet_flow")
    run(parser.parse_args().output)
