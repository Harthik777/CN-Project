"""Offline verification of the public data, using dpkt as an independent decoder."""
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import unittest

import dpkt

from backend.flow_model import FlowScorer
from backend.packets import _decode
from scripts.prepare_real_captures import redact
from scripts.train_flow_model import frame

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "artifacts" / "real_captures"


class RealCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((DATA / "manifest.json").read_text())
        cls.scorer = FlowScorer()

    def test_provenance_selection_and_packaged_integrity(self):
        sources = {source["id"]: source for source in self.manifest["sources"]}
        self.assertEqual(len(sources), 2)
        self.assertEqual(len(self.manifest["captures"]), 6)
        observed = {key: set() for key in sources}
        for capture in self.manifest["captures"]:
            data = (DATA / capture["file"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), capture["sha256"])
            self.assertEqual(len(data), capture["summary"]["file_bytes"])
            self.assertLessEqual(len(data), 512 * 1024)
            numbers = capture["source_packet_numbers"]
            self.assertEqual(len(numbers), 200)
            self.assertEqual(numbers, sorted(set(numbers)))
            self.assertFalse(observed[capture["source_id"]].intersection(numbers))
            observed[capture["source_id"]].update(numbers)
            self.assertEqual(len(sources[capture["source_id"]]["sha256"]), 64)
            self.assertNotEqual(capture["sha256"], capture["original_excerpt_sha256"])

    def test_independent_packet_counts_headers_and_zeroed_payloads(self):
        for capture in self.manifest["captures"]:
            counts, ip_bytes, payload_bytes, timestamps = Counter(), 0, 0, []
            for timestamp, raw in dpkt.pcap.Reader(io.BytesIO((DATA / capture["file"]).read_bytes())):
                ip = dpkt.ethernet.Ethernet(raw).data
                self.assertIsInstance(ip, dpkt.ip.IP)
                tcp_udp = ip.data
                self.assertIsInstance(tcp_udp, (dpkt.tcp.TCP, dpkt.udp.UDP))
                self.assertEqual(bytes(tcp_udp.data), bytes(len(tcp_udp.data)))
                transport = raw[14 + ip.hl * 4:14 + ip.len]
                size = tcp_udp.ulen if isinstance(tcp_udp, dpkt.udp.UDP) else len(transport)
                pseudo = ip.src + ip.dst + struct.pack("!BBH", 0, ip.p, size)
                self.assertEqual(dpkt.in_cksum(pseudo + transport[:size]), 0)
                counts["TCP" if ip.p == 6 else "UDP"] += 1
                ip_bytes += ip.len
                payload_bytes += len(tcp_udp.data)
                timestamps.append(timestamp)
            expected = capture["summary"]
            self.assertEqual(sum(counts.values()), expected["parsed_packets"])
            self.assertEqual(dict(counts), expected["protocols"])
            self.assertEqual(ip_bytes, expected["total_ip_bytes"])
            result = self.scorer((DATA / capture["file"]).read_bytes())
            self.assertEqual(payload_bytes, sum(flow["payload_bytes"] for flow in result["flows"]))
            self.assertAlmostEqual((max(timestamps)-min(timestamps))*1000, expected["duration_ms"], places=5)

    def test_frozen_model_reproduces_transfer_check(self):
        self.assertEqual(self.scorer.model_id, self.manifest["model_id"])
        totals = Counter()
        for capture in self.manifest["captures"]:
            result = self.scorer((DATA / capture["file"]).read_bytes())
            for name in ("flows", "parsed_packets", "flagged_flows", "completed_handshakes"):
                self.assertEqual(result["summary"][name], capture["summary"][name])
                totals[name] += result["summary"][name]
        self.assertEqual(totals["parsed_packets"], 1200)
        self.assertEqual(totals["flows"], 194)
        self.assertEqual(totals["flagged_flows"], 185)
        # Dataset contexts must not silently become per-flow attack ground truth.
        self.assertIn("No per-flow attack ground truth", self.manifest["label_scope"])

    def test_redaction_preserves_headers_lengths_and_recalculates_checksums(self):
        for protocol in ("TCP", "UDP"):
            original = frame("192.0.2.1", "198.51.100.2", 1000, 443, protocol=protocol, payload=29)
            output = redact(original)
            self.assertEqual(len(output), len(original))
            self.assertEqual(_decode(original, 1), _decode(output, 1))
            ip = dpkt.ethernet.Ethernet(output).data
            self.assertEqual(bytes(ip.data.data), bytes(29))
            transport = output[14+ip.hl*4:14+ip.len]
            pseudo = socket.inet_aton("192.0.2.1")+socket.inet_aton("198.51.100.2")+struct.pack("!BBH",0,ip.p,len(transport))
            self.assertEqual(dpkt.in_cksum(pseudo+transport),0)


if __name__ == "__main__":
    unittest.main()
