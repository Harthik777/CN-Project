import hashlib
import json
import math
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.flow_model import ARTIFACTS, FlowScorer
from backend.packets import CaptureError, decode_capture, extract_flows, flow_features
from backend.store import Store
from scripts.train_flow_model import frame, make_capture, pcap


class PacketParsingTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = "192.0.2.1", "198.51.100.2"
        self.syn = frame(self.a, self.b, 1234, 443, flags=2, seq=100, ack=0)
        self.synack = frame(self.b, self.a, 443, 1234, flags=18, seq=200, ack=101)
        self.ack = frame(self.a, self.b, 1234, 443, flags=16, seq=101, ack=201)
        self.records = [(1000.0, self.syn), (1000.02, self.synack), (1000.03, self.ack)]

    def test_matching_handshake_and_byte_accounting(self):
        result = extract_flows(pcap(self.records))
        self.assertEqual(result["summary"]["completed_handshakes"], 1)
        flow = result["flows"][0]
        self.assertEqual((flow["packets"], flow["ip_bytes"], flow["payload_bytes"]), (3, 120, 0))
        self.assertEqual((flow["forward_packets"], flow["reverse_packets"]), (2, 1))
        self.assertAlmostEqual(flow["handshake"]["syn_to_syn_ack_ms"], 20, places=3)
        self.assertAlmostEqual(flow["handshake"]["completion_ms"], 30, places=3)
        self.assertAlmostEqual(flow["iat_mean_ms"], 15, places=3)

    def test_bad_ack_does_not_claim_a_handshake(self):
        wrong = frame(self.a, self.b, 1234, 443, flags=16, seq=101, ack=999)
        result = extract_flows(pcap(self.records[:2] + [(1000.03, wrong)]))
        self.assertIsNone(result["flows"][0]["handshake"])

    def test_bad_syn_ack_does_not_claim_a_handshake(self):
        wrong = frame(self.b, self.a, 443, 1234, flags=18, seq=200, ack=999)
        result = extract_flows(pcap([self.records[0], (1000.02, wrong), self.records[2]]))
        self.assertIsNone(result["flows"][0]["handshake"])

    def test_sequence_wraparound(self):
        frames = [(1, frame(self.a, self.b, 1, 2, flags=2, seq=2**32-1, ack=0)),
                  (2, frame(self.b, self.a, 2, 1, flags=18, seq=2**32-1, ack=0)),
                  (3, frame(self.a, self.b, 1, 2, flags=16, seq=0, ack=0))]
        self.assertEqual(extract_flows(pcap(frames))["summary"]["completed_handshakes"], 1)

    def test_endianness_and_timestamp_resolution(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                result = extract_flows(pcap(self.records, endian=endian, nano=nano))
                self.assertEqual(result["summary"]["parsed_packets"], 3)
                self.assertAlmostEqual(result["flows"][0]["duration_ms"], 30, places=3)

    def test_unsorted_records_sorted_with_original_packet_numbers(self):
        result = extract_flows(pcap(self.records[::-1]))
        self.assertEqual(result["summary"]["out_of_order_records"], 2)
        self.assertEqual(result["flows"][0]["handshake"]["syn_packet"], 3)

    def test_ipv6_udp_and_port_direction(self):
        packet = frame("2001:db8::1", "2001:db8::2", 1000, 53, protocol="UDP", payload=12, ipv6=True)
        flow = extract_flows(pcap([(1, packet)]))["flows"][0]
        self.assertEqual((flow["ip_version"], flow["protocol"], flow["ip_bytes"], flow["payload_bytes"]), (6, "UDP", 60, 12))
        self.assertIsNone(flow["handshake"])
        self.assertTrue(all(math.isfinite(x) for x in flow_features(flow)))

    def test_vlan_and_raw_and_cooked_link_headers(self):
        vlan = self.syn[:12] + bytes.fromhex("810000010800") + self.syn[14:]
        cooked = bytes(14) + bytes.fromhex("0800") + self.syn[14:]
        for link, packet in ((1, vlan), (101, self.syn[14:]), (228, self.syn[14:]), (113, cooked)):
            self.assertEqual(extract_flows(pcap([(1, packet)], link=link))["flows"][0]["source_ip"], self.a)

    def test_ipv6_hop_by_hop_extension(self):
        packet = bytearray(frame("2001:db8::1", "2001:db8::2", 1, 2, protocol="UDP", payload=1, ipv6=True))
        packet[20] = 0
        packet[18:20] = struct.pack("!H", 17)
        packet = packet[:54] + bytes([17, 0]) + bytes(6) + packet[54:]
        self.assertEqual(extract_flows(pcap([(1, packet)]))["flows"][0]["payload_bytes"], 1)

    def test_fragments_and_unsupported_protocols_are_accounted_for(self):
        fragment = bytearray(self.syn); fragment[20:22] = struct.pack("!H", 0x2000)
        icmp = bytearray(self.syn); icmp[23] = 1
        result = extract_flows(pcap(self.records + [(1001, fragment), (1002, icmp), (1003, self.syn[:20])]))
        self.assertEqual(result["summary"]["skipped_by_reason"], {"fragmented_ip": 1, "other_ip_protocol": 1, "truncated_header": 1})
        self.assertEqual(result["summary"]["packet_records"], 6)

    def test_truncated_payload_cannot_be_counted_as_full_packet(self):
        packet = frame(self.a, self.b, 1, 2, payload=50)
        result = extract_flows(pcap(self.records + [(1001, packet[:-5])]))
        self.assertEqual(result["summary"]["skipped_by_reason"], {"truncated_ip": 1})

    def test_malformed_tcp_and_udp_lengths_are_skipped(self):
        tcp = bytearray(self.syn); tcp[46] = 0x10
        udp = bytearray(frame(self.a, self.b, 1, 2, protocol="UDP")); udp[38:40] = bytes.fromhex("ffff")
        result = extract_flows(pcap(self.records + [(1001, tcp), (1002, udp)]))
        self.assertEqual(result["summary"]["skipped_by_reason"], {"malformed_tcp": 1, "malformed_udp": 1})

    def test_repeated_payload_ranges_and_preview_bound(self):
        packet = frame(self.a, self.b, 1234, 443, seq=101, ack=201, payload=10)
        result = extract_flows(pcap(self.records + [(1000.04+i*.01, packet) for i in range(20)]))
        flow = result["flows"][0]
        self.assertEqual(flow["repeated_payload_ranges"], 19)
        self.assertEqual(flow["payload_bytes"], 200)
        self.assertEqual(len(flow["packet_preview"]), 12)
        self.assertEqual(flow["packets"], 23)

    def test_flow_idle_timeout_and_new_syn_sequence(self):
        fresh = frame(self.a, self.b, 1234, 443, flags=2, seq=999, ack=0)
        result = extract_flows(pcap(self.records + [(1001, fresh), (1070, fresh)]))
        self.assertEqual(result["summary"]["flows"], 3)

    def test_invalid_file_headers_and_record_lengths_rejected(self):
        good = pcap(self.records)
        bad_length = bytearray(good); struct.pack_into("<I", bad_length, 32, 2**32-1)
        for data in (b"", b"\x0a\x0d\x0d\x0a"+bytes(24), good[:23], good[:-1], bytes(bad_length), good+bytes(3), bytes(512*1024+1)):
            with self.assertRaises(CaptureError):
                extract_flows(data)

    def test_packet_and_flow_limits_reject_whole_capture(self):
        with patch("backend.packets.MAX_PACKETS", 2), self.assertRaises(CaptureError):
            extract_flows(pcap(self.records))
        with patch("backend.packets.MAX_FLOWS", 1), self.assertRaises(CaptureError):
            extract_flows(pcap(self.records + [(2000, self.syn)]))

    def test_headers_never_export_payload_bytes(self):
        secret = b"test-secret-payload"
        packet = frame(self.a, self.b, 1, 2, payload=len(secret))[:-len(secret)] + secret
        result = extract_flows(pcap([(1, packet)]))
        self.assertNotIn(secret.decode(), json.dumps(result))
        self.assertEqual(result["flows"][0]["payload_bytes"], len(secret))


class PacketModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scorer = FlowScorer()

    def test_sample_and_model_identities(self):
        data = (ARTIFACTS / "sample_capture.pcap").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.scorer.metadata["sample_sha256"])
        result = self.scorer(data)
        self.assertEqual((result["summary"]["parsed_packets"], len(result["flows"])), (378, 32))
        self.assertEqual(result["summary"]["completed_handshakes"], 22)
        self.assertTrue(all(len(row["features"]) == 13 for row in result["flows"]))
        self.assertEqual(result, self.scorer(data))

    def test_test_capture_metrics_reproduce_without_fitting(self):
        from sklearn.metrics import confusion_matrix
        y, predictions = [], []
        split_hashes = []
        for entries in self.scorer.metadata["captures"].values():
            split_hashes.extend(c["sha256"] for c in entries)
        self.assertEqual(len(split_hashes), len(set(split_hashes)))
        for capture in self.scorer.metadata["captures"]["test"]:
            data, labels = make_capture(capture["seed"], True)
            self.assertEqual(hashlib.sha256(data).hexdigest(), capture["sha256"])
            result = self.scorer(data)
            y.extend(labels[(row["source_ip"], row["source_port"])] != "normal" for row in result["flows"])
            predictions.extend(row["is_alert"] for row in result["flows"])
        tn, fp, fn, tp = confusion_matrix(y, predictions, labels=[False, True]).ravel()
        m = self.scorer.metadata["test_metrics"]
        np.testing.assert_equal([tn, fp, fn, tp], [m["true_negative"], m["false_positive"], m["false_negative"], m["true_positive"]])


class PacketApiTests(unittest.TestCase):
    def setUp(self):
        class FakeScorer:
            model_id = "test"
            thresholds = {}
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "db.sqlite3"
        self.app = create_app(self.path, FakeScorer())
        self.client = TestClient(self.app).__enter__()
        self.auth = self.client.post("/api/sessions", json={}).json()
        self.route = f"/api/sessions/{self.auth['session_id']}/capture"
        self.headers = {"Authorization": "Bearer " + self.auth["token"], "Content-Type": "application/vnd.tcpdump.pcap"}
        self.sample = (ARTIFACTS / "sample_capture.pcap").read_bytes()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def post(self, data=None, headers=None):
        return self.client.post(self.route, headers=headers or self.headers, content=self.sample if data is None else data)

    def test_upload_readback_retry_and_restart(self):
        first = self.post()
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(first.json()["saved"])
        self.assertTrue(self.post().json()["duplicate"])
        report = self.client.get(self.route, headers=self.headers).json()
        self.assertEqual(len(report["flows"]), 32)
        reopened = Store(self.path).capture_snapshot(self.auth["session_id"], self.auth["token"])
        self.assertEqual(report, reopened)
        with self.app.state.store.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*),SUM(packets),SUM(ip_bytes) FROM capture_flows").fetchone()[:], (32, 378, 157599))

    def test_runtime_health_and_compressed_offline_shell(self):
        health = self.client.get("/api/health").json()
        self.assertGreaterEqual(health["uptime_seconds"], 0)
        worker = self.client.get("/sw.js")
        self.assertEqual(worker.status_code, 200)
        self.assertEqual(worker.headers["cache-control"], "no-cache")
        self.assertIn("sentinel-shell:", worker.text)
        page = self.client.get("/", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.headers["content-encoding"], "gzip")
        self.assertIn("Download offline HTML", page.text)

    def test_capture_authorization(self):
        other = self.client.post("/api/sessions", json={}).json()
        for headers in ({"Content-Type": "application/octet-stream"}, {"Authorization": "Bearer " + other["token"]}):
            self.assertEqual(self.post(headers=headers).status_code, 401)
            self.assertEqual(self.client.get(self.route, headers=headers).status_code, 401)

    def test_invalid_capture_and_conflicting_upload_are_atomic(self):
        self.assertEqual(self.post(b"bad capture").status_code, 422)
        self.assertEqual(self.client.get(self.route, headers=self.headers).status_code, 404)
        self.assertEqual(self.post().status_code, 200)
        other, _ = make_capture(5000, True)
        self.assertEqual(self.post(other).status_code, 409)
        self.assertEqual(self.client.get(self.route, headers=self.headers).json()["summary"]["capture_sha256"], hashlib.sha256(self.sample).hexdigest())

    def test_failure_after_summary_insert_rolls_back(self):
        class BrokenScorer:
            model_id = "broken"
            def __call__(self, data):
                return {"summary": {}, "flows": [{}]}
        self.app.state.flow_scorer = BrokenScorer()
        self.assertEqual(self.post().status_code, 503)
        self.assertEqual(self.client.get(self.route, headers=self.headers).status_code, 404)

    def test_body_limit_and_cors(self):
        response = self.post(bytes(512*1024+1), {**self.headers, "Origin": "https://harthik777.github.io"})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["access-control-allow-origin"], "https://harthik777.github.io")

    def test_sample_metadata_and_cascade_deletion(self):
        self.assertEqual(self.client.get("/api/packets/sample").content, self.sample)
        self.assertEqual(self.client.get("/api/packets/model").json()["feature_count"], 13)
        self.post()
        with self.app.state.store.connect() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (self.auth["session_id"],))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM capture_flows").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
