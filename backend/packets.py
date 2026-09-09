"""Bounded classic-PCAP decoder and bidirectional TCP/UDP flow extraction.

Only headers and lengths survive parsing. No payloads are stored or returned.
Fragments are counted and excluded; this is not a TCP reassembly engine.
"""
import hashlib
import ipaddress
import math
import statistics
import struct
from collections import Counter
from datetime import datetime, timezone

MAX_CAPTURE_BYTES = 512 * 1024
MAX_PACKETS = 6000
MAX_FLOWS = 250
IDLE_SECONDS = 60
MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 10**6), b"\xa1\xb2\xc3\xd4": (">", 10**6),
         b"\x4d\x3c\xb2\xa1": ("<", 10**9), b"\xa1\xb2\x3c\x4d": (">", 10**9)}
LINKS = {1: "Ethernet", 101: "Raw IP", 228: "Raw IPv4", 229: "Raw IPv6", 113: "Linux cooked v1"}


class CaptureError(ValueError):
    pass


class SkippedPacket(ValueError):
    pass


def _decode(frame, link):
    offset = 0
    if link == 1:
        if len(frame) < 14:
            raise SkippedPacket("truncated_header")
        kind = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        for _ in range(2):
            if kind not in (0x8100, 0x88a8):
                break
            if len(frame) < offset + 4:
                raise SkippedPacket("truncated_header")
            kind = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if kind not in (0x0800, 0x86dd):
            raise SkippedPacket("non_ip")
    elif link == 113:
        if len(frame) < 16:
            raise SkippedPacket("truncated_header")
        kind = struct.unpack_from("!H", frame, 14)[0]
        offset = 16
        if kind not in (0x0800, 0x86dd):
            raise SkippedPacket("non_ip")
    else:
        kind = 0x0800 if link == 228 else 0x86dd if link == 229 else None
    raw = frame[offset:]
    if not raw:
        raise SkippedPacket("truncated_header")
    version = raw[0] >> 4
    if kind and version != (4 if kind == 0x0800 else 6):
        raise SkippedPacket("malformed_ip")
    if version == 4:
        if len(raw) < 20:
            raise SkippedPacket("truncated_header")
        header = (raw[0] & 15) * 4
        length = struct.unpack_from("!H", raw, 2)[0]
        if header < 20 or length < header:
            raise SkippedPacket("malformed_ip")
        if len(raw) < length:
            raise SkippedPacket("truncated_ip")
        if struct.unpack_from("!H", raw, 6)[0] & 0x3fff:
            raise SkippedPacket("fragmented_ip")
        protocol, ttl = raw[9], raw[8]
        source, destination = raw[12:16], raw[16:20]
    elif version == 6:
        if len(raw) < 40:
            raise SkippedPacket("truncated_header")
        length = 40 + struct.unpack_from("!H", raw, 4)[0]
        if length == 40:
            raise SkippedPacket("unsupported_ipv6_jumbogram")
        if len(raw) < length:
            raise SkippedPacket("truncated_ip")
        protocol, ttl, header = raw[6], raw[7], 40
        source, destination = raw[8:24], raw[24:40]
        for _ in range(8):
            if protocol == 44:
                raise SkippedPacket("fragmented_ip")
            if protocol not in (0, 43, 60, 51):
                break
            if header + 2 > length:
                raise SkippedPacket("malformed_ipv6_extension")
            next_protocol, size = raw[header], raw[header + 1]
            size = (size + 2) * 4 if protocol == 51 else (size + 1) * 8
            header += size
            if header > length:
                raise SkippedPacket("malformed_ipv6_extension")
            protocol = next_protocol
        if protocol in (0, 43, 60, 51, 44):
            raise SkippedPacket("unsupported_ipv6_extension")
    else:
        raise SkippedPacket("non_ip")
    transport = raw[header:length]
    if protocol == 6:
        if len(transport) < 20:
            raise SkippedPacket("truncated_transport")
        sport, dport, seq, ack = struct.unpack_from("!HHII", transport)
        tcp_header = (transport[12] >> 4) * 4
        if tcp_header < 20 or tcp_header > len(transport):
            raise SkippedPacket("malformed_tcp")
        flags = transport[13]
        payload = len(transport) - tcp_header
    elif protocol == 17:
        if len(transport) < 8:
            raise SkippedPacket("truncated_transport")
        sport, dport, udp_length = struct.unpack_from("!HHH", transport)
        if udp_length < 8 or udp_length > len(transport):
            raise SkippedPacket("malformed_udp")
        flags, seq, ack, payload = 0, None, None, udp_length - 8
    else:
        raise SkippedPacket("other_ip_protocol")
    return dict(ip_version=version, source_ip=str(ipaddress.ip_address(source)),
                destination_ip=str(ipaddress.ip_address(destination)), source_port=sport,
                destination_port=dport, protocol="TCP" if protocol == 6 else "UDP",
                ip_bytes=length, payload_bytes=payload, ttl=ttl, flags=flags, seq=seq, ack=ack)


def decode_capture(data):
    if not data or len(data) > MAX_CAPTURE_BYTES:
        raise CaptureError("Capture must be between 24 bytes and 512 KiB")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raise CaptureError("PCAPNG is not supported yet. In Wireshark use Save As and select pcap.")
    if len(data) < 24 or data[:4] not in MAGIC:
        raise CaptureError("Expected a classic PCAP file with a complete global header")
    endian, resolution = MAGIC[data[:4]]
    major, minor, _, _, snaplen, link = struct.unpack_from(endian + "HHiiII", data, 4)
    if (major, minor) != (2, 4) or not 1 <= snaplen <= 16 * 1024 * 1024:
        raise CaptureError("Unsupported PCAP version or invalid snapshot length")
    if link not in LINKS:
        raise CaptureError("Unsupported link type. Use Ethernet, raw IP, or Linux cooked v1 PCAP.")
    offset, records, previous = 24, 0, None
    packets, skipped = [], Counter()
    capture_times, wire_bytes, captured_bytes, non_monotonic = [], 0, 0, 0
    while offset < len(data):
        if records >= MAX_PACKETS:
            raise CaptureError(f"Capture exceeds {MAX_PACKETS} packet records")
        if offset + 16 > len(data):
            raise CaptureError("Truncated PCAP packet-record header")
        seconds, fraction, included, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if fraction >= resolution or included > snaplen or included > original or offset + included > len(data):
            raise CaptureError("Invalid packet-record timestamp or length")
        timestamp = seconds + fraction / resolution
        non_monotonic += int(previous is not None and timestamp < previous)
        previous = timestamp
        capture_times.append(timestamp)
        captured_bytes += included
        wire_bytes += original
        records += 1
        try:
            packet = _decode(data[offset:offset + included], link)
            packet.update(timestamp=timestamp, packet_number=records, captured_bytes=included, wire_bytes=original)
            packets.append(packet)
        except SkippedPacket as exc:
            skipped[str(exc)] += 1
        offset += included
    if not packets:
        raise CaptureError("No complete supported TCP/UDP packets found in this capture")
    packets.sort(key=lambda p: (p["timestamp"], p["packet_number"]))
    summary = dict(capture_sha256=hashlib.sha256(data).hexdigest(), format="pcap", link_type=LINKS[link],
                   file_bytes=len(data), packet_records=records, parsed_packets=len(packets),
                   skipped_packets=sum(skipped.values()), skipped_by_reason=dict(skipped),
                   captured_bytes=captured_bytes, original_record_bytes=wire_bytes,
                   timestamp_resolution="nanoseconds" if resolution == 10**9 else "microseconds",
                   out_of_order_records=non_monotonic, duration_ms=round((max(capture_times)-min(capture_times))*1000, 6),
                   start_utc=datetime.fromtimestamp(min(capture_times), timezone.utc).isoformat(),
                   end_utc=datetime.fromtimestamp(max(capture_times), timezone.utc).isoformat())
    return packets, summary


def flag_text(flags):
    return " ".join(name for mask, name in ((2, "SYN"), (16, "ACK"), (1, "FIN"), (4, "RST"),
                                              (8, "PSH"), (32, "URG"), (64, "ECE"), (128, "CWR")) if flags & mask)


def _summarize_flow(packets, ordinal):
    first = packets[0]
    endpoint = (first["source_ip"], first["source_port"])
    forward = lambda p: (p["source_ip"], p["source_port"]) == endpoint
    counts = Counter()
    seen_payload = set()
    syn = synack = None
    handshake = None
    preview = []
    for packet in packets:
        direction = "forward" if forward(packet) else "reverse"
        counts[direction + "_packets"] += 1
        counts[direction + "_bytes"] += packet["ip_bytes"]
        counts["payload_bytes"] += packet["payload_bytes"]
        for bit, name in ((2, "syn"), (1, "fin"), (4, "rst"), (16, "ack")):
            counts[name] += bool(packet["flags"] & bit)
        if packet["protocol"] == "TCP":
            if packet["payload_bytes"]:
                key = (direction, packet["seq"], packet["payload_bytes"])
                counts["repeated_payload_ranges"] += key in seen_payload
                seen_payload.add(key)
            # Require matching sequence acknowledgements for all three legs.
            flags = packet["flags"]
            if syn is None and flags & 0x12 == 2:
                syn = packet
            elif syn is not None and synack is None and flags & 0x12 == 0x12:
                if forward(packet) != forward(syn) and packet["ack"] == (syn["seq"] + 1) % 2**32:
                    synack = packet
            elif synack is not None and handshake is None and flags & 0x12 == 0x10 and not flags & 4:
                if forward(packet) == forward(syn) and packet["ack"] == (synack["seq"] + 1) % 2**32 and packet["seq"] == (syn["seq"] + 1) % 2**32:
                    handshake = dict(syn_packet=syn["packet_number"], syn_ack_packet=synack["packet_number"],
                                     ack_packet=packet["packet_number"],
                                     syn_to_syn_ack_ms=round((synack["timestamp"]-syn["timestamp"])*1000, 6),
                                     completion_ms=round((packet["timestamp"]-syn["timestamp"])*1000, 6))
        if len(preview) < 12:
            preview.append(dict(packet_number=packet["packet_number"], direction=direction,
                                offset_ms=round((packet["timestamp"]-first["timestamp"])*1000, 6),
                                flags=flag_text(packet["flags"]), seq=packet["seq"], ack=packet["ack"],
                                ip_bytes=packet["ip_bytes"], payload_bytes=packet["payload_bytes"], ttl=packet["ttl"]))
    intervals = [(b["timestamp"]-a["timestamp"])*1000 for a, b in zip(packets, packets[1:])]
    mean = statistics.mean(intervals) if intervals else 0
    row = {key: first[key] for key in ("ip_version", "source_ip", "source_port", "destination_ip", "destination_port", "protocol")}
    row.update(flow_id=ordinal, start_timestamp=first["timestamp"],
               duration_ms=round((packets[-1]["timestamp"]-first["timestamp"])*1000, 6),
               packets=len(packets), ip_bytes=sum(p["ip_bytes"] for p in packets),
               iat_mean_ms=mean, iat_cv=statistics.pstdev(intervals)/mean if mean else 0,
               **{key: counts[key] for key in ("forward_packets", "reverse_packets", "forward_bytes", "reverse_bytes",
                                               "payload_bytes", "syn", "ack", "fin", "rst", "repeated_payload_ranges")},
               handshake=handshake, packet_preview=preview)
    row["evidence"] = []
    if row["protocol"] == "TCP" and not handshake:
        row["evidence"].append("No complete matching TCP handshake visible in the capture")
    if not row["reverse_packets"]:
        row["evidence"].append("Only one direction observed")
    if row["rst"]:
        row["evidence"].append(f"{row['rst']} TCP reset flag(s) observed")
    if row["repeated_payload_ranges"]:
        row["evidence"].append("Repeated TCP sequence/length ranges; retransmission or duplicate capture is possible")
    return row


def extract_flows(data):
    packets, summary = decode_capture(data)
    groups, active, syn_sequences = [], {}, {}
    for packet in packets:
        endpoints = sorted(((packet["source_ip"], packet["source_port"]), (packet["destination_ip"], packet["destination_port"])))
        key = (packet["protocol"], *endpoints)
        group = active.get(key)
        new_syn = packet["protocol"] == "TCP" and packet["flags"] & 0x12 == 2
        sender = (packet["source_ip"], packet["source_port"])
        previous_syn = syn_sequences.get(key, {}).get(sender)
        different_syn = new_syn and previous_syn is not None and previous_syn != packet["seq"]
        if group is None or packet["timestamp"] - group[-1]["timestamp"] > IDLE_SECONDS or different_syn:
            if len(groups) >= MAX_FLOWS:
                raise CaptureError(f"Capture exceeds {MAX_FLOWS} flows; select a smaller time interval")
            group = []
            groups.append(group)
            active[key] = group
            syn_sequences[key] = {}
        if new_syn:
            syn_sequences[key].setdefault(sender, packet["seq"])
        group.append(packet)
    flows = [_summarize_flow(group, i + 1) for i, group in enumerate(groups)]
    summary.update(flows=len(flows), protocols=dict(Counter(p["protocol"] for p in packets)),
                   ip_versions=dict(Counter(str(p["ip_version"]) for p in packets)),
                   completed_handshakes=sum(f["handshake"] is not None for f in flows),
                   flow_definition="Bidirectional five-tuple, 60-second idle timeout; new TCP SYN sequence starts a new flow",
                   total_ip_bytes=sum(f["ip_bytes"] for f in flows))
    return dict(summary=summary, flows=flows)


FEATURE_NAMES = ["log_duration_ms", "log_packets", "log_ip_bytes", "log_payload_bytes",
                 "mean_ip_packet_bytes", "reverse_packet_fraction", "reverse_byte_fraction",
                 "log_iat_mean_ms", "iat_cv", "syn_fraction", "rst_fraction", "repeated_payload_fraction", "is_udp"]


def flow_features(flow):
    n, size = flow["packets"], flow["ip_bytes"]
    return [math.log1p(flow["duration_ms"]), math.log1p(n), math.log1p(size), math.log1p(flow["payload_bytes"]),
            size/n, flow["reverse_packets"]/n, flow["reverse_bytes"]/size, math.log1p(flow["iat_mean_ms"]),
            flow["iat_cv"], flow["syn"]/n, flow["rst"]/n, flow["repeated_payload_ranges"]/n,
            float(flow["protocol"] == "UDP")]
