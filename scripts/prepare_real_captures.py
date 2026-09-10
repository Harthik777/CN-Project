"""Reproduce bounded, payload-redacted excerpts from pinned public CTU captures.

Downloads are an explicit preparation step. Tests and the demo use packaged data.
Selection uses source record positions, never model scores or attack labels.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from backend.flow_model import FlowScorer
from backend.packets import MAGIC, SkippedPacket, _decode

DEST = ROOT / "artifacts" / "real_captures"
SOURCES = [
    dict(id="normal-dns", title="CTU Normal 4: recorded DNS traffic", context="Publisher-described normal DNS traffic",
         file="normal-dns.pcap", bytes=772961,
         sha256="7fbefbe1a18867bc683f59890cbc0124e5f6166e5aa13035fcf1ccf2f06f7ae4",
         url="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/2015-03-24_capture1-only-dns.pcap",
         source_page="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/",
         citation="Garcia, Sebastian. Malware Capture Facility Project. Stratosphere Laboratory.",
         terms="Use with attribution to the project and authors; see the publisher FAQ.",
         terms_url="https://www.stratosphereips.org/datasets-faq"),
    dict(id="ctu13-7", title="CTU-13 scenario 7: recorded botnet-host traffic", context="Capture from the infected virtual machine in CTU-13 scenario 7",
         file="ctu13-7.pcap", bytes=18868213,
         sha256="ff5c18adaa6a4681df1db43d0eac10d05e65d51931d5380ca54ceff0d005d2c5",
         url="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/botnet-capture-20110816-sogou.pcap",
         source_page="https://www.stratosphereips.org/datasets-ctu13",
         citation="Garcia, S., Grill, M., Stiborek, J., and Zunino, A. (2014). An empirical comparison of botnet detection methods. Computers & Security 45, 100-123. https://doi.org/10.1016/j.cose.2014.05.011",
         terms="Creative Commons Attribution (CC-BY), as stated by Stratosphere Laboratory.",
         terms_url="https://www.stratosphereips.org/datasets-overview"),
]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def redact(frame):
    """Zero payload and link padding, preserving IPv4/TCP/UDP headers and lengths."""
    frame = bytearray(frame)
    if frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
        raise ValueError("This dataset preparation step expects Ethernet IPv4")
    ip_header = (frame[14] & 15) * 4
    ip_length = struct.unpack_from("!H", frame, 16)[0]
    start = 14 + ip_header
    proto = frame[23]
    if proto == 6:
        header, size, check_offset = (frame[start + 12] >> 4) * 4, ip_length - ip_header, 16
    elif proto == 17:
        header, size, check_offset = 8, struct.unpack_from("!H", frame, start + 4)[0], 6
    else:
        raise ValueError("Only TCP/UDP packets can be packaged")
    frame[start + header:] = bytes(len(frame) - start - header)
    struct.pack_into("!H", frame, start + check_offset, 0)
    pseudo = bytes(frame[26:34]) + struct.pack("!BBH", 0, proto, size)
    value = checksum(pseudo + bytes(frame[start:start + size]))
    struct.pack_into("!H", frame, start + check_offset, value or 65535)
    return bytes(frame)


def records(data):
    endian, _ = MAGIC[data[:4]]
    if struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise ValueError("Source must use Ethernet")
    offset, number = 24, 0
    while offset < len(data):
        header = data[offset:offset + 16]
        _, _, included, original = struct.unpack(endian + "IIII", header)
        if included > original or offset + 16 + included > len(data):
            raise ValueError("Invalid source record")
        number += 1
        frame = data[offset + 16:offset + 16 + included]
        yield number, header, frame
        offset += 16 + included


def prepare(source, cache, scorer):
    data = (cache / source["file"]).read_bytes()
    if len(data) != source["bytes"] or hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError(f"Source hash mismatch: {source['id']}")
    valid, skipped = [], Counter()
    for number, header, frame in records(data):
        try:
            _decode(frame, 1)
            valid.append((number, header, frame))
        except SkippedPacket as exc:
            skipped[str(exc)] += 1
    items = []
    for position, start in (("start", 0), ("middle", len(valid) // 2 - 100), ("end", len(valid) - 200)):
        selected = valid[start:start + 200]
        original = data[:24] + b"".join(h + f for _, h, f in selected)
        redacted = data[:24] + b"".join(h + redact(f) for _, h, f in selected)
        if len(redacted) > 512 * 1024:
            raise ValueError("Excerpt exceeds the browser upload limit")
        before, after = scorer(original), scorer(redacted)
        if before["flows"] != after["flows"]:
            raise AssertionError("Redaction changed a flow feature, score or header observation")
        identifier = f"{source['id']}-{position}"
        item = dict(id=identifier, title=f"{source['title']} ({position})", source_id=source["id"],
                    file=f"{identifier}.pcap", sha256=hashlib.sha256(redacted).hexdigest(),
                    original_excerpt_sha256=hashlib.sha256(original).hexdigest(),
                    source_packet_numbers=[n for n, _, _ in selected],
                    source_supported_packets=len(valid), source_skipped=dict(skipped),
                    position=position, selection_start_supported_index=start,
                    summary=after["summary"], redaction_preserves_features_and_scores=True)
        (DEST / item["file"]).write_bytes(redacted)
        items.append(item)
    return items


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=ROOT / "output" / "ctu-source")
    parser.add_argument("--download", action="store_true", help="Download the two pinned PCAPs from their publishers")
    args = parser.parse_args()
    args.source_dir.mkdir(parents=True, exist_ok=True)
    if args.download:
        for item in SOURCES:
            path = args.source_dir / item["file"]
            if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]:
                continue
            with urllib.request.urlopen(item["url"], timeout=30) as response:
                data = response.read(item["bytes"] + 1)
            if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("Publisher file changed; review provenance before accepting it")
            path.write_bytes(data)
    DEST.mkdir(parents=True, exist_ok=True)
    scorer = FlowScorer()
    captures = [capture for source in SOURCES for capture in prepare(source, args.source_dir, scorer)]
    manifest = dict(version="public-pcap-v1", sources=SOURCES, captures=captures, model_id=scorer.model_id,
                    selection="200 complete supported TCP/UDP packets from the beginning, midpoint and end of each source's supported-packet sequence. Selection is independent of scores and labels.",
                    modification="Application payload and link padding bytes replaced by zeros; TCP/UDP checksums recalculated. Addresses, timestamps, packet sizes, flags, sequence numbers and TCP options retained. These are derived captures, not unmodified originals.",
                    label_scope="Capture context only. The publisher's Argus labels describe different flow boundaries; they were not joined to these bounded excerpts. No per-flow attack ground truth or real-data accuracy is claimed.",
                    limitation="The model is still trained on synthetic captures. An outlier flag is not a verified attack. Small excerpts can start or end mid-conversation and are not representative of the whole datasets.")
    (DEST / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"captures": len(captures), "packets": sum(c["summary"]["parsed_packets"] for c in captures),
                      "flows": sum(c["summary"]["flows"] for c in captures),
                      "results": [{"id": c["id"], "bytes": c["summary"]["file_bytes"], "flows": c["summary"]["flows"], "flags": c["summary"]["flagged_flows"]} for c in captures]}, indent=2))


if __name__ == "__main__":
    main()
