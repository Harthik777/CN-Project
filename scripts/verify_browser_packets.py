"""Differential tests: independent Python and browser parsers/scorers, including malformed captures."""
import argparse
import base64
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from backend.flow_model import ARTIFACTS, FlowScorer
from backend.packets import CaptureError
from scripts.train_flow_model import frame, pcap, make_capture


def fixtures():
    a, b = "192.0.2.1", "198.51.100.2"
    syn = frame(a,b,1,2,flags=2,seq=100,ack=0)
    synack = frame(b,a,2,1,flags=18,seq=200,ack=101)
    ack = frame(a,b,1,2,flags=16,seq=101,ack=201)
    records = [(1000,syn),(1000.02,synack),(1000.03,ack)]
    yield "sample", (ARTIFACTS / "sample_capture.pcap").read_bytes()
    for seed in list(range(1000,1020)) + list(range(2000,2008)) + list(range(3000,3008)):
        yield f"capture-{seed}", make_capture(seed, seed >= 3000)[0]
    for endian in ("<",">"):
        for nano in (False,True):
            yield f"timestamp-{endian}-{nano}", pcap(records,endian=endian,nano=nano)
    yield "out-of-order", pcap(records[::-1])
    yield "bad-ack", pcap(records[:2]+[(1000.03,frame(a,b,1,2,flags=16,seq=101,ack=999))])
    yield "bad-synack", pcap([records[0],(1000.02,frame(b,a,2,1,flags=18,seq=200,ack=999)),records[2]])
    yield "sequence-wrap", pcap([(1,frame(a,b,1,2,flags=2,seq=2**32-1,ack=0)),(2,frame(b,a,2,1,flags=18,seq=2**32-1,ack=0)),(3,frame(a,b,1,2,flags=16,seq=0,ack=0))])
    ipv6 = frame("2001:db8::1","2001:db8::2",1,2,protocol="UDP",ipv6=True,payload=12)
    for link,packet in ((101,syn[14:]),(228,syn[14:]),(229,ipv6[14:]),(113,bytes(14)+bytes.fromhex("0800")+syn[14:]),(1,syn[:12]+bytes.fromhex("8100000188a800020800")+syn[14:])):
        yield f"link-{link}", pcap([(1,packet)],link=link)
    extension = bytearray(ipv6); extension[20]=0; extension[18:20]=struct.pack("!H",28)
    yield "ipv6-extension", pcap([(1,extension[:54]+bytes([17,0])+bytes(6)+extension[54:])])
    fragment = bytearray(syn); fragment[20:22]=struct.pack("!H",0x2000)
    icmp = bytearray(syn); icmp[23]=1
    tcp = bytearray(syn); tcp[46]=0x10
    udp = bytearray(frame(a,b,1,2,protocol="UDP")); udp[38:40]=b"\xff\xff"
    yield "skip-accounting", pcap(records+[(1001,fragment),(1002,icmp),(1003,syn[:20]),(1004,tcp),(1005,udp)])
    fresh=frame(a,b,1,2,flags=2,seq=999,ack=0)
    yield "new-flow-and-idle", pcap(records+[(1001,fresh),(1070,fresh)])
    payload=frame(a,b,1,2,payload=40)
    yield "repeat-and-preview", pcap(records+[(1000.04+i*.01,payload) for i in range(25)])
    yield "truncated-ip", pcap(records+[(1001,payload[:-1])])
    yield "nanosecond-precision", pcap([(1000.000000123,syn),(1000.123456789,synack),(1000.123456999,ack)],nano=True)
    yield "ipv6-address-compression", pcap([(1,frame("::","ffff:0:0:1:0:0:0:1",1,2,protocol="UDP",ipv6=True,payload=1))])
    for name,data in (("empty",b""),("pcapng",b"\x0a\x0d\x0d\x0a"+bytes(24)),("short-global",pcap(records)[:23]),("short-record",pcap(records)[:-1]),("extra-header",pcap(records)+bytes(3)),("too-large",bytes(524289)),("too-many-packets",pcap([(i,syn) for i in range(6001)])),("too-many-flows",pcap([(i,frame(a,b,i,2,flags=2)) for i in range(251)]))):
        yield name,data
    valid=pcap(records)
    for position,value in ((4,99),(16,0),(20,999),(28,1_000_000),(32,0xffffffff)):
        data=bytearray(valid); struct.pack_into("<I",data,position,value)
        yield f"bad-header-{position}",bytes(data)
    # Deterministic byte-level corruptions exercise graceful whole-file rejection and skip accounting.
    import random
    rng=random.Random(77)
    for i in range(60):
        data=bytearray(valid)
        for _ in range(1+i%3): data[rng.randrange(len(data))]=rng.randrange(256)
        yield f"mutated-{i}",bytes(data)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--node",default="node"); args=parser.parse_args()
    scorer=FlowScorer(); rows=[]
    for name,data in fixtures():
        item={"name":name,"pcap":base64.b64encode(data).decode()}
        try: item["expected"]=scorer(data)
        except CaptureError: item["reject"]=True
        rows.append(item)
    output=ROOT/"output"/"browser-parity"; output.mkdir(parents=True,exist_ok=True)
    path=output/"fixtures.json"; path.write_text(json.dumps(rows),encoding="utf-8")
    subprocess.run([args.node,"--experimental-strip-types",str(ROOT/"frontend"/"tests"/"packet-parity.mjs"),str(path),str(output/"results.json")],check=True,cwd=ROOT)
