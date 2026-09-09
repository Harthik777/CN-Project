/** Browser implementation of backend/packets.py, checked against Python on every release.
 * Only header metadata survives decoding. No network calls, payload retention or model fitting.
 */
export type PacketPreview = { packet_number: number; direction: string; offset_ms: number; flags: string;
  seq: number | null; ack: number | null; ip_bytes: number; payload_bytes: number; ttl: number };
export type Flow = {
  flow_id: number; ip_version: number; source_ip: string; source_port: number; destination_ip: string; destination_port: number;
  protocol: string; packets: number; ip_bytes: number; duration_ms: number; payload_bytes: number; start_timestamp: number;
  forward_packets: number; reverse_packets: number; forward_bytes: number; reverse_bytes: number;
  syn: number; ack: number; fin: number; rst: number; repeated_payload_ranges: number;
  iat_mean_ms: number; iat_cv: number; anomaly_score: number; is_alert: boolean;
  evidence: string[]; features: Record<string, number>; packet_preview: PacketPreview[];
  handshake: { syn_packet: number; syn_ack_packet: number; ack_packet: number; syn_to_syn_ack_ms: number; completion_ms: number } | null;
};
export type Report = {
  summary: { capture_sha256: string; file_bytes: number; packet_records: number; parsed_packets: number; skipped_packets: number;
    skipped_by_reason: Record<string, number>; flows: number; protocols: Record<string, number>; completed_handshakes: number;
    total_ip_bytes: number; duration_ms: number; analysis_ms?: number; flagged_flows: number; link_type: string;
    start_utc: string; end_utc: string; out_of_order_records: number; flow_definition: string;
    format: string; captured_bytes: number; original_record_bytes: number; timestamp_resolution: string; ip_versions: Record<string, number> };
  flows: Flow[]; limitations: string[];
  model: { model_id: string; model: string; feature_count: number; threshold: number; training_scope: string;
    train_flows: number; validation_flows: number; test_flows: number;
    test_metrics: { precision: number; recall: number; f1: number; false_positive_rate: number } };
};
export type BrowserModel = { schema: number; features: string[]; normalizer: number; trees: number[][][];
  model: Report["model"]; limitations: string[]; sample_sha256: string; artifact_sha256: string };
type Packet = { ip_version: number; source_ip: string; destination_ip: string; source_port: number; destination_port: number;
  protocol: string; ip_bytes: number; payload_bytes: number; ttl: number; flags: number; seq: number | null; ack: number | null;
  timestamp: number; packet_number: number };
export class CaptureError extends Error {}
class SkippedPacket extends Error {}
const skip = (reason: string): never => { throw new SkippedPacket(reason); };
const round = (value: number) => Math.round(value * 1e6) / 1e6;
const mean = (values: number[]) => values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;
export const FEATURE_NAMES = ["log_duration_ms", "log_packets", "log_ip_bytes", "log_payload_bytes", "mean_ip_packet_bytes",
  "reverse_packet_fraction", "reverse_byte_fraction", "log_iat_mean_ms", "iat_cv", "syn_fraction", "rst_fraction", "repeated_payload_fraction", "is_udp"];
const LINKS: Record<number, string> = { 1: "Ethernet", 101: "Raw IP", 228: "Raw IPv4", 229: "Raw IPv6", 113: "Linux cooked v1" };

function address(bytes: Uint8Array): string {
  if (bytes.length === 4) return [...bytes].join(".");
  const words = Array.from({ length: 8 }, (_, i) => (bytes[i*2] << 8 | bytes[i*2+1]).toString(16));
  let best = -1, size = 1;
  for (let i = 0; i < 8;) {
    if (words[i] !== "0") { i++; continue; }
    let end = i; while (end < 8 && words[end] === "0") end++;
    if (end-i > size) { best = i; size = end-i; } i = end;
  }
  return best < 0 ? words.join(":") : `${words.slice(0,best).join(":")}::${words.slice(best+size).join(":")}`;
}
function decode(frame: Uint8Array, link: number): Omit<Packet, "timestamp" | "packet_number"> {
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  let offset = 0, kind: number | undefined;
  if (link === 1) {
    if (frame.length < 14) skip("truncated_header");
    kind = view.getUint16(12); offset = 14;
    for (let i = 0; i < 2 && (kind === 0x8100 || kind === 0x88a8); i++) {
      if (frame.length < offset+4) skip("truncated_header");
      kind = view.getUint16(offset+2); offset += 4;
    }
    if (kind !== 0x0800 && kind !== 0x86dd) skip("non_ip");
  } else if (link === 113) {
    if (frame.length < 16) skip("truncated_header");
    kind = view.getUint16(14); offset = 16;
    if (kind !== 0x0800 && kind !== 0x86dd) skip("non_ip");
  } else { kind = link === 228 ? 0x0800 : link === 229 ? 0x86dd : undefined; }
  const raw = frame.subarray(offset), ip = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  if (!raw.length) skip("truncated_header");
  const version = raw[0] >> 4;
  if (kind && version !== (kind === 0x0800 ? 4 : 6)) skip("malformed_ip");
  let header: number, length: number, protocol: number, ttl: number, source: Uint8Array, destination: Uint8Array;
  if (version === 4) {
    if (raw.length < 20) skip("truncated_header");
    header = (raw[0] & 15)*4; length = ip.getUint16(2);
    if (header < 20 || length < header) skip("malformed_ip");
    if (raw.length < length) skip("truncated_ip");
    if (ip.getUint16(6) & 0x3fff) skip("fragmented_ip");
    protocol = raw[9]; ttl = raw[8]; source = raw.subarray(12,16); destination = raw.subarray(16,20);
  } else if (version === 6) {
    if (raw.length < 40) skip("truncated_header");
    length = 40 + ip.getUint16(4);
    if (length === 40) skip("unsupported_ipv6_jumbogram");
    if (raw.length < length) skip("truncated_ip");
    protocol = raw[6]; ttl = raw[7]; header = 40; source = raw.subarray(8,24); destination = raw.subarray(24,40);
    for (let i = 0; i < 8; i++) {
      if (protocol === 44) skip("fragmented_ip");
      if (![0,43,60,51].includes(protocol)) break;
      if (header+2 > length) skip("malformed_ipv6_extension");
      const next = raw[header], size = protocol === 51 ? (raw[header+1]+2)*4 : (raw[header+1]+1)*8;
      header += size; if (header > length) skip("malformed_ipv6_extension"); protocol = next;
    }
    if ([0,43,60,51,44].includes(protocol)) skip("unsupported_ipv6_extension");
  } else { return skip("non_ip"); }
  const transport = raw.subarray(header,length), tcp = new DataView(transport.buffer, transport.byteOffset, transport.byteLength);
  let sport: number, dport: number, seq: number | null = null, ack: number | null = null, flags = 0, payload: number;
  if (protocol === 6) {
    if (transport.length < 20) skip("truncated_transport");
    sport = tcp.getUint16(0); dport = tcp.getUint16(2); seq = tcp.getUint32(4); ack = tcp.getUint32(8);
    const tcpHeader = (transport[12] >> 4)*4;
    if (tcpHeader < 20 || tcpHeader > transport.length) skip("malformed_tcp");
    flags = transport[13]; payload = transport.length - tcpHeader;
  } else if (protocol === 17) {
    if (transport.length < 8) skip("truncated_transport");
    sport = tcp.getUint16(0); dport = tcp.getUint16(2); const size = tcp.getUint16(4);
    if (size < 8 || size > transport.length) skip("malformed_udp"); payload = size-8;
  } else { return skip("other_ip_protocol"); }
  return { ip_version: version, source_ip: address(source), destination_ip: address(destination), source_port: sport,
    destination_port: dport, protocol: protocol === 6 ? "TCP" : "UDP", ip_bytes: length, payload_bytes: payload, ttl, flags, seq, ack };
}
function utc(timestamp: number) {
  const micros = Math.round(timestamp * 1e6), seconds = Math.floor(micros / 1e6), fraction = micros - seconds*1e6;
  return new Date(seconds*1000).toISOString().slice(0,19) + (fraction ? `.${String(fraction).padStart(6,"0")}` : "") + "+00:00";
}
function flagText(flags: number) {
  return ([[2,"SYN"],[16,"ACK"],[1,"FIN"],[4,"RST"],[8,"PSH"],[32,"URG"],[64,"ECE"],[128,"CWR"]] as const)
    .filter(([bit]) => flags & bit).map(([,name]) => name).join(" ");
}
const endpoint = (p: Packet) => JSON.stringify([p.source_ip, p.source_port]);
function summarize(packets: Packet[], ordinal: number): Flow {
  const first = packets[0], sender = endpoint(first), forward = (p: Packet) => endpoint(p) === sender;
  const counts: Record<string, number> = Object.fromEntries(["forward_packets","reverse_packets","forward_bytes","reverse_bytes","payload_bytes","syn","ack","fin","rst","repeated_payload_ranges"].map(k => [k,0]));
  const seen = new Set<string>(), preview: PacketPreview[] = [];
  let syn: Packet | null = null, synack: Packet | null = null, handshake: Flow["handshake"] = null;
  for (const p of packets) {
    const direction = forward(p) ? "forward" : "reverse";
    counts[`${direction}_packets`]++; counts[`${direction}_bytes`] += p.ip_bytes; counts.payload_bytes += p.payload_bytes;
    for (const [bit,name] of [[2,"syn"],[1,"fin"],[4,"rst"],[16,"ack"]] as const) counts[name] += Number(!!(p.flags & bit));
    if (p.protocol === "TCP") {
      if (p.payload_bytes) {
        const key = `${direction}/${p.seq}/${p.payload_bytes}`;
        counts.repeated_payload_ranges += Number(seen.has(key)); seen.add(key);
      }
      if (!syn && (p.flags & 0x12) === 2) syn = p;
      else if (syn && !synack && (p.flags & 0x12) === 0x12) {
        if (forward(p) !== forward(syn) && p.ack === ((syn.seq!+1) >>> 0)) synack = p;
      } else if (syn && synack && !handshake && (p.flags & 0x12) === 0x10 && !(p.flags & 4)) {
        if (forward(p) === forward(syn) && p.ack === ((synack.seq!+1) >>> 0) && p.seq === ((syn.seq!+1) >>> 0)) {
          handshake = { syn_packet: syn.packet_number, syn_ack_packet: synack.packet_number, ack_packet: p.packet_number,
            syn_to_syn_ack_ms: round((synack.timestamp-syn.timestamp)*1000), completion_ms: round((p.timestamp-syn.timestamp)*1000) };
        }
      }
    }
    if (preview.length < 12) preview.push({ packet_number: p.packet_number, direction, offset_ms: round((p.timestamp-first.timestamp)*1000),
      flags: flagText(p.flags), seq: p.seq, ack: p.ack, ip_bytes: p.ip_bytes, payload_bytes: p.payload_bytes, ttl: p.ttl });
  }
  const intervals = packets.slice(1).map((p,i) => (p.timestamp-packets[i].timestamp)*1000), avg = mean(intervals);
  const flow: Flow = { ip_version: first.ip_version, source_ip: first.source_ip, source_port: first.source_port,
    destination_ip: first.destination_ip, destination_port: first.destination_port, protocol: first.protocol,
    flow_id: ordinal, start_timestamp: first.timestamp, duration_ms: round((packets[packets.length-1].timestamp-first.timestamp)*1000),
    packets: packets.length, ip_bytes: packets.reduce((sum,p) => sum+p.ip_bytes,0), iat_mean_ms: avg,
    iat_cv: avg ? Math.sqrt(mean(intervals.map(v => (v-avg)**2)))/avg : 0,
    forward_packets: counts.forward_packets, reverse_packets: counts.reverse_packets, forward_bytes: counts.forward_bytes,
    reverse_bytes: counts.reverse_bytes, payload_bytes: counts.payload_bytes, syn: counts.syn, ack: counts.ack, fin: counts.fin, rst: counts.rst,
    repeated_payload_ranges: counts.repeated_payload_ranges, handshake, packet_preview: preview, evidence: [], features: {}, anomaly_score: 0, is_alert: false };
  if (flow.protocol === "TCP" && !handshake) flow.evidence.push("No complete matching TCP handshake visible in the capture");
  if (!flow.reverse_packets) flow.evidence.push("Only one direction observed");
  if (flow.rst) flow.evidence.push(`${flow.rst} TCP reset flag(s) observed`);
  if (flow.repeated_payload_ranges) flow.evidence.push("Repeated TCP sequence/length ranges; retransmission or duplicate capture is possible");
  return flow;
}
export function flowFeatures(f: Flow): number[] {
  return [Math.log1p(f.duration_ms), Math.log1p(f.packets), Math.log1p(f.ip_bytes), Math.log1p(f.payload_bytes), f.ip_bytes/f.packets,
    f.reverse_packets/f.packets, f.reverse_bytes/f.ip_bytes, Math.log1p(f.iat_mean_ms), f.iat_cv, f.syn/f.packets,
    f.rst/f.packets, f.repeated_payload_ranges/f.packets, Number(f.protocol === "UDP")];
}
export function forestScore(features: number[], model: BrowserModel): number {
  // sklearn's tree input is float32; preserving that conversion matters near split thresholds.
  const values = features.map(Math.fround);
  let total = 0;
  for (const tree of model.trees) {
    let index = 0;
    while (tree[index][0] !== -1) {
      const node = tree[index]; index = values[node[2]] <= node[3] ? node[0] : node[1];
    }
    total += tree[index][4];
  }
  return Math.pow(2, -total/model.normalizer);
}
export async function analyzeCapture(data: Uint8Array, model: BrowserModel): Promise<Report> {
  const started = performance.now();
  if (data.length < 24 || data.length > 512*1024) throw new CaptureError("Capture must be between 24 bytes and 512 KiB");
  const magic = [...data.subarray(0,4)].map(v => v.toString(16).padStart(2,"0")).join("");
  if (magic === "0a0d0d0a") throw new CaptureError("PCAPNG is not supported yet. In Wireshark use Save As and select pcap.");
  const formats: Record<string,[boolean,number]> = { d4c3b2a1:[true,1e6], a1b2c3d4:[false,1e6], "4d3cb2a1":[true,1e9], a1b23c4d:[false,1e9] };
  if (!formats[magic]) throw new CaptureError("Expected a classic PCAP file with a complete global header");
  const [le,resolution] = formats[magic], v = new DataView(data.buffer,data.byteOffset,data.byteLength);
  const snaplen = v.getUint32(16,le), link = v.getUint32(20,le);
  if (v.getUint16(4,le) !== 2 || v.getUint16(6,le) !== 4 || snaplen < 1 || snaplen > 16*1024*1024) throw new CaptureError("Unsupported PCAP version or invalid snapshot length");
  if (!LINKS[link]) throw new CaptureError("Unsupported link type. Use Ethernet, raw IP, or Linux cooked v1 PCAP.");
  let offset = 24, records = 0, previous: number | null = null, captured = 0, wire = 0, nonMonotonic = 0;
  const packets: Packet[] = [], skipped: Record<string,number> = {}, times: number[] = [];
  while (offset < data.length) {
    if (records >= 6000) throw new CaptureError("Capture exceeds 6000 packet records");
    if (offset+16 > data.length) throw new CaptureError("Truncated PCAP packet-record header");
    const seconds = v.getUint32(offset,le), fraction = v.getUint32(offset+4,le), included = v.getUint32(offset+8,le), original = v.getUint32(offset+12,le);
    offset += 16;
    if (fraction >= resolution || included > snaplen || included > original || offset+included > data.length) throw new CaptureError("Invalid packet-record timestamp or length");
    const timestamp = seconds+fraction/resolution;
    nonMonotonic += Number(previous !== null && timestamp < previous); previous = timestamp; times.push(timestamp);
    captured += included; wire += original; records++;
    try { packets.push({ ...decode(data.subarray(offset,offset+included),link), timestamp, packet_number: records }); }
    catch (error) { if (!(error instanceof SkippedPacket)) throw error; skipped[error.message] = (skipped[error.message] || 0)+1; }
    offset += included;
  }
  if (!packets.length) throw new CaptureError("No complete supported TCP/UDP packets found in this capture");
  packets.sort((a,b) => a.timestamp-b.timestamp || a.packet_number-b.packet_number);
  const groups: Packet[][] = [], active = new Map<string,Packet[]>(), synSequences = new Map<string,Map<string,number>>();
  const protocols: Record<string,number> = {}, ipVersions: Record<string,number> = {};
  for (const p of packets) {
    const ends = [[p.source_ip,p.source_port],[p.destination_ip,p.destination_port]].sort((a,b) => String(a[0]) < String(b[0]) ? -1 : String(a[0]) > String(b[0]) ? 1 : Number(a[1])-Number(b[1]));
    const key = JSON.stringify([p.protocol,...ends]), sender = endpoint(p), newSyn = p.protocol === "TCP" && (p.flags & 0x12) === 2;
    let group = active.get(key); const previousSyn = synSequences.get(key)?.get(sender);
    if (!group || p.timestamp-group[group.length-1].timestamp > 60 || (newSyn && previousSyn !== undefined && previousSyn !== p.seq)) {
      if (groups.length >= 250) throw new CaptureError("Capture exceeds 250 flows; select a smaller time interval");
      group = []; groups.push(group); active.set(key,group); synSequences.set(key,new Map());
    }
    if (newSyn && !synSequences.get(key)!.has(sender)) synSequences.get(key)!.set(sender,p.seq!);
    group.push(p); protocols[p.protocol] = (protocols[p.protocol] || 0)+1; ipVersions[p.ip_version] = (ipVersions[p.ip_version] || 0)+1;
  }
  if (model.schema !== 1 || JSON.stringify(model.features) !== JSON.stringify(FEATURE_NAMES) || model.trees.length !== 100) throw new Error("Packaged browser model is incompatible. Reload the application.");
  const flows = groups.map((group,i) => summarize(group,i+1));
  for (const flow of flows) {
    const features = flowFeatures(flow); flow.features = Object.fromEntries(FEATURE_NAMES.map((key,i) => [key,features[i]]));
    flow.anomaly_score = forestScore(features,model); flow.is_alert = flow.anomaly_score > model.model.threshold;
  }
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(data));
  return { summary: { capture_sha256: [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2,"0")).join(""),
    format: "pcap", link_type: LINKS[link], file_bytes: data.length, packet_records: records, parsed_packets: packets.length,
    skipped_packets: Object.values(skipped).reduce((a,b) => a+b,0), skipped_by_reason: skipped, captured_bytes: captured,
    original_record_bytes: wire, timestamp_resolution: resolution === 1e9 ? "nanoseconds" : "microseconds", out_of_order_records: nonMonotonic,
    duration_ms: round((Math.max(...times)-Math.min(...times))*1000), start_utc: utc(Math.min(...times)), end_utc: utc(Math.max(...times)),
    flows: flows.length, protocols, ip_versions: ipVersions, completed_handshakes: flows.filter(f => f.handshake).length,
    flow_definition: "Bidirectional five-tuple, 60-second idle timeout; new TCP SYN sequence starts a new flow",
    total_ip_bytes: flows.reduce((sum,f) => sum+f.ip_bytes,0), flagged_flows: flows.filter(f => f.is_alert).length, analysis_ms: round(performance.now()-started) },
    flows, model: structuredClone(model.model), limitations: [...model.limitations] };
}

export function isReport(data: unknown): data is Report {
  if (!data || typeof data !== "object") return false;
  const r = data as Report, numbers = (keys: string[], row: object) => keys.every(k => Number.isFinite((row as Record<string,unknown>)[k]));
  return !!r.summary && !!r.model && typeof r.model.model_id === "string" && numbers(["threshold","train_flows","validation_flows","test_flows"],r.model)
    && !!r.model.test_metrics && numbers(["precision","recall","false_positive_rate"],r.model.test_metrics)
    && Array.isArray(r.limitations) && r.limitations.every(x => typeof x === "string")
    && typeof r.summary.capture_sha256 === "string" && numbers(["parsed_packets","skipped_packets","packet_records","flows","completed_handshakes","flagged_flows"],r.summary)
    && !!r.summary.protocols && !!r.summary.skipped_by_reason && Array.isArray(r.flows) && r.flows.length <= 250
    && r.flows.every(f => f && numbers(["flow_id","ip_version","source_port","destination_port","packets","ip_bytes","payload_bytes","duration_ms","iat_mean_ms","anomaly_score","forward_packets","reverse_packets"],f)
      && [f.source_ip,f.destination_ip,f.protocol].every(x => typeof x === "string") && typeof f.is_alert === "boolean"
      && !!f.features && Object.keys(f.features).length === 13 && Object.values(f.features).every(Number.isFinite)
      && Array.isArray(f.evidence) && f.evidence.every(x => typeof x === "string") && Array.isArray(f.packet_preview) && f.packet_preview.length <= 12
      && f.packet_preview.every(p => p && numbers(["packet_number","offset_ms","ip_bytes","payload_bytes","ttl"],p)
        && [p.flags,p.direction].every(x => typeof x === "string") && [p.seq,p.ack].every(x => x === null || Number.isFinite(x)))
      && (f.handshake === null || (!!f.handshake && numbers(["syn_packet","syn_ack_packet","ack_packet","syn_to_syn_ack_ms","completion_ms"],f.handshake))));
}
