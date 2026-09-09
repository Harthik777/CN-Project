import { useEffect, useState } from "react";
import { Download, Network, Play, RefreshCw, Upload } from "lucide-react";

const API = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");
const KEY = `sentinel-packet-session-v1:${API || window.location.origin}`;
const DOC = "https://github.com/Harthik777/CN-Project/blob/codex/full-stack/docs/PACKET_LAB.md";
type Credential = { session_id: string; token: string };
type Packet = { packet_number: number; direction: string; offset_ms: number; flags: string; seq: number | null; ack: number | null; ip_bytes: number; payload_bytes: number; ttl: number };
type Flow = { flow_id: number; ip_version: number; source_ip: string; source_port: number; destination_ip: string; destination_port: number;
  protocol: string; packets: number; ip_bytes: number; duration_ms: number; payload_bytes: number; forward_packets: number; reverse_packets: number;
  iat_mean_ms: number; anomaly_score: number; is_alert: boolean; evidence: string[]; features: Record<string, number>; packet_preview: Packet[];
  handshake: { syn_packet: number; syn_ack_packet: number; ack_packet: number; syn_to_syn_ack_ms: number; completion_ms: number } | null };
type Report = { summary: { capture_sha256: string; file_bytes: number; packet_records: number; parsed_packets: number; skipped_packets: number;
  skipped_by_reason: Record<string, number>; flows: number; protocols: Record<string, number>; completed_handshakes: number; total_ip_bytes: number;
  duration_ms: number; analysis_ms: number; flagged_flows: number; link_type: string; start_utc: string; end_utc: string; out_of_order_records: number; flow_definition: string };
  flows: Flow[]; limitations: string[]; model: { model_id: string; model: string; feature_count: number; threshold: number; training_scope: string;
  train_flows: number; validation_flows: number; test_flows: number; test_metrics: { precision: number; recall: number; f1: number; false_positive_rate: number } } };

function saved(): Credential | null {
  try { const item = JSON.parse(localStorage.getItem(KEY) || "null"); return item?.session_id && item?.token ? item : null; }
  catch { return null; }
}

class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }
async function request<T>(path: string, credential?: Credential | null, body?: BodyInit, contentType = "application/json"): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 90000);
  try {
    const response = await fetch(`${API}${path}`, { method: body === undefined ? "GET" : "POST", body,
      headers: { ...(body === undefined ? {} : { "Content-Type": contentType }), ...(credential ? { Authorization: `Bearer ${credential.token}` } : {}) }, signal: controller.signal });
    if (!response.headers.get("content-type")?.includes("application/json")) throw new Error("Packet API unavailable. The free server may be waking up; try again shortly.");
    const data = await response.json();
    if (!response.ok) throw new ApiError(response.status, data.detail || `Request failed (${response.status})`);
    return data as T;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") throw new Error("Request timed out. Use Refresh saved report before submitting again.");
    throw error;
  } finally { window.clearTimeout(timer); }
}

function download(content: string, name: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = name; anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function PacketConsole() {
  const [credential, setCredential] = useState<Credential | null>(saved);
  const [report, setReport] = useState<Report | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [onlyAlerts, setOnlyAlerts] = useState(false);
  async function run(label: string, action: () => Promise<void>) {
    setBusy(label); setError(""); setNotice("");
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(""); }
  }
  async function refresh(current = credential) {
    if (!current) return;
    try { setReport(await request<Report>(`/api/sessions/${current.session_id}/capture`, current)); }
    catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 410)) {
        setCredential(null); setReport(null);
        try { localStorage.removeItem(KEY); } catch { /* Optional browser persistence. */ }
        setNotice("The previous demo session is no longer available. Analyze a capture to start a new session.");
      } else if (e instanceof ApiError && e.status === 404) { setReport(null); setNotice("This session has no saved capture yet. Analyze a capture to continue."); }
      else throw e;
    }
  }
  useEffect(() => { if (credential) void run("Reading saved packet report…", () => refresh()); }, []);
  async function analyze(sample: boolean) {
    let capture: Blob;
    if (sample) {
      const response = await fetch(`${API}/api/packets/sample`, { signal: AbortSignal.timeout(90000) });
      if (!response.ok) throw new Error("Sample capture is unavailable; try again after the server wakes up.");
      capture = await response.blob();
    } else {
      if (!file) throw new Error("Select a classic PCAP file first.");
      capture = file;
    }
    if (!capture.size || capture.size > 512 * 1024) throw new Error("Choose a capture up to 512 KiB. Use a shorter capture or export selected packets from Wireshark.");
    const next = await request<Credential>("/api/sessions", null, "{}");
    setCredential(next); setReport(null); setSelectedId(null);
    try { localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* Page-lifetime session still works. */ }
    await request(`/api/sessions/${next.session_id}/capture`, next, capture, "application/vnd.tcpdump.pcap");
    await refresh(next);
    setNotice(sample ? "Synthetic sample analyzed. Results read back from the server." : "Capture analyzed. Header-derived flow results read back from the server.");
  }
  const flows = [...(report?.flows || [])].sort((a, b) => b.anomaly_score-a.anomaly_score || a.flow_id-b.flow_id);
  const visible = onlyAlerts ? flows.filter(f => f.is_alert) : flows;
  const selected = flows.find(f => f.flow_id === selectedId) || flows[0];
  const summary = report?.summary;
  function exportCsv() {
    if (!report) return;
    const columns: (keyof Flow)[] = ["flow_id", "ip_version", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "packets", "ip_bytes", "payload_bytes", "duration_ms", "iat_mean_ms", "forward_packets", "reverse_packets", "anomaly_score", "is_alert"];
    download([columns.join(","), ...report.flows.map(row => columns.map(key => JSON.stringify(row[key])).join(","))].join("\n"), "sentinel-packet-flows.csv", "text/csv;charset=utf-8");
  }
  return <main className="live-workspace packet-workspace view-enter">
    <section className="live-intro">
      <div><div className="eyebrow">COMPUTER NETWORKS · FLOW DATA · MACHINE LEARNING</div><h2>From packets to network evidence</h2>
        <p>Inspect TCP and UDP conversations, verify handshake evidence, and find flows that differ from a learned synthetic baseline.</p>
        <p className="live-owner"><strong>Harthik M V</strong> · Computer Networks / ML / Data Engineering</p></div>
      <a className="packet-guide" href={DOC} target="_blank" rel="noreferrer">Packet lab & methodology ↗</a>
    </section>
    <div className="live-flow"><span>01 · Read PCAP headers</span><span>02 · Aggregate bidirectional flows</span><span>03 · Score 13 flow features</span><span>04 · Inspect + export evidence</span></div>
    {error && <div className="live-error" role="alert">{error}</div>}
    {(busy || notice) && <div className="live-notice" role="status">{busy || notice}</div>}
    <section className="live-panel">
      <div className="live-control-row">
        <button className="live-primary" disabled={!!busy} onClick={() => void run("Reading and analyzing the sample capture…", () => analyze(true))}><Play size={16}/>Analyze sample capture</button>
        <a href={`${API}/api/packets/sample`} download="sentinel-synthetic-sample.pcap">Download sample PCAP</a>
        <button disabled={!!busy || !credential} onClick={() => void run("Reading saved report…", () => refresh())}><RefreshCw size={15}/>Refresh saved report</button>
      </div>
      <div className="packet-upload"><label htmlFor="packet-capture">Analyze your capture<input id="packet-capture" type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" disabled={!!busy} onChange={e => setFile(e.target.files?.[0] || null)}/></label>
        <button disabled={!!busy || !file} onClick={() => void run("Uploading capture and extracting flows…", () => analyze(false))}><Upload size={15}/>Upload and analyze</button></div>
      <p className="live-muted">Classic PCAP · up to 512 KiB / 6,000 packets / 250 flows · Ethernet, raw IP, Linux cooked v1 · IPv4 and IPv6. Convert PCAPNG using Wireshark Save As → pcap.</p>
      <p className="live-muted">The server reads the uploaded file and saves header-derived results. Payloads are discarded. Use a capture you are authorized to share. The bundled sample is generated traffic, not a recording of a live network.</p>
    </section>
    <div className="live-metrics">
      <div><span>PARSED PACKETS</span><strong>{summary?.parsed_packets ?? "0"}</strong><small>{summary ? `${summary.skipped_packets} skipped / ${summary.packet_records} records` : "TCP and UDP packet headers"}</small></div>
      <div><span>BIDIRECTIONAL FLOWS</span><strong>{summary?.flows ?? "0"}</strong><small>Five-tuple + 60-second idle timeout</small></div>
      <div><span>MATCHED HANDSHAKES</span><strong>{summary?.completed_handshakes ?? "0"}</strong><small>SYN → SYN-ACK → matching ACK</small></div>
      <div><span>FLAGGED FLOWS</span><strong>{summary?.flagged_flows ?? "0"}</strong><small>Deviation from synthetic baseline</small></div>
    </div>
    <section className="live-investigation">
      <div className="live-panel live-events"><div className="live-section-heading"><h3>Network conversations</h3><label><input type="checkbox" checked={onlyAlerts} onChange={e => setOnlyAlerts(e.target.checked)}/> Flagged only</label></div>
        <div className="live-table-scroll"><table><thead><tr><th>Flow / protocol</th><th>First sender → peer</th><th>Packets / IP bytes</th><th>Duration</th><th>Outlier score</th></tr></thead><tbody>
          {visible.map(flow => <tr key={flow.flow_id} className={selected?.flow_id === flow.flow_id ? "selected" : ""}>
            <td><button aria-label={`Inspect flow ${flow.flow_id}`} onClick={() => setSelectedId(flow.flow_id)}>#{flow.flow_id}<small>{flow.protocol} / IPv{flow.ip_version}</small></button></td>
            <td className="packet-endpoints">{flow.source_ip}:{flow.source_port}<small>→ {flow.destination_ip}:{flow.destination_port}</small></td>
            <td>{flow.packets}<small>{flow.ip_bytes.toLocaleString()} bytes</small></td><td>{flow.duration_ms.toFixed(2)} ms</td>
            <td className={flow.is_alert ? "live-risk" : ""}>{flow.anomaly_score.toFixed(3)}<small>{flow.is_alert ? "Flagged" : "Below threshold"}</small></td>
          </tr>)}
        </tbody></table>{!visible.length && <div className="live-empty"><Network size={32}/><p>{report ? "No flows match this filter." : "Analyze the sample to inspect packets, flows, and model output."}</p></div>}</div>
      </div>
      <aside className="live-panel live-detail"><h3>{selected ? `Flow ${selected.flow_id} · packet evidence` : "Inspect a network flow"}</h3>
        {selected ? <><div className="live-event-risk"><strong>{selected.anomaly_score.toFixed(3)}</strong><div>{selected.is_alert ? "Above model threshold" : "Below model threshold"}<small>Threshold {report?.model.threshold.toFixed(3)} · score is not a probability</small></div></div>
          <dl className="live-evidence"><dt>Packets observed</dt><dd>{selected.forward_packets} forward / {selected.reverse_packets} reverse</dd><dt>IP bytes / transport payload bytes</dt><dd>{selected.ip_bytes.toLocaleString()} / {selected.payload_bytes.toLocaleString()}</dd><dt>Mean packet inter-arrival</dt><dd>{selected.iat_mean_ms.toFixed(3)} ms</dd></dl>
          {selected.handshake ? <div className="packet-handshake"><strong>Matching TCP handshake observed</strong><p>SYN #{selected.handshake.syn_packet} → SYN-ACK #{selected.handshake.syn_ack_packet} → ACK #{selected.handshake.ack_packet}</p><p>SYN to SYN-ACK: {selected.handshake.syn_to_syn_ack_ms.toFixed(3)} ms<br/>Handshake completion: {selected.handshake.completion_ms.toFixed(3)} ms</p></div> : <p className="live-muted">{selected.protocol === "UDP" ? "UDP has no TCP-style connection handshake." : "A complete matching handshake was not observed. A partial capture can also cause this."}</p>}
          {selected.evidence.map(text => <p key={text}>{text}</p>)}
          <details><summary>13 model input features</summary><dl className="live-evidence">{Object.entries(selected.features).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value.toFixed(5)}</dd></div>)}</dl></details>
        </> : <p>Select a flow to see sequence acknowledgements, flags, directions, and timing derived from the capture.</p>}
      </aside>
    </section>
    {selected && <section className="live-panel live-events packet-headers"><h3>Flow {selected.flow_id}: first {selected.packet_preview.length} packet headers</h3><p className="live-muted">All packets contribute to flow statistics. This preview retains at most 12 headers per flow. Forward means the first observed sender.</p>
      <div className="live-table-scroll"><table><thead><tr><th>Packet</th><th>Direction</th><th>Offset (ms)</th><th>Flags</th><th>Sequence</th><th>Acknowledgement</th><th>IP / payload bytes</th><th>TTL / hop limit</th></tr></thead><tbody>{selected.packet_preview.map(p => <tr key={p.packet_number}><td>#{p.packet_number}</td><td>{p.direction}</td><td>{p.offset_ms.toFixed(3)}</td><td>{p.flags || "n/a"}</td><td>{p.seq ?? "n/a"}</td><td>{p.ack ?? "n/a"}</td><td>{p.ip_bytes} / {p.payload_bytes}</td><td>{p.ttl}</td></tr>)}</tbody></table></div></section>}
    {report && <section className="live-panel packet-provenance"><h3>Capture provenance & model evaluation</h3><dl className="live-evidence"><dt>Capture SHA-256</dt><dd>{summary?.capture_sha256}</dd><dt>Capture interval (UTC)</dt><dd>{summary?.start_utc} to {summary?.end_utc}</dd><dt>Protocol packet counts</dt><dd>{Object.entries(summary?.protocols || {}).map(([key, count]) => `${key}: ${count}`).join(" · ")}</dd><dt>Skipped packet accounting</dt><dd>{JSON.stringify(summary?.skipped_by_reason)} · {summary?.out_of_order_records} out-of-order records sorted by timestamp</dd><dt>Model / extractor identity</dt><dd>{report.model.model_id}</dd></dl>
      <p>Isolation Forest · {report.model.train_flows} training flows · {report.model.validation_flows} validation flows · {report.model.test_flows} test flows from separate synthetic captures.</p>
      <p>Synthetic test precision {(report.model.test_metrics.precision*100).toFixed(1)}% · recall {(report.model.test_metrics.recall*100).toFixed(1)}% · false-positive rate {(report.model.test_metrics.false_positive_rate*100).toFixed(1)}%. These results do not establish performance on operational traffic.</p>
      <details><summary>Analysis limits</summary>{report.limitations.map(text => <p className="live-muted" key={text}>{text}</p>)}</details>
    </section>}
    <footer className="live-panel live-footer"><p>Results are saved in an isolated 24-hour demo session. Free hosting may lose sessions after a restart. Export a report for your submission.</p><div className="live-control-row">
      <button disabled={!report} onClick={() => report && download(JSON.stringify(report, null, 2), "sentinel-packet-report.json", "application/json")}><Download size={15}/>Export report JSON</button>
      <button disabled={!report} onClick={exportCsv}><Download size={15}/>Export flows CSV</button></div></footer>
  </main>;
}
