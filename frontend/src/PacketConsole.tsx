import { useState } from "react";
import { Download, Network, Play, RefreshCw, Upload } from "lucide-react";
import { ApiError, ConnectionError, apiRequest } from "./api";
import type { Credential } from "./api";
import { analyzeCapture, isReport } from "./packet-engine";
import type { BrowserModel, Flow, Report } from "./packet-engine";
import { clearResult, readResult, saveResult } from "./result-cache";
import browserModel from "./data/browser-model.json";
import sampleCapture from "./data/sample-capture.json";

const API = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");
const KEY = `sentinel-packet-session-v1:${API || window.location.origin}`;
const DOC = "https://github.com/Harthik777/CN-Project/blob/codex/full-stack/docs/PACKET_LAB.md";
const CACHE_KEY = "sentinel-packet-report-v1";
const MODEL = browserModel as BrowserModel;
const SAMPLE_URL = `data:application/vnd.tcpdump.pcap;base64,${sampleCapture.base64}`;

function saved(): Credential | null {
  try { const item = JSON.parse(localStorage.getItem(KEY) || "null"); return item?.session_id && item?.token ? item : null; }
  catch { return null; }
}

async function request<T>(path: string, credential?: Credential | null, body?: BodyInit, contentType = "application/json"): Promise<T> {
  return apiRequest<T>(API,path,{credential,body,contentType,timeoutMs:12000,attempts:1});
}

function download(content: string, name: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = name; anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function PacketConsole() {
  const [initial] = useState(() => readResult(CACHE_KEY,isReport));
  const [credential, setCredential] = useState<Credential | null>(saved);
  const [report, setReport] = useState<Report | null>(initial?.data || null);
  const [origin, setOrigin] = useState(initial ? `Browser copy · ${initial.source} · saved ${new Date(initial.saved_at).toLocaleString()}` : "Ready for browser or server analysis");
  const [mode, setMode] = useState<"auto" | "browser">("auto");
  const [stored, setStored] = useState(!!initial);
  const [file, setFile] = useState<File | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [onlyAlerts, setOnlyAlerts] = useState(false);
  async function run(label: string, action: () => Promise<unknown>) {
    setBusy(label); setError(""); setNotice("");
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(""); }
  }
  function remember(next: Report, source: string) {
    setReport(next); setOrigin(`${source} · ${new Date().toLocaleString()}`);
    setStored(!!saveResult(CACHE_KEY,next,source));
  }
  async function refresh(current = credential) {
    if (!current) return;
    try { remember(await request<Report>(`/api/sessions/${current.session_id}/capture`, current),"Server inference"); return true; }
    catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 410)) {
        setCredential(null);
        try { localStorage.removeItem(KEY); } catch { /* Optional browser persistence. */ }
        setNotice("The server session expired or restarted. Your displayed browser copy is still available for inspection and export.");
      } else if (e instanceof ApiError && e.status === 404) { setNotice("The server has no saved capture for this session. Your displayed browser result is unchanged."); }
      else throw e;
    }
  }
  async function analyze(sample: boolean) {
    if (!sample && (!file || !file.size || file.size > 512*1024)) throw new Error("Select a classic PCAP capture up to 512 KiB.");
    const bytes = sample ? Uint8Array.from(atob(sampleCapture.base64),c => c.charCodeAt(0)) : new Uint8Array(await file!.arrayBuffer());
    // A real local result is available before any network request. Invalid captures never replace the previous report.
    const local = await analyzeCapture(bytes,MODEL);
    setSelectedId(null); setCredential(null); clearResult(KEY); remember(local,"Browser inference");
    if (mode === "browser" || window.location.protocol === "file:" || !navigator.onLine) {
      setNotice("Analysis completed on this device using the trained forest. No capture was uploaded."); return;
    }
    setBusy("Browser results ready. Checking the server for an optional SQL save…");
    let uploadAttempted = false;
    try {
      const health = await apiRequest<{flow_model_id:string}>(API,"/api/health",{timeoutMs:4000,attempts:1});
      if (health.flow_model_id !== MODEL.model.model_id) {
        setNotice("Browser analysis completed. The server has a different model version, so this report was not uploaded. Reload to check for an update."); return;
      }
      const next = await request<Credential>("/api/sessions",null,"{}");
      setCredential(next);
      try { localStorage.setItem(KEY,JSON.stringify(next)); } catch { /* Export remains available. */ }
      uploadAttempted = true;
      await request(`/api/sessions/${next.session_id}/capture`,next,new Blob([bytes]),"application/vnd.tcpdump.pcap");
      if (!await refresh(next)) return;
      setNotice("Analysis saved to SQL and read back from the server. A browser copy is available for later inspection.");
    } catch (e) {
      if (!(e instanceof ConnectionError)) throw e;
      setNotice(uploadAttempted
        ? "Browser analysis completed successfully. A server save is unconfirmed; use Refresh saved report to check it when available."
        : "The server is unavailable. Browser analysis completed successfully with the trained model. No capture was uploaded.");
    }
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
    <div className="live-notice" role="status"><strong>{origin}</strong><p>Packet parsing and model scoring can run on this device. The server is optional for packet analysis.</p></div>
    {error && <div className="live-error" role="alert">{error}</div>}
    {(busy || notice) && <div className="live-notice" role="status">{busy || notice}</div>}
    <section className="live-panel">
      <div className="live-control-row">
        <label>Analysis mode<select aria-label="Packet analysis mode" disabled={!!busy} value={mode} onChange={e => setMode(e.target.value as "auto" | "browser")}>
          <option value="auto">Automatic: browser + optional server save</option><option value="browser">Browser only: no upload</option></select></label>
        <button className="live-primary" disabled={!!busy} onClick={() => void run("Reading and analyzing the sample capture…", () => analyze(true))}><Play size={16}/>Analyze sample capture</button>
        <a href={SAMPLE_URL} download="sentinel-synthetic-sample.pcap">Download sample PCAP</a>
        <button disabled={!!busy || !credential} onClick={() => void run("Reading saved report…", () => refresh())}><RefreshCw size={15}/>Refresh saved report</button>
      </div>
      <div className="packet-upload"><label htmlFor="packet-capture">Analyze your capture<input id="packet-capture" type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" disabled={!!busy} onChange={e => setFile(e.target.files?.[0] || null)}/></label>
        <button disabled={!!busy || !file} onClick={() => void run("Uploading capture and extracting flows…", () => analyze(false))}><Upload size={15}/>Upload and analyze</button></div>
      <p className="live-muted">Classic PCAP · up to 512 KiB / 6,000 packets / 250 flows · Ethernet, raw IP, Linux cooked v1 · IPv4 and IPv6. Convert PCAPNG using Wireshark Save As → pcap.</p>
      <p className="live-muted">Automatic mode analyzes locally first and uploads to the server when reachable. Browser-only mode keeps the file on this device. Results contain headers and statistics, never payloads. The bundled sample is generated traffic.</p>
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
    <footer className="live-panel live-footer"><p>{stored ? "The latest report is stored in this browser for up to 7 days." : "No durable browser copy is available yet. Export important results."} Server sessions last up to 24 hours and may be lost after a restart. Browser copies are not server backups.</p><div className="live-control-row">
      <button disabled={!report} onClick={() => report && download(JSON.stringify({...report, execution: {description:origin}}, null, 2), "sentinel-packet-report.json", "application/json")}><Download size={15}/>Export report JSON</button>
      <button disabled={!report} onClick={exportCsv}><Download size={15}/>Export flows CSV</button>
      <button disabled={!!busy} onClick={() => { clearResult(CACHE_KEY); clearResult(KEY); setReport(null); setCredential(null); setStored(false); setOrigin("Ready for browser or server analysis"); setNotice("Browser report and session connection cleared."); }}>Clear browser report</button></div></footer>
  </main>;
}
