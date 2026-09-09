import { useEffect, useRef, useState } from "react";
import { Activity, Download, Play, RefreshCw, Server, ShieldCheck } from "lucide-react";
import type { PolicyKey } from "./types";
import { ApiError, ConnectionError, apiRequest } from "./api";
import { clearResult, readResult, saveResult } from "./result-cache";

const API = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");
const SESSION_KEY = `sentinel-live-session-v1:${API || window.location.origin}`;
const CACHE_KEY = "sentinel-live-result-v1";
type Credential = { session_id: string; token: string };
type LiveEvent = {
  event_id: number; timestamp: string; entity_id: string; source_ip: string;
  resource_accessed: string; auth_result: string; risk: number; pred_label: string;
  is_alert: boolean; reason: string; ae_score: number; iso_score: number;
  seq_score: number; attack_prob: number; entity_hist_count: number;
  protocol: string;
  [key: string]: unknown;
};
type Decision = { sequence: number; event_id: number; disposition: string; note: string; saved_at: number };
type Snapshot = { session_id: string; policy: PolicyKey; model_id: string;
  events: LiveEvent[]; feedback: Decision[]; expires_at: number; max_events: number };
type Health = { status: string; model_id: string; thresholds: Record<PolicyKey, number>; storage: string; max_events: number };
type Scenarios = Record<string, { title: string; description: string; events: unknown[] }>;
const title = (value: string) => value.replaceAll("_", " ");

async function request<T>(path: string, credential?: Credential | null, body?: unknown): Promise<T> {
  return apiRequest<T>(API,path,{credential,body:body === undefined ? undefined : JSON.stringify(body)});
}
function isSnapshot(data: unknown): data is Snapshot {
  if (!data || typeof data !== "object") return false;
  const s = data as Snapshot;
  return typeof s.session_id === "string" && typeof s.model_id === "string" && Number.isFinite(s.expires_at)
    && ["top_0.5pct","top_1pct","top_2pct","top_5pct"].includes(s.policy) && Array.isArray(s.events) && s.events.length <= 1000
    && s.events.every(e => e && [e.timestamp,e.entity_id,e.source_ip,e.resource_accessed,e.auth_result,e.pred_label,e.protocol].every(v => typeof v === "string")
      && [e.event_id,e.risk,e.ae_score,e.iso_score,e.seq_score,e.attack_prob,e.entity_hist_count].every(Number.isFinite) && typeof e.is_alert === "boolean"
      && (e.reason == null || typeof e.reason === "string"))
    && Array.isArray(s.feedback) && s.feedback.every(d => d && [d.sequence,d.event_id,d.saved_at].every(Number.isFinite) && typeof d.disposition === "string" && typeof d.note === "string");
}

function savedCredential(): Credential | null {
  try {
    const item = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    return item && typeof item.session_id === "string" && typeof item.token === "string" ? item : null;
  } catch { return null; }
}

export default function LiveConsole() {
  const [initial] = useState(() => readResult(CACHE_KEY,isSnapshot));
  const [health, setHealth] = useState<Health | null>(null);
  const [scenarios, setScenarios] = useState<Scenarios>({});
  const [credential, setCredential] = useState<Credential | null>(savedCredential);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(initial?.data || null);
  const [cached, setCached] = useState(!!initial);
  const [copyTime, setCopyTime] = useState(initial?.saved_at || "");
  const [policy, setPolicy] = useState<PolicyKey>("top_2pct");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [disposition, setDisposition] = useState("needs_investigation");
  const [note, setNote] = useState("");
  const [jsonInput, setJsonInput] = useState("");
  const [exportText, setExportText] = useState("");
  const [onlyAlerts, setOnlyAlerts] = useState(false);
  const [lastLatency, setLastLatency] = useState<number | null>(null);
  const pendingReview = useRef<{ key: string; request_id: string } | null>(null);

  async function refresh(current = credential) {
    if (!current) return false;
    try {
      const state = await request<Snapshot>(`/api/sessions/${current.session_id}`, current);
      setSnapshot(state);
      setCached(false);
      setCopyTime(saveResult(CACHE_KEY,state,"Server inference")?.saved_at || "");
      setPolicy(state.policy);
      return true;
    } catch (error) {
      if (error instanceof ApiError && (error.status === 401 || error.status === 410)) {
        setCredential(null); setCached(true); setLastLatency(null);
        try { localStorage.removeItem(SESSION_KEY); } catch { /* Storage can be unavailable. */ }
        setNotice("The server session expired or restarted. Any displayed browser copy remains read-only and exportable. Create a new session to submit events.");
        return false;
      }
      throw error;
    }
  }
  async function run(label: string, action: () => Promise<void>) {
    setBusy(label); setError(""); setNotice("");
    try { await action(); }
    catch (e) {
      if (e instanceof ConnectionError) { setHealth(null); setCached(true); }
      setError(e instanceof Error ? e.message : String(e));
    }
    finally { setBusy(""); }
  }
  async function connect() {
    setHealth(null);
    if (window.location.protocol === "file:" || !navigator.onLine) {
      setCached(true); setNotice("Live server inference is offline. Inspect saved results, use the bundled Alerts replay, or analyze a PCAP in the browser."); return;
    }
    const [status, examples] = await Promise.all([
      request<Health>("/api/health"), request<Scenarios>("/api/scenarios"),
    ]);
    setHealth(status); setScenarios(examples);
    await refresh();
  }
  useEffect(() => { void run("Connecting to inference API…", connect); }, []);

  async function createSession() {
    const next = await request<Credential>("/api/sessions", null, { policy });
    setCredential(next); setSelectedId(null); setExportText(""); setLastLatency(null);
    setNote(""); setDisposition("needs_investigation");
    try { localStorage.setItem(SESSION_KEY, JSON.stringify(next)); }
    catch { setNotice("Browser storage is unavailable. This session stays connected until the page closes."); }
    await refresh(next);
  }
  async function ingest(events: unknown[]) {
    if (!credential) throw new Error("Create a session first.");
    const result = await request<{ accepted: number; duplicates: number; scoring_ms: number }>(
      `/api/sessions/${credential.session_id}/events`, credential, { events });
    setLastLatency(result.scoring_ms);
    if (!await refresh()) return;
    setNotice(`${result.accepted} new events scored · ${result.duplicates} duplicates skipped · results read back from the server.`);
  }
  const events = snapshot?.events || [];
  const canWrite = !!health && !!credential && !cached && snapshot?.session_id === credential.session_id;
  const alerts = events.filter(e => e.is_alert);
  const visible = [...(onlyAlerts ? alerts : events)].reverse();
  const selected = events.find(e => e.event_id === selectedId) || alerts[alerts.length-1] || events[events.length-1];
  const selectedTime = selected ? Date.parse(selected.timestamp) : 0;
  const ipHour = selected ? events.slice(0, events.indexOf(selected)+1).filter(e =>
    e.source_ip === selected.source_ip && Date.parse(e.timestamp) >= selectedTime-3600000) : [];
  const ipAccounts = new Set(ipHour.map(e => e.entity_id)).size;
  const ipFailureRate = ipHour.length ? ipHour.filter(e => e.auth_result === "FAILURE").length/ipHour.length : 0;
  const ipFiveMinutes = ipHour.filter(e => Date.parse(e.timestamp) >= selectedTime-300000).length;
  const history = snapshot?.feedback.filter(d => d.event_id === selected?.event_id) || [];
  const threshold = health?.thresholds[snapshot?.policy || policy];

  return <main className="live-workspace view-enter">
    <section className="live-intro">
      <div><div className="eyebrow">ML INFERENCE · RELIABLE EVENT PIPELINES</div>
        <h2>From raw events to a reviewed finding</h2>
        <p>Submit synthetic access events, inspect predictions computed by the saved models, and save analyst decisions to the backend.</p>
        <p className="live-owner"><strong>Harthik M V</strong> · Aspiring Machine Learning Engineer / Data Engineer</p></div>
      <span className={`live-connection ${health ? "online" : ""}`}><Server size={16}/>{health ? "Inference API connected" : "Connecting / unavailable"}</span>
    </section>

    <div className="live-flow" aria-label="Investigation flow">
      <span>01 · Ingest</span><span>02 · Build past-only features</span><span>03 · Score + explain</span><span>04 · Review + audit</span>
    </div>
    {error && <div className="live-error" role="alert">{error}</div>}
    {(!health || cached) && <div className="live-notice"><strong>{cached && snapshot ? "Read-only browser copy" : "Offline demonstration available"}</strong>
      <p>{copyTime ? `Last browser save: ${new Date(copyTime).toLocaleString()}. ` : ""}New access-event inference requires the server. Packet analysis works in your browser.</p>
      <div className="live-control-row"><a href="#packets">Analyze packets in browser</a><a href="#alerts">Open bundled Alerts replay</a></div></div>}
    {(busy || notice) && <div className="live-notice" role="status">{busy || notice}</div>}

    <section className="live-panel live-controls">
      <div className="live-control-row">
        <label>Policy for a new session<select aria-label="Live session policy" value={policy} disabled={!!busy} onChange={e => setPolicy(e.target.value as PolicyKey)}>
          <option value="top_0.5pct">Top 0.5% · maximum precision</option><option value="top_1pct">Top 1% · precision first</option>
          <option value="top_2pct">Top 2% · balanced coverage</option><option value="top_5pct">Top 5% · maximum coverage</option>
        </select></label>
        <button className="live-primary" disabled={!!busy || !health} onClick={() => void run("Creating an isolated session…", createSession)}><Play size={15}/>{snapshot ? "New session" : "1. Create session"}</button>
        <button disabled={!!busy} onClick={() => void run("Checking service and saved state…", connect)}><RefreshCw size={15}/>Refresh server state</button>
        <a href={`${API}/docs`} target="_blank" rel="noreferrer">API documentation ↗</a>
        <a href="https://github.com/Harthik777/CN-Project/blob/codex/full-stack/docs/NETWORK_LAB.md" target="_blank" rel="noreferrer">Computer networks lab ↗</a>
      </div>
      <div className="live-scenarios">
        <div><strong>2. Establish a baseline</strong><p>{scenarios.baseline?.description || "120 synthetic normal accesses."}</p>
          <button disabled={!!busy || !canWrite || !scenarios.baseline} onClick={() => void run("Scoring baseline events…", () => ingest(scenarios.baseline.events))}>Score baseline</button></div>
        <div><strong>3. Replay a suspicious campaign</strong><p>{scenarios.attack?.description || "Failed logins across accounts from a shared source."}</p>
          <button disabled={!!busy || !canWrite || !scenarios.attack || events.length === 0} onClick={() => void run("Scoring attack campaign…", () => ingest(scenarios.attack.events))}>Score attack campaign</button></div>
        <div><strong>4. Investigate and review</strong><p>Select an event below, compare its evidence, then save a disposition. Refresh to verify the server retained it.</p><span className="live-muted">Decisions do not retrain the model.</span></div>
      </div>
    </section>

    <div className="live-metrics">
      <div><span>INGESTED EVENTS</span><strong>{events.length}</strong><small>Up to {health?.max_events || 1000} per session</small></div>
      <div><span>FLAGGED EVENTS</span><strong>{alerts.length}</strong><small>Actual outputs for this session</small></div>
      <div><span>SERVER SCORING TIME</span><strong>{lastLatency === null ? "—" : `${Math.round(lastLatency)} ms`}</strong><small>Includes replay of stored history</small></div>
      <div><span>AUDIT RECORDS</span><strong>{snapshot?.feedback.length || 0}</strong><small>{threshold === undefined ? "Fixed validation threshold" : `Threshold ${threshold < .1 ? threshold.toFixed(5) : threshold.toFixed(2)}`}</small></div>
    </div>

    <section className="live-investigation">
      <div className="live-panel live-events"><div className="live-section-heading"><h3>Scored event stream</h3>
        <label><input type="checkbox" checked={onlyAlerts} onChange={e => setOnlyAlerts(e.target.checked)}/> Alerts only</label></div>
        <div className="live-table-scroll"><table><thead><tr><th>Event / time (UTC)</th><th>Principal</th><th>Risk</th><th>Model classification</th><th>State</th></tr></thead>
          <tbody>{visible.map(event => <tr key={event.event_id} className={selected?.event_id === event.event_id ? "selected" : ""}>
            <td><button aria-label={`Inspect event ${event.event_id}`} onClick={() => { setSelectedId(event.event_id); setNote(""); setDisposition("needs_investigation"); }}>{event.event_id}<small>{event.timestamp.slice(11,19)}</small></button></td>
            <td>{event.entity_id}<small>{event.source_ip}</small></td><td className={event.is_alert ? "live-risk" : ""}>{event.risk.toFixed(3)}</td>
            <td>{title(event.pred_label)}</td><td>{event.is_alert ? "Flagged" : "Below threshold"}</td>
          </tr>)}</tbody></table>
          {!visible.length && <div className="live-empty"><Activity size={28}/><p>{events.length ? "No events match this filter." : "Create a session and submit a baseline to see actual inference results."}</p></div>}
        </div>
      </div>
      <aside className="live-panel live-detail"><h3>{selected ? `Event ${selected.event_id} · investigation` : "Investigation evidence"}</h3>
        {selected ? <>
          <div className="live-event-risk"><strong>{selected.risk.toFixed(3)}</strong><span>{title(selected.pred_label)}<small>{selected.is_alert ? "Above policy threshold" : "Below policy threshold"}</small></span></div>
          <p>{selected.reason || "This event is below the alert threshold; no alert explanation was generated."}</p>
          <h4>Network access evidence</h4>
          <dl className="live-evidence"><dt>Source IP / reported protocol</dt><dd>{selected.source_ip} · {selected.protocol}</dd>
            <dt>Accounts using this IP · last hour</dt><dd>{ipAccounts}</dd>
            <dt>Failed accesses from this IP · last hour</dt><dd>{(ipFailureRate*100).toFixed(1)}%</dd>
            <dt>Accesses from this IP · last five minutes</dt><dd>{ipFiveMinutes}</dd>
            <dt>Observed action</dt><dd>{selected.auth_result} · {selected.resource_accessed}</dd>
            <dt>Past entity events</dt><dd>{selected.entity_hist_count}</dd><dt>Classifier attack probability</dt><dd>{(selected.attack_prob*100).toFixed(3)}%</dd>
            <dt>Anomaly channel ranks</dt><dd>AE {selected.ae_score.toFixed(3)} · IF {selected.iso_score.toFixed(3)} · GRU {selected.seq_score.toFixed(3)}</dd></dl>
          <p className="live-muted">IP windows are calculated from this session's submitted logs through the selected event. Protocol and IP are supplied fields; this demo uses synthetic access logs.</p>
          <form onSubmit={e => { e.preventDefault(); void run("Saving decision to the server…", async () => {
            if (!credential || !canWrite) return;
            const reviewKey = JSON.stringify([credential.session_id, selected.event_id, disposition, note]);
            if (pendingReview.current?.key !== reviewKey) pendingReview.current = {key: reviewKey, request_id: crypto.randomUUID()};
            await request(`/api/sessions/${credential.session_id}/feedback`, credential,
              {request_id: pendingReview.current.request_id, event_id: selected.event_id, disposition, note});
            if (!await refresh()) return;
            pendingReview.current = null; setNotice("Decision saved and read back from the server. Previous decisions remain in the audit history.");
          }); }}>
            <label>Analyst disposition<select aria-label="Live analyst disposition" value={disposition} onChange={e => setDisposition(e.target.value)}>
              <option value="needs_investigation">Needs investigation</option><option value="confirmed_attack">Confirmed attack</option><option value="benign">Benign</option></select></label>
            <label>Investigation note<textarea aria-label="Live investigation note" value={note} onChange={e => setNote(e.target.value)} maxLength={2000} placeholder="What evidence supports your decision?"/></label>
            <button className="live-primary" disabled={!!busy || !canWrite}><ShieldCheck size={15}/>Save to server</button>
          </form>
          <h4>Decision history ({history.length})</h4>
          {history.length ? history.map(d => <div className="live-history" key={d.sequence}><strong>{title(d.disposition)}</strong><small>{new Date(d.saved_at*1000).toLocaleString()}</small><p>{d.note || "No note"}</p></div>) : <p className="live-muted">No saved decisions for this event.</p>}
          <details><summary>Raw event and computed evidence</summary><pre>{JSON.stringify(selected, null, 2)}</pre></details>
        </> : <p className="live-muted">Select a scored event to inspect its raw fields, channel scores and analyst history.</p>}
      </aside>
    </section>

    <section className="live-panel live-input"><details><summary>Submit your own synthetic event JSON</summary>
      <p>Supply an array of up to 250 events. UTC offsets, unique event IDs and chronological order are required. Labels and precomputed scores are rejected. Use synthetic data in this public demo.</p>
      <button disabled={!scenarios.baseline || !!busy} onClick={() => setJsonInput(JSON.stringify(scenarios.baseline.events.slice(0,3), null,2))}>Load example JSON</button>
      <textarea aria-label="Raw event JSON" value={jsonInput} onChange={e => setJsonInput(e.target.value)} spellCheck={false}/>
      <button disabled={!!busy || !canWrite || !jsonInput} onClick={() => void run("Validating and scoring submitted events…", async () => {
        const value: unknown = JSON.parse(jsonInput); if (!Array.isArray(value)) throw new Error("Provide a JSON array of events."); await ingest(value);
      })}>Validate and score JSON</button>
    </details></section>

    <footer className="live-panel live-footer"><div><strong>Session evidence</strong>
      <p>{health?.storage || "The server is unavailable."} The latest browser copy is kept for up to 7 days when storage is available. Export important evidence.</p>
      <p className="live-muted">{snapshot ? `Session ${snapshot.session_id.slice(0,8)} · expires ${new Date(snapshot.expires_at*1000).toLocaleString()} · ` : ""}Model {(snapshot?.model_id || health?.model_id)?.slice(0,12) || "unavailable"}. Synthetic benchmark metrics are shown separately in Model audit.</p></div>
      <button disabled={!snapshot} onClick={() => {
        const text = JSON.stringify(snapshot, null, 2); setExportText(text);
        const url = URL.createObjectURL(new Blob([text], {type:"application/json"}));
        const anchor = document.createElement("a"); anchor.href=url; anchor.download="sentinel-live-evidence.json"; anchor.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
      }}><Download size={15}/>Export evidence</button>
      <button disabled={!!busy} onClick={() => { clearResult(CACHE_KEY); clearResult(SESSION_KEY); setSnapshot(null); setCredential(null); setCopyTime(""); setExportText(""); setCached(false); setNotice("Browser evidence and session connection cleared."); }}>Clear browser evidence</button>
      {exportText && <details open><summary>Copyable evidence export</summary><textarea aria-label="Live evidence export" readOnly value={exportText}/></details>}
    </footer>
  </main>;
}
