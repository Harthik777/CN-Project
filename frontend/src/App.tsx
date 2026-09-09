import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  BarChart3,
  BellRing,
  CalendarDays,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  Copy,
  Database,
  Download,
  Eye,
  EyeOff,
  Fingerprint,
  Gauge,
  Globe2,
  Info,
  Layers3,
  LockKeyhole,
  MapPin,
  Radio,
  RotateCw,
  Rows3,
  Search,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Target,
  UserRoundCheck,
  Waypoints,
  X,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  FormEvent,
  ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import dashboardData from "./data/dashboard-data.json";
import TopologyView from "./TopologyView";
import LiveConsole from "./LiveConsole";
import PacketConsole from "./PacketConsole";
import type {
  AlertRecord,
  DashboardData,
  Disposition,
  PolicyKey,
  Severity,
  ViewName,
} from "./types";

const DATA = dashboardData as unknown as DashboardData;
const MAX_VISIBLE_ALERTS = 500;
const FEEDBACK_PREFIX = `sentinel-feedback-${DATA.snapshot_sha256}-`;

const policyLabels: Record<PolicyKey, string> = {
  "top_0.5pct": "Top 0.5% | maximum precision",
  top_1pct: "Top 1% | precision first",
  top_2pct: "Top 2% | balanced coverage",
  top_5pct: "Top 5% | maximum coverage",
};

const attackColors: Record<string, string> = {
  brute_force: "#D92D20",
  credential_stuffing: "#F79009",
  device_spoofing: "#FBBF24",
  impossible_travel: "#3B82F6",
  lateral_movement: "#7C6FAD",
  low_and_slow_exfiltration: "#22C55E",
};

const percent = (value: number, digits = 1) =>
  `${(Number(value) * 100).toFixed(digits)}%`;

const titleCase = (value: string) =>
  value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());

const compactTimestamp = (value: string) =>
  value.slice(5, 16).replace("T", " ");

const fullTimestamp = (value: string) =>
  value.slice(0, 19).replace("T", " ");

const cleanReason = (value: string) =>
  value.replace(/^\[[^\]]+\]\s*/i, "").replaceAll("_", " ")
    .replace(/would be benign (if|in)/g, "rule guidance only; benign status unverified:");

const riskText = (value: number) =>
  Number(value) < 0.1 ? Number(value).toFixed(3) : Number(value).toFixed(1);

const riskColor = (severity: Severity) =>
  severity === "critical"
    ? "#D92D20"
    : severity === "high"
      ? "#F79009"
      : "#3B82F6";

function severityFor(alert: AlertRecord): Severity {
  const topOneThreshold = DATA.operating_points.top_1pct.threshold;
  if (alert.risk >= 99.8) return "critical";
  if (alert.risk >= topOneThreshold) return "high";
  return "review";
}

function storageKeys(): string[] {
  try {
    return Object.keys(localStorage).filter((key) =>
      key.startsWith(FEEDBACK_PREFIX),
    );
  } catch {
    return [];
  }
}

function readDisposition(eventId: number): Disposition | null {
  try {
    const saved = localStorage.getItem(`${FEEDBACK_PREFIX}${eventId}`);
    return saved ? (JSON.parse(saved) as Disposition) : null;
  } catch {
    return null;
  }
}

function writeDisposition(value: Disposition) {
  localStorage.setItem(
    `${FEEDBACK_PREFIX}${value.event_id}`,
    JSON.stringify(value),
  );
}

function exportFeedback() {
  const decisions = storageKeys().flatMap((key) => {
    const item = readDisposition(Number(key.slice(FEEDBACK_PREFIX.length)));
    return item ? [item] : [];
  });
  const text = JSON.stringify({
    schema_version: 1,
    snapshot_sha256: DATA.snapshot_sha256,
    decisions,
  }, null, 2);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "sentinel-feedback.json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return text;
}

function ProductMark() {
  return (
    <div className="product-mark" aria-label="SentinelUEBA">
      <span className="mark-core">S</span>
      <span className="mark-signal" />
    </div>
  );
}

function RailButton({
  label,
  active,
  onClick,
  children,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      className={`rail-button ${active ? "active" : ""}`}
      aria-label={label}
      aria-pressed={active}
      data-tooltip={label}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function StatusDot({ tone = "green" }: { tone?: "green" | "amber" | "red" }) {
  return <span className={`status-dot ${tone}`} aria-hidden="true" />;
}

function Metric({
  label,
  value,
  note,
  tone,
}: {
  label: string;
  value: string;
  note: string;
  tone: "red" | "green" | "cyan" | "amber";
}) {
  return (
    <div className="posture-metric">
      <div className="metric-label">{label}</div>
      <div className={`metric-value ${tone}`}>{value}</div>
      <div className="metric-note">{note}</div>
    </div>
  );
}

function PostureStrip({
  policy,
  reviewedCount,
}: {
  policy: PolicyKey;
  reviewedCount: number;
}) {
  const point = DATA.operating_points[policy];

  return (
    <section className="posture-strip" aria-label="Detection posture">
      <div className="posture-lead">
        <div className="posture-symbol">
          <ShieldCheck size={24} strokeWidth={1.8} />
        </div>
        <div>
          <div className="metric-label">Detection posture</div>
          <div className="posture-title">{policyLabels[policy].split(" | ")[1]}</div>
          <div className="posture-note">
            Validation-fitted threshold <strong>{riskText(point.threshold)}</strong>
          </div>
        </div>
      </div>
      <Metric
        label="Alert volume"
        value={point.n_flagged.toLocaleString()}
        note={policyLabels[policy]}
        tone="red"
      />
      <Metric
        label="Precision"
        value={percent(point.precision)}
        note={`${point.false_positives ?? 0} false positives`}
        tone="green"
      />
      <Metric
        label="Attack recall"
        value={percent(point.recall)}
        note="Synthetic test · selected policy"
        tone="cyan"
      />
      <Metric
        label="Review progress"
        value={reviewedCount.toLocaleString()}
        note={`${DATA.drift.test_drift_alarms} drift alarms`}
        tone="amber"
      />
    </section>
  );
}

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
}) {
  return (
    <label className="toggle-control">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="toggle-track">
        <span className="toggle-thumb" />
      </span>
      <span className="toggle-label">{label}</span>
      {checked ? <Eye size={14} /> : <EyeOff size={14} />}
    </label>
  );
}

function RiskCell({ alert }: { alert: AlertRecord }) {
  const severity = severityFor(alert);
  return (
    <div className="risk-cell">
      <span className={`risk-number-small ${severity}`}>
        {riskText(alert.risk)}
      </span>
      <span className="risk-mini-track">
        <span
          className={`risk-mini-fill ${severity}`}
          style={{ width: `${Math.min(100, alert.risk)}%` }}
        />
      </span>
    </div>
  );
}

function AlertQueue({
  policy,
  setPolicy,
  selectedId,
  onSelect,
  feedbackVersion,
  globalSearch,
}: {
  policy: PolicyKey;
  setPolicy: (policy: PolicyKey) => void;
  selectedId: number | null;
  onSelect: (id: number) => void;
  feedbackVersion: number;
  globalSearch: string;
}) {
  const [search, setSearch] = useState("");
  const [riskFloor, setRiskFloor] = useState(0);
  const [bucket, setBucket] = useState<"all" | Severity>("all");
  const [showTruth, setShowTruth] = useState(false);
  const [compact, setCompact] = useState(false);
  const [sort, setSort] = useState<{
    key: "timestamp" | "risk" | "entity" | "classification";
    direction: "asc" | "desc";
  }>({ key: "risk", direction: "desc" });
  const searchRef = useRef<HTMLInputElement>(null);
  const threshold = DATA.operating_points[policy].threshold;

  useEffect(() => {
    setSearch(globalSearch);
  }, [globalSearch]);

  const searchedAlerts = useMemo(() => {
    const query = search.toLowerCase().trim();
    return DATA.alerts.filter((alert) => {
      const haystack =
        `${alert.entity} ${alert.classification} ${alert.source_ip} ` +
        `${alert.resource} ${alert.city} ${alert.role}`;
      return (
        alert.risk >= threshold &&
        alert.risk >= riskFloor &&
        haystack.toLowerCase().includes(query)
      );
    });
  }, [riskFloor, search, threshold]);

  const severityCounts = useMemo(
    () =>
      searchedAlerts.reduce(
        (counts, alert) => {
          counts[severityFor(alert)] += 1;
          return counts;
        },
        { critical: 0, high: 0, review: 0 },
      ),
    [searchedAlerts],
  );

  const filteredAlerts = useMemo(
    () =>
      searchedAlerts.filter(
        (alert) => bucket === "all" || severityFor(alert) === bucket,
      ),
    [bucket, searchedAlerts],
  );

  const sortedAlerts = useMemo(() => {
    const direction = sort.direction === "asc" ? 1 : -1;
    return [...filteredAlerts].sort((left, right) => {
      const leftValue = left[sort.key];
      const rightValue = right[sort.key];
      if (typeof leftValue === "number" && typeof rightValue === "number") {
        return (leftValue - rightValue) * direction;
      }
      return String(leftValue).localeCompare(String(rightValue)) * direction;
    });
  }, [filteredAlerts, sort]);

  const visibleAlerts = sortedAlerts.slice(0, MAX_VISIBLE_ALERTS);
  const hasActiveFilters = Boolean(search || riskFloor || bucket !== "all");

  const toggleSort = (
    key: "timestamp" | "risk" | "entity" | "classification",
  ) => {
    setSort((current) => ({
      key,
      direction:
        current.key === key && current.direction === "desc" ? "asc" : "desc",
    }));
  };

  const sortIcon = (
    key: "timestamp" | "risk" | "entity" | "classification",
  ) =>
    sort.key !== key ? (
      <ArrowUpDown size={13} />
    ) : sort.direction === "asc" ? (
      <ArrowUp size={13} />
    ) : (
      <ArrowDown size={13} />
    );


  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (
        event.key === "/" &&
        document.activeElement?.tagName !== "INPUT" &&
        document.activeElement?.tagName !== "SELECT"
      ) {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if (event.key === "Escape" && search) {
        setSearch("");
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [search]);

  useEffect(() => {
    if (
      visibleAlerts.length > 0 &&
      !visibleAlerts.some((alert) => alert.id === selectedId)
    ) {
      onSelect(visibleAlerts[0].id);
    }
  }, [onSelect, selectedId, visibleAlerts]);

  return (
    <section className="queue-panel">
      <div className="queue-heading">
        <div>
          <div className="section-kicker">Operational triage</div>
          <div className="title-row">
            <h2>Priority queue</h2>
            <span className="queue-volume">
              {filteredAlerts.length.toLocaleString()} alerts
            </span>
          </div>
        </div>
        <div className="queue-health">
          <StatusDot />
          <span>Saved scores</span>
          <span className="queue-divider" />
          <span>
            showing {Math.min(visibleAlerts.length, MAX_VISIBLE_ALERTS)}
          </span>
        </div>
      </div>

      <div className="analyst-toolbar">
        <label className="search-control">
          <Search size={17} aria-hidden="true" />
          <input
            ref={searchRef}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search principal, pattern, IP, or resource"
            aria-label="Search alerts"
          />
          <kbd>/</kbd>
        </label>

        <label className="select-control">
          <SlidersHorizontal size={15} aria-hidden="true" />
          <span>Policy</span>
          <select
            value={policy}
            onChange={(event) => {
              setPolicy(event.target.value as PolicyKey);
              setRiskFloor(0);
            }}
            aria-label="Alert policy"
          >
            {Object.entries(policyLabels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>

        <label className="risk-control">
          <Gauge size={15} aria-hidden="true" />
          <span>Risk</span>
          <input
            type="range"
            value={riskFloor}
            min={0}
            max={100}
            step={1}
            onChange={(event) => setRiskFloor(Number(event.target.value))}
            aria-label="Minimum risk"
          />
          <output>{riskFloor}</output>
        </label>

        <Toggle checked={showTruth} onChange={setShowTruth} label="Labels" />
      </div>

      <div className="queue-subbar">
        <div className="severity-segments" aria-label="Severity filter">
          <button
            type="button"
            className={bucket === "all" ? "active" : ""}
            onClick={() => setBucket("all")}
          >
            All <span>{searchedAlerts.length}</span>
          </button>
          <button
            type="button"
            className={bucket === "critical" ? "active critical" : ""}
            onClick={() => setBucket("critical")}
          >
            Critical <span>{severityCounts.critical}</span>
          </button>
          <button
            type="button"
            className={bucket === "high" ? "active high" : ""}
            onClick={() => setBucket("high")}
          >
            High <span>{severityCounts.high}</span>
          </button>
          <button
            type="button"
            className={bucket === "review" ? "active review" : ""}
            onClick={() => setBucket("review")}
          >
            Review <span>{severityCounts.review}</span>
          </button>
        </div>
        <div className="queue-tools">
          {hasActiveFilters && (
            <button
              type="button"
              className="clear-filter-button"
              onClick={() => {
                setSearch("");
                setRiskFloor(0);
                setBucket("all");
              }}
            >
              <X size={14} />
              Clear filters
            </button>
          )}
          <button
            type="button"
            className={`density-button ${compact ? "active" : ""}`}
            onClick={() => setCompact((value) => !value)}
            aria-pressed={compact}
            aria-label={compact ? "Use comfortable rows" : "Use compact rows"}
            title={compact ? "Comfortable rows" : "Compact rows"}
          >
            <Rows3 size={15} />
          </button>
          <div className="threshold-note">
            <Target size={14} />
            Threshold {riskText(threshold)}
          </div>
        </div>
      </div>

      <div className="alert-table-wrap">
        <table className={`alert-table ${compact ? "compact" : ""}`}>
          <thead>
            <tr>
              <th className="observed-column">
                <button type="button" onClick={() => toggleSort("timestamp")}>
                  Observed {sortIcon("timestamp")}
                </button>
              </th>
              <th className="risk-column">
                <button type="button" onClick={() => toggleSort("risk")}>
                  Risk {sortIcon("risk")}
                </button>
              </th>
              <th className="principal-column">
                <button type="button" onClick={() => toggleSort("entity")}>
                  Principal {sortIcon("entity")}
                </button>
              </th>
              <th className="behaviour-column">
                <button
                  type="button"
                  onClick={() => toggleSort("classification")}
                >
                  Behaviour {sortIcon("classification")}
                </button>
              </th>
              <th>Evidence summary</th>
              {showTruth && <th className="truth-column">Ground truth</th>}
              <th className="arrow-column" aria-label="Open" />
            </tr>
          </thead>
          <tbody>
            {visibleAlerts.map((alert, index) => {
              const severity = severityFor(alert);
              const reviewed = readDisposition(alert.id);
              return (
                <tr
                  key={alert.id}
                  className={selectedId === alert.id ? "selected" : ""}
                  onClick={() => onSelect(alert.id)}
                  tabIndex={0}
                  data-row-index={index}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onSelect(alert.id);
                    }
                    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                      event.preventDefault();
                      const nextIndex =
                        event.key === "ArrowDown"
                          ? Math.min(visibleAlerts.length - 1, index + 1)
                          : Math.max(0, index - 1);
                      onSelect(visibleAlerts[nextIndex].id);
                      event.currentTarget
                        .closest("tbody")
                        ?.querySelector<HTMLTableRowElement>(
                          `tr[data-row-index="${nextIndex}"]`,
                        )
                        ?.focus();
                    }
                  }}
                >
                  <td>
                    <div className="observed-cell">
                      <span className={`severity-line ${severity}`} />
                      <div>
                        <span className="table-primary mono">
                          {compactTimestamp(alert.timestamp)}
                        </span>
                        <span className="table-secondary">
                          {reviewed ? (
                            <>
                              <Check size={11} /> reviewed
                            </>
                          ) : (
                            `event ${alert.id}`
                          )}
                        </span>
                      </div>
                    </div>
                  </td>
                  <td>
                    <RiskCell alert={alert} />
                  </td>
                  <td>
                    <span className="table-primary">{alert.entity}</span>
                    <span className="table-secondary">{alert.role}</span>
                  </td>
                  <td>
                    <span
                      className="attack-chip"
                      style={
                        {
                          "--attack-color":
                            attackColors[alert.classification] ?? "#3B82F6",
                        } as React.CSSProperties
                      }
                      title={titleCase(alert.classification)}
                    >
                      {titleCase(alert.classification)}
                    </span>
                  </td>
                  <td>
                    <span
                      className="evidence-summary"
                      title={cleanReason(alert.reason)}
                    >
                      {cleanReason(alert.reason)}
                    </span>
                  </td>
                  {showTruth && (
                    <td>
                      <span className="truth-chip">{titleCase(alert.truth)}</span>
                    </td>
                  )}
                  <td>
                    <ChevronRight
                      size={16}
                      className="row-chevron"
                      aria-hidden="true"
                    />
                  </td>
                </tr>
              );
            })}
            {visibleAlerts.length === 0 && (
              <tr>
                <td colSpan={showTruth ? 7 : 6} className="empty-state">
                  <Search size={22} />
                  <strong>No alerts match this view</strong>
                  <span>Adjust the search, policy, severity, or risk floor.</span>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <footer className="queue-footer">
        <span>
          Fixed validation threshold applied to the chronological test window
        </span>
        <span>{feedbackVersion >= 0 ? `${storageKeys().length} reviewed` : ""}</span>
      </footer>
    </section>
  );
}

function ContextItem({
  icon,
  label,
  value,
  mono = false,
  copyable = false,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  mono?: boolean;
  copyable?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const copyValue = async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const field = document.createElement("textarea");
      field.value = value;
      field.style.position = "fixed";
      field.style.opacity = "0";
      document.body.appendChild(field);
      field.select();
      document.execCommand("copy");
      field.remove();
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="context-item">
      <div className="context-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong className={mono ? "mono" : ""}>{value}</strong>
      </div>
      {copyable && (
        <button
          type="button"
          className="copy-context-button"
          onClick={copyValue}
          aria-label={`Copy ${label.toLowerCase()}`}
          title={`Copy ${label.toLowerCase()}`}
        >
          {copied ? <Check size={14} /> : <Copy size={14} />}
        </button>
      )}
    </div>
  );
}

function factorTokens(reason: string) {
  const evidence = cleanReason(reason).split("|")[0];
  const match = evidence.match(/(?:driven by|pattern:)\s*(.*)/i);
  const value = match?.[1] ?? evidence;
  return value
    .split(/[|,]/)
    .map((token) => token.trim())
    .filter(Boolean)
    .slice(0, 5);
}

function RiskTimeline({
  alert,
  threshold,
}: {
  alert: AlertRecord;
  threshold: number;
}) {
  const points = (DATA.timeline[alert.entity] ?? []).slice(-72).map((point) => ({
    ...point,
    time: compactTimestamp(point.timestamp),
  }));

  if (!points.length) {
    return <div className="mini-empty">No entity history in this replay.</div>;
  }

  const minimum = Math.max(
    0,
    Math.min(threshold, ...points.map((point) => point.risk)) - 4,
  );

  return (
    <div className="timeline-chart" aria-label="Entity risk history">
      <ResponsiveContainer width="100%" height={140}>
        <AreaChart data={points} margin={{ top: 12, right: 6, left: -24, bottom: 0 }}>
          <CartesianGrid
            stroke="#263244"
            vertical={false}
            strokeDasharray="3 5"
          />
          <XAxis dataKey="time" hide />
          <YAxis
            domain={[minimum, 100]}
            tick={{ fill: "#8B96A8", fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={36}
          />
          <Tooltip
            cursor={{ stroke: "#667085", strokeDasharray: "3 3" }}
            contentStyle={{
              background: "#172033",
              border: "1px solid #263244",
              borderRadius: 8,
              color: "#E5E7EB",
              fontSize: 12,
            }}
            formatter={(value) => [`${Number(value).toFixed(1)} risk`, ""]}
            labelStyle={{ color: "#8B96A8", marginBottom: 4 }}
          />
          <ReferenceLine
            y={threshold}
            stroke="#D92D20"
            strokeDasharray="5 4"
            label={{
              value: `policy ${riskText(threshold)}`,
              position: "insideTopRight",
              fill: "#B6BDC8",
              fontSize: 11,
            }}
          />
          <Area
            type="monotone"
            dataKey="risk"
            stroke="#3B82F6"
            strokeWidth={1.5}
            fill="#3B82F61A"
            activeDot={{ r: 4, fill: "#E5E7EB", stroke: "#3B82F6" }}
            animationDuration={260}
          />
        </AreaChart>
      </ResponsiveContainer>
      <div className="timeline-legend">
        <span>{points[0].timestamp.slice(0, 10)}</span>
        <span>
          <span className="legend-line" /> entity risk
        </span>
        <span>{points[points.length - 1]?.timestamp.slice(0, 10)}</span>
      </div>
      <ol className="event-timeline" aria-label="Recent risk events">
        {points
          .slice(-3)
          .reverse()
          .map((point) => (
            <li
              key={point.timestamp}
              className={
                point.risk >= 99.8
                  ? "critical"
                  : point.risk >= threshold
                    ? "high"
                    : "review"
              }
            >
              <time>{compactTimestamp(point.timestamp)}</time>
              <span>
                Entity risk scored <strong>{riskText(point.risk)}</strong>
              </span>
            </li>
          ))}
      </ol>
    </div>
  );
}

function DispositionForm({
  alert,
  onSaved,
}: {
  alert: AlertRecord;
  onSaved: () => void;
}) {
  const existing = readDisposition(alert.id);
  const [disposition, setDisposition] = useState(
    existing?.disposition ?? `confirmed_${alert.classification}`,
  );
  const [note, setNote] = useState(existing?.note ?? "");
  const [saved, setSaved] = useState(Boolean(existing));
  const [saveError, setSaveError] = useState("");
  const [exportText, setExportText] = useState("");

  useEffect(() => {
    const current = readDisposition(alert.id);
    setDisposition(
      current?.disposition ?? `confirmed_${alert.classification}`,
    );
    setNote(current?.note ?? "");
    setSaved(Boolean(current));
    setSaveError("");
  }, [alert]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setSaveError("");
    try {
      writeDisposition({
      event_id: alert.id,
      disposition,
      note,
      at: new Date().toISOString(),
      });
    } catch {
      setSaveError("Browser storage is unavailable. The decision was not saved.");
      return;
    }
    setSaved(true);
    onSaved();
  };

  return (
    <form className="disposition-form" onSubmit={submit}>
      <div className="form-row">
        <label>
          <span>Disposition</span>
          <select
            value={disposition}
            onChange={(event) => {
              setDisposition(event.target.value);
              setSaved(false);
            }}
          >
            <option value={`confirmed_${alert.classification}`}>
              Confirm {titleCase(alert.classification)}
            </option>
            <option value="false_positive">False positive</option>
            <option value="expected_behavior">Expected behaviour</option>
            <option value="needs_investigation">Needs investigation</option>
          </select>
        </label>
        <label className="note-control">
          <span>Case note</span>
          <input
            value={note}
            onChange={(event) => {
              setNote(event.target.value);
              setSaved(false);
            }}
            placeholder="Add investigation context"
          />
        </label>
      </div>
      <button type="submit" className={`primary-action ${saved ? "saved" : ""}`}>
        {saved ? <CheckCircle2 size={16} /> : <UserRoundCheck size={16} />}
        {saved ? "Disposition saved" : "Save disposition"}
      </button>
      <p>
        Saved in this browser. Export decisions and import them with the Python
        feedback tool before a training refresh. Saving does not retrain the model.
      </p>
      {saveError && <p role="alert">{saveError}</p>}
      <button type="button" className="primary-action" onClick={() => setExportText(exportFeedback())}>
        <Download size={16} /> Export decisions
      </button>
      {exportText && (
        <div>
          <p role="status">Export ready. If the download did not start, save the JSON below as sentinel-feedback.json.</p>
          <textarea
            aria-label="Exported decisions JSON"
            readOnly
            value={exportText}
            rows={8}
            style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
          />
        </div>
      )}
    </form>
  );
}

function IncidentPanel({
  alert,
  policy,
  onClose,
  open,
  onSaved,
}: {
  alert: AlertRecord | null;
  policy: PolicyKey;
  onClose: () => void;
  open: boolean;
  onSaved: () => void;
}) {
  if (!alert) {
    return (
      <aside className="incident-panel empty-inspector">
        <CircleGauge size={28} />
        <strong>Select an alert</strong>
        <span>Investigation evidence will appear here.</span>
      </aside>
    );
  }

  const severity = severityFor(alert);
  const color = riskColor(severity);
  const scoreEntries = Object.entries(alert.scores).sort(
    ([, left], [, right]) => right - left,
  );
  const agreement =
    scoreEntries.reduce((sum, [, value]) => sum + value, 0) /
    scoreEntries.length;
  const threshold = DATA.operating_points[policy].threshold;

  return (
    <aside className={`incident-panel ${open ? "mobile-open" : ""}`}>
      <button
        type="button"
        className="mobile-close"
        onClick={onClose}
        aria-label="Close incident"
      >
        <X size={18} />
      </button>

      <div className="incident-hero">
        <div
          className="risk-dial"
          style={
            {
              "--risk-angle": `${Math.min(360, alert.risk * 3.6)}deg`,
              "--risk-color": color,
            } as React.CSSProperties
          }
        >
          <div className="risk-dial-inner">
            <strong>{alert.risk.toFixed(1)}</strong>
            <span>risk</span>
          </div>
        </div>
        <div className="incident-title">
          <div className={`incident-severity ${severity}`}>
            <StatusDot tone={severity === "critical" ? "red" : "amber"} />
            {severity} priority
          </div>
          <h2>{titleCase(alert.classification)}</h2>
          <p>
            {alert.entity} <span>/</span> {alert.city}
          </p>
          <div className="incident-meta">
            <span>Event {alert.id}</span>
            <span>{fullTimestamp(alert.timestamp)}</span>
          </div>
        </div>
      </div>

      <details className="inspector-section reason-section" open>
        <summary className="section-title">
          <div>
            <div className="section-kicker">Decision evidence</div>
            <h3>Why this surfaced</h3>
          </div>
          <span className="agreement">
            <Layers3 size={13} />
            {percent(agreement)} mean channel score
          </span>
        </summary>
        <blockquote>{cleanReason(alert.reason)}</blockquote>
        <div className="factor-list">
          {factorTokens(alert.reason).map((factor) => (
            <span key={factor}>{factor.replaceAll("_", " ")}</span>
          ))}
        </div>
      </details>

      <details className="inspector-section" open>
        <summary className="section-title">
          <div>
            <div className="section-kicker">Event context</div>
            <h3>Investigation surface</h3>
          </div>
          {alert.drift_alarm && (
            <span className="drift-chip">
              <Activity size={13} /> drift
            </span>
          )}
        </summary>
        <div className="context-grid">
          <ContextItem
            icon={<Fingerprint size={16} />}
            label="Principal"
            value={`${alert.entity} / ${alert.role}`}
            copyable
          />
          <ContextItem
            icon={<Globe2 size={16} />}
            label="Source"
            value={alert.source_ip}
            mono
            copyable
          />
          <ContextItem
            icon={<MapPin size={16} />}
            label="Location"
            value={alert.city}
          />
          <ContextItem
            icon={<LockKeyhole size={16} />}
            label="Resource"
            value={alert.resource}
            mono
            copyable
          />
          <ContextItem
            icon={<Radio size={16} />}
            label="Authentication"
            value={titleCase(alert.auth)}
          />
          <ContextItem
            icon={<Database size={16} />}
            label="Baseline"
            value={`Epoch ${alert.baseline_epoch}`}
          />
        </div>
      </details>

      <details className="inspector-section" open>
        <summary className="section-title compact">
          <div>
            <div className="section-kicker">Behaviour over time</div>
            <h3>Entity risk trace</h3>
          </div>
          <Waypoints size={17} />
        </summary>
        <RiskTimeline alert={alert} threshold={threshold} />
      </details>

      <details className="inspector-section" open>
        <summary className="section-title compact">
          <div>
            <div className="section-kicker">Model ensemble</div>
            <h3>Detection channels</h3>
          </div>
          <span className="score-count">{scoreEntries.length} signals</span>
        </summary>
        <div className="evidence-bars">
          {scoreEntries.map(([name, value], index) => (
            <div className="evidence-row" key={name}>
              <div className="evidence-label">
                <span>{name}</span>
                <strong>{value.toFixed(3)}</strong>
              </div>
              <div className="evidence-track">
                <span
                  className={index === 0 ? "champion" : ""}
                  style={{ width: `${Math.min(100, value * 100)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </details>

      <details className="inspector-section action-section" open>
        <summary className="section-title compact">
          <div>
            <div className="section-kicker">Analyst decision</div>
            <h3>Close the loop</h3>
          </div>
          <UserRoundCheck size={17} />
        </summary>
        <DispositionForm alert={alert} onSaved={onSaved} />
      </details>
    </aside>
  );
}

function AuditMetric({
  label,
  value,
  detail,
  tone = "cyan",
}: {
  label: string;
  value: string;
  detail: string;
  tone?: "cyan" | "green" | "amber";
}) {
  return (
    <div className="audit-metric">
      <span>{label}</span>
      <strong className={tone}>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function ModelAudit() {
  const channels = Object.entries(DATA.channels)
    .map(([name, metric]) => ({
      name: titleCase(name),
      key: name,
      prAuc: metric.pr_auc,
      rocAuc: metric.roc_auc,
    }))
    .sort((left, right) => right.prAuc - left.prAuc);
  const classes = Object.entries(DATA.per_class).map(([name, metric]) => ({
    name,
    ...metric,
  }));
  const probe = DATA.real_data_probe ?? {};
  const probeDataset = String(probe.dataset ?? "SPEDIA");
  const probeProtocol = String(
    probe.evaluation_protocol ?? "Chronological negative-control probe",
  );
  const probeEvents = Number(probe.test_events ?? 0);
  const probePrAuc = Number(probe.pr_auc ?? 0);

  return (
    <main className="audit-view view-enter">
      <header className="audit-heading">
        <div>
          <div className="section-kicker">Model governance</div>
          <h2>Untouched test evaluation</h2>
          <p>
            Chronological holdout with a one-hour purge and validation-fitted
            thresholds.
          </p>
        </div>
        <div className="protocol-badge">
          <ShieldCheck size={16} />
          Test never used for selection
        </div>
      </header>

      <section className="audit-metric-strip">
        <AuditMetric
          label="PR-AUC"
          value={DATA.kpis.pr_auc.toFixed(3)}
          detail="2.02% attack prevalence"
        />
        <AuditMetric
          label="ROC-AUC"
          value={DATA.kpis.roc_auc.toFixed(3)}
          detail="Untouched test ranking"
        />
        <AuditMetric
          label="Precision @ top 1%"
          value={percent(DATA.kpis.precision)}
          detail={`${DATA.operating_points.top_1pct.false_positives ?? 0} false positives`}
          tone="green"
        />
        <AuditMetric
          label="Attack typing"
          value={DATA.kpis.macro_f1.toFixed(3)}
          detail="Macro-F1 across six classes"
          tone="amber"
        />
      </section>

      <div className="audit-grid primary-grid">
        <section className="audit-panel channel-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker">Ranking quality</div>
              <h3>Detection channels</h3>
            </div>
            <span>PR-AUC</span>
          </div>
          <div className="channel-chart">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={channels}
                layout="vertical"
                margin={{ top: 8, right: 18, bottom: 0, left: 12 }}
              >
                <CartesianGrid
                  stroke="#263244"
                  horizontal={false}
                  strokeDasharray="3 5"
                />
                <XAxis
                  type="number"
                  domain={[0, 1]}
                  tick={{ fill: "#8B96A8", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(value) => Number(value).toFixed(1)}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={145}
                  tick={{ fill: "#B6BDC8", fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#172033",
                    border: "1px solid #263244",
                    borderRadius: 8,
                    color: "#E5E7EB",
                    fontSize: 12,
                  }}
                  formatter={(value) => [Number(value).toFixed(4), "PR-AUC"]}
                />
                <Bar
                  dataKey="prAuc"
                  radius={[0, 4, 4, 0]}
                  barSize={13}
                  animationDuration={260}
                >
                  {channels.map((channel) => (
                    <Cell
                      key={channel.key}
                      fill={
                        channel.key === DATA.selected_strategy
                          ? "#D92D20"
                          : "#3B82F6"
                      }
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="champion-callout">
            <div className="champion-icon">
              <Target size={18} />
            </div>
            <div>
              <span>Validation-selected strategy</span>
              <strong>{titleCase(DATA.selected_strategy)}</strong>
            </div>
            <span className="champion-score">
              {DATA.channels[DATA.selected_strategy]?.pr_auc.toFixed(3)}
            </span>
          </div>
        </section>

        <section className="audit-panel operating-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker">Analyst capacity</div>
              <h3>Operating points</h3>
            </div>
            <SlidersHorizontal size={16} />
          </div>
          <div className="operating-table-wrap">
            <table className="operating-table">
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>False positives</th>
                  <th>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {(
                  Object.entries(DATA.operating_points) as [
                    PolicyKey,
                    DashboardData["operating_points"][PolicyKey],
                  ][]
                ).map(([key, point]) => (
                  <tr key={key} className={key === "top_1pct" ? "selected" : ""}>
                    <td>
                      <span className="policy-table-name">
                        {key.replace("top_", "Top ").replace("pct", "%")}
                      </span>
                      {key === "top_1pct" && <span className="default-tag">Default</span>}
                    </td>
                    <td className="mono">{percent(point.precision)}</td>
                    <td className="mono">{percent(point.recall)}</td>
                    <td className="mono">{point.false_positives ?? 0}</td>
                    <td className="mono">{point.n_flagged.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="operating-note">
            <Info size={15} />
            <p>
              Every policy uses a frozen threshold learned from validation. The
              test score distribution does not set the alert budget.
            </p>
          </div>
        </section>
      </div>

      <div className="audit-grid secondary-grid">
        <section className="audit-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker">Anomaly typing</div>
              <h3>Per-class F1</h3>
            </div>
            <BarChart3 size={17} />
          </div>
          <div className="class-bars">
            {classes.map((entry) => (
              <div className="class-row" key={entry.name}>
                <div className="class-label">
                  <span
                    className="class-swatch"
                    style={{
                      background:
                        attackColors[entry.name] ?? "var(--accent-blue)",
                    }}
                  />
                  <span>{titleCase(entry.name)}</span>
                  <small>{entry.support} attacks</small>
                </div>
                <div className="class-track">
                  <span
                    style={{
                      width: `${entry.f1 * 100}%`,
                      background:
                        attackColors[entry.name] ?? "var(--accent-blue)",
                    }}
                  />
                </div>
                <strong>{entry.f1.toFixed(3)}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="audit-panel probe-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker">Evidence boundary</div>
              <h3>External telemetry probe</h3>
            </div>
            <Database size={17} />
          </div>
          <div className="probe-status">
            <div className="probe-score">
              <span>{probePrAuc.toFixed(3)}</span>
              <small>proxy PR-AUC</small>
            </div>
            <div>
              <strong>{probeDataset}</strong>
              <p>{probeProtocol}</p>
            </div>
          </div>
          <dl className="probe-grid">
            <div>
              <dt>Held-out events</dt>
              <dd>{probeEvents.toLocaleString()}</dd>
            </div>
            <div>
              <dt>Label source</dt>
              <dd>Rule-severity proxy</dd>
            </div>
            <div>
              <dt>Role</dt>
              <dd>Negative control</dd>
            </div>
            <div>
              <dt>Conclusion</dt>
              <dd>Attack performance unproven</dd>
            </div>
          </dl>
          <div className="probe-boundary">
            This is a complementarity check, not a real-data performance claim.
          </div>
        </section>
      </div>

      <footer className="audit-footer">
        <div>
          <AlertTriangle size={18} />
          <p>
            Primary labelled metrics use the documented synthetic access-log
            generator and are prototype evidence, not production guarantees.
          </p>
        </div>
        <span>Historical metrics · synthetic benchmark</span>
      </footer>
    </main>
  );
}

export default function App() {
  const [view, setView] = useState<ViewName>(() => {
    const hash = window.location.hash.slice(1);
    return ["alerts", "topology", "evaluation", "live", "packets"].includes(hash) ? hash as ViewName : window.location.protocol === "file:" ? "alerts" : "packets";
  });
  useEffect(() => { window.history.replaceState(null, "", `#${view}`); }, [view]);
  const [policy, setPolicy] = useState<PolicyKey>("top_2pct");
  const [globalSearch, setGlobalSearch] = useState("");
  const [globalSearchDraft, setGlobalSearchDraft] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(
    DATA.alerts[0]?.id ?? null,
  );
  const [detailOpen, setDetailOpen] = useState(false);
  const [feedbackVersion, setFeedbackVersion] = useState(0);

  const selectedAlert =
    DATA.alerts.find((alert) => alert.id === selectedId) ?? null;
  const reviewedCount = storageKeys().length;

  const selectAlert = (id: number) => {
    setSelectedId(id);
    setDetailOpen(true);
  };

  return (
    <div className="app-shell">
      <aside className="navigation-rail">
        <ProductMark />
        <nav aria-label="Primary navigation">
          <RailButton label="Packet analysis" active={view === "packets"} onClick={() => setView("packets")}><Layers3 size={20}/></RailButton>
          <RailButton label="Live inference" active={view === "live"} onClick={() => setView("live")}><Radio size={20}/></RailButton>
          <RailButton
            label="Alert workspace"
            active={view === "alerts"}
            onClick={() => setView("alerts")}
          >
            <ShieldAlert size={20} />
          </RailButton>
          <RailButton
            label="Entity topology"
            active={view === "topology"}
            onClick={() => setView("topology")}
          >
            <Waypoints size={20} />
          </RailButton>
          <RailButton
            label="Model audit"
            active={view === "evaluation"}
            onClick={() => setView("evaluation")}
          >
            <BarChart3 size={20} />
          </RailButton>
        </nav>
        <div className="rail-spacer" />
        <div className="rail-system" title="Offline score snapshot">
          <Activity size={17} />
          <StatusDot />
        </div>
        <div className="rail-version">2.4</div>
      </aside>

      <div className="application-surface">
        <header className="command-bar">
          <div className="product-identity">
            <div>
              <div className="breadcrumb">
                SentinelUEBA <span>/</span> Security Operations
                <span className="environment-badge">{view === "packets" ? "Packet analysis · demo" : view === "live" ? "Live inference · demo" : "Synthetic replay"}</span>
              </div>
              <h1>
                {view === "packets" ? "Network packet lab" : view === "live" ? "Live investigation" : view === "alerts"
                  ? "Threat operations"
                  : view === "topology"
                    ? "Entity intelligence"
                    : "Model assurance"}
              </h1>
            </div>
          </div>

          {view !== "packets" && <form
            className="global-search"
            role="search"
            onSubmit={(event) => {
              event.preventDefault();
              setGlobalSearch(globalSearchDraft.trim());
              setView("alerts");
            }}
          >
            <Search size={16} aria-hidden="true" />
            <input
              value={globalSearchDraft}
              onChange={(event) => setGlobalSearchDraft(event.target.value)}
              placeholder="Search alerts, entities, IPs, or resources"
              aria-label="Global search"
            />
            <kbd>Enter</kbd>
          </form>}

          <div className="command-actions">
            <span className="system-state">
              <StatusDot />
              {view === "live" || view === "packets" ? "Live API" : "Replay"}
            </span>
            <span className="time-range">
              <CalendarDays size={15} />
              {view === "live" || view === "packets" ? "Isolated demo session" : "14-day replay"}
            </span>
            <button
              type="button"
              className="header-icon-button"
              onClick={() => window.location.reload()}
              aria-label="Refresh score snapshot"
              title="Refresh score snapshot"
            >
              <RotateCw size={16} />
            </button>
            {view !== "packets" && <button
              type="button"
              className="notification-button"
              aria-label="Alert notifications"
              title="Alert notifications"
            >
              <BellRing size={17} />
              <span>{DATA.operating_points[policy].n_flagged}</span>
            </button>}
            <span className="profile-badge" title="Harthik M V · Aspiring Machine Learning Engineer / Data Engineer" aria-label="Project by Harthik M V">
              HM
            </span>
          </div>
        </header>

        {view === "alerts" && (
          <>
            <div className="mobile-policy-summary" role="status">
              Synthetic test: {percent(DATA.operating_points[policy].precision)} precision
              {" · "}{percent(DATA.operating_points[policy].recall)} attack recall
            </div>
            <PostureStrip policy={policy} reviewedCount={reviewedCount} />
            <main className="workspace view-enter">
              <AlertQueue
                policy={policy}
                setPolicy={setPolicy}
                selectedId={selectedId}
                onSelect={selectAlert}
                feedbackVersion={feedbackVersion}
                globalSearch={globalSearch}
              />
              <IncidentPanel
                alert={selectedAlert}
                policy={policy}
                open={detailOpen}
                onClose={() => setDetailOpen(false)}
                onSaved={() => setFeedbackVersion((value) => value + 1)}
              />
            </main>
          </>
        )}

        {view === "topology" && (
          <TopologyView
            data={DATA}
            policy={policy}
            onInvestigate={(alertId) => {
              setSelectedId(alertId);
              setDetailOpen(true);
              setView("alerts");
            }}
          />
        )}

        {view === "evaluation" && <ModelAudit />}
        {view === "live" && <LiveConsole />}
        {view === "packets" && <PacketConsole />}
      </div>

      <nav className="mobile-navigation" aria-label="Mobile navigation">
        <button type="button" className={view === "packets" ? "active" : ""} onClick={() => setView("packets")}><Layers3 size={19}/>Packets</button>
        <button type="button" className={view === "live" ? "active" : ""} onClick={() => setView("live")}><Radio size={19}/>Live inference</button>
        <button
          type="button"
          className={view === "alerts" ? "active" : ""}
          onClick={() => setView("alerts")}
        >
          <ShieldAlert size={19} />
          Alerts
        </button>
        <button
          type="button"
          className={view === "topology" ? "active" : ""}
          onClick={() => setView("topology")}
        >
          <Waypoints size={19} />
          Topology
        </button>
        <button
          type="button"
          className={view === "evaluation" ? "active" : ""}
          onClick={() => setView("evaluation")}
        >
          <BarChart3 size={19} />
          Model audit
        </button>
      </nav>
    </div>
  );
}
