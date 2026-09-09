export type PolicyKey =
  | "top_0.5pct"
  | "top_1pct"
  | "top_2pct"
  | "top_5pct";

export type Severity = "critical" | "high" | "review";
export type ViewName = "alerts" | "topology" | "evaluation" | "live" | "packets";

export interface AlertRecord {
  id: number;
  timestamp: string;
  entity: string;
  entity_type: string;
  role: string;
  classification: string;
  truth: string;
  risk: number;
  source_ip: string;
  city: string;
  resource: string;
  auth: string;
  reason: string;
  baseline_epoch: number;
  drift_alarm: boolean;
  scores: Record<string, number>;
}

export interface TimelinePoint {
  timestamp: string;
  risk: number;
  classification: string;
  baseline_epoch: number;
}

export interface OperatingPoint {
  threshold: number;
  precision: number;
  recall: number;
  false_positive_rate: number;
  realized_alert_rate: number;
  n_flagged: number;
  true_positives?: number;
  false_positives?: number;
}

export interface ChannelMetric {
  pr_auc: number;
  roc_auc: number;
}

export interface ClassMetric {
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface DashboardData {
  snapshot_sha256: string;
  default_policy: PolicyKey;
  threshold: number;
  policy_alert_count: number;
  kpis: {
    pr_auc: number;
    roc_auc: number;
    precision: number;
    recall: number;
    fp_rate: number;
    macro_f1: number;
  };
  selected_strategy: string;
  cold_start: {
    events: number;
    recall: number;
    recall_std: number | null;
    recall_single_run: number;
    recall_is_multiseed: boolean;
    false_positive_rate: number;
  };
  drift: {
    test_drift_alarms: number;
    drift_alarms: number;
    entities_with_drift: number;
  };
  real_data_probe: Record<string, unknown> | null;
  channels: Record<string, ChannelMetric>;
  operating_points: Record<PolicyKey, OperatingPoint>;
  per_class: Record<string, ClassMetric>;
  alerts: AlertRecord[];
  timeline: Record<string, TimelinePoint[]>;
}

export interface Disposition {
  event_id: number;
  disposition: string;
  note: string;
  at: string;
}
