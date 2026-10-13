// Kiểu dữ liệu khớp với backend/app/schemas.py

export type Role = 'admin' | 'viewer'
export type AttackLabel = 'DoS/DDoS' | 'PortScan' | 'BruteForce'
export type FlowLabel = 'BENIGN' | AttackLabel | 'INVALID'
export type AlertStatus = 'open' | 'ack' | 'closed'
export type Severity = 'high' | 'medium' | 'low'

export interface User {
  id: number
  username: string
  role: Role
  full_name: string | null
  email: string | null
  telegram_chat_id: string | null
  notify: boolean
  is_active: boolean
  created_at: string
}

export interface PipelineStatus {
  state: 'running' | 'stopped' | 'never'
  last_run: string | null
  last_run_age_s?: number
  last_error?: string | null
  interval_s?: number
  runs_10min?: number
  errors_10min?: number
  avg_ms_10min?: number | null
  expected_runs_10min?: number
}

export interface Overview {
  minutes: number
  flows_total: number
  flows_attack: number
  attack_ratio: number
  flows_by_label: Partial<Record<FlowLabel, number>>
  alerts_open: number
  alerts_open_by_severity: Partial<Record<Severity, number>>
  alerts_by_label: Partial<Record<AttackLabel, number>>
  pipeline: PipelineStatus
  model: { name: string; feature_set: string; tau: number }
}

export interface Timeseries {
  flows: { minute: string; label: FlowLabel; flows: number }[]
  alerts: { minute: string; label: AttackLabel; alerts: number }[]
}

export interface TopRow {
  ip: string
  label: AttackLabel
  flows: number
  last_seen: string
}

export interface Alert {
  id: number
  label: AttackLabel
  severity: Severity
  src_ip: string | null
  dst_ip: string | null
  dst_port: number | null
  first_seen: string
  last_seen: string
  flow_count: number
  src_count: number
  max_score: number | null
  source: string
  rule_detail: string | null
  status: AlertStatus
  note: string | null
  ack_by: string | null
  ack_at: string | null
  closed_at: string | null
  created_at: string
}

export interface Flow {
  id: number
  ts: string
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  protocol: number
  duration_us: number | null
  fwd_pkts: number | null
  bwd_pkts: number | null
  fwd_bytes: number | null
  bwd_bytes: number | null
  valid: boolean
  label: FlowLabel | null
  attack_score: number | null
  source: string | null
  rule_detail: string | null
  alert_id: number | null
}

export interface NotificationRow {
  id: number
  channel: 'telegram' | 'email'
  recipient: string
  status: 'pending' | 'sent' | 'failed'
  error: string | null
  created_at: string
  sent_at: string | null
  latency_ms: number | null
}

export interface AlertPage {
  items: Alert[]
  total: number
  page: number
  size: number
}

export interface AlertDetail {
  alert: Alert
  flows: Flow[]
  notifications: NotificationRow[]
  top_sources: { ip: string; flows: number }[]
}

export interface RuntimeSettings {
  tau: number
  ps_min: number
  bf_min: number
  alert_idle_seconds: number
  telegram_enabled: boolean
  telegram_bot_token: string
  email_enabled: boolean
  smtp_host: string
  smtp_port: number
  smtp_user: string
  smtp_password: string
  smtp_from: string
  smtp_starttls: boolean
  notify_min_severity: Severity
}

export interface ModelInfo {
  model_name: string
  run_id: string
  feature_set: string
  n_features: number
  classes: string[]
  bundle_threshold: number
  tau: number
  created: string
  versions: Record<string, string>
  macro_f1_test: number | null
  file: string
  file_size_mb: number
}

export interface PipelineRun {
  id: number
  started_at: string
  finished_at: string | null
  files: string | null
  rows_in: number
  rows_valid: number
  rows_attack: number
  alerts_new: number
  alerts_updated: number
  flag_mode: string | null
  tau: number | null
  ms: number | null
  error: string | null
}
