export type ScanKind = 'quick' | 'full' | 'custom';
export interface Config {
  protection_enabled: boolean;
  watch_paths: string[];
  exclusions: string[];
  allowed_hashes: string[];
  max_file_bytes: number;
  heuristics_enabled: boolean;
  scan_interval_hours: number | null;
  update_interval_hours: number | null;
  update_manifest_url: string | null;
  update_public_key: string | null;
  cloud_lookup_enabled: boolean;
}
export interface Finding {
  name: string;
  method: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
}
export interface Threat {
  id: string;
  path: string;
  sha256: string;
  size: number;
  detected_at: string;
  findings: Finding[];
  status: string;
}
export interface ScanProgress {
  id: string;
  kind: ScanKind;
  state: string;
  scanned: number;
  total_files: number | null;
  skipped: number;
  errors: number;
  threats: number;
  current_path: string | null;
  started_at: string;
  finished_at: string | null;
  elapsed_seconds: number;
  estimated_remaining_seconds: number | null;
}
export interface QuarantineEntry {
  id: string;
  threat: Threat;
  quarantined_at: string;
  source_removed: boolean;
  staging_path: string | null;
  restored_at: string | null;
}
export interface Activity {
  at: string;
  level: string;
  message: string;
}
export interface Status {
  version: string;
  protection_enabled: boolean;
  watcher_active: boolean;
  watched_roots: string[];
  dropped_events: number;
  monitoring?: {
    health: 'disabled' | 'starting' | 'healthy' | 'recovering' | 'degraded';
    queue_depth: number;
    workers_active: number;
    worker_limit: number;
    oldest_event_age_ms: number;
    recovery_in_progress: boolean;
    recovery_count: number;
    last_recovery_at: string | null;
    retry_count: number;
    scan_failures: number;
    last_error: string | null;
  };
  yara_enabled: boolean;
  signature_version: number;
  scanned_total: number;
  process_count: number;
  network_received: number;
  network_transmitted: number;
  established_connections: number | null;
  scan: ScanProgress | null;
  threats: Threat[];
  quarantine: QuarantineEntry[];
  history: ScanProgress[];
  activity: Activity[];
  config: Config;
}
export type Action =
  | { action: 'start_scan'; request: { kind: ScanKind; paths: string[] } }
  | { action: 'pause_scan' | 'resume_scan' | 'cancel_scan' | 'update_signatures' }
  | { action: 'set_protection'; enabled: boolean }
  | { action: 'save_config'; config: Config }
  | { action: 'quarantine' | 'delete_quarantine' | 'allow'; id: string }
  | { action: 'restore'; id: string; destination: string };
