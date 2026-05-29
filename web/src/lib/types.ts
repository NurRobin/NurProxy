export interface Provider {
  id: string;
  type: string;
  name: string;
  is_default: boolean;
  created_at: string;
}

export interface Zone {
  id: string;
  provider_id: string;
  external_id: string;
  name: string;
  created_at: string;
}

export interface ProxyPortConflict {
  port: number;
  process?: string;
  pid?: number;
}

export interface ProxyDetection {
  installed: boolean;
  kind?: string;
  version?: string;
  binary_path?: string;
  config_dir?: string;
  log_paths?: string[];
  port_conflicts?: ProxyPortConflict[];
}

export interface Agent {
  id: string;
  name: string;
  fqdn: string;
  api_url: string;
  zones?: Zone[];
  dns_mode: 'static' | 'ddns';
  ddns_interval: number;
  public_ip?: string;
  status: 'pending' | 'adopted' | 'offline' | 'error';
  last_seen?: string;
  version?: string;
  caddy_running?: boolean;
  last_error?: string;
  dns_error?: string;
  proxy_detection?: ProxyDetection;
  proxy_detected_at?: string;
  created_at: string;
  updated_at: string;
  servers?: Server[];
}

export interface Server {
  id: string;
  agent_id: string;
  name: string;
  address: string;
  notes?: string;
  created_at: string;
}

export interface Domain {
  id: number;
  subdomain: string;
  zone_id: string;
  server_id: string;
  port: number;
  proxy_config: ProxyConfig;
  manual_config: boolean;
  websocket: boolean;
  force_https: boolean;
  ssl_mode: 'auto' | 'manual' | 'off';
  dns_record_id?: string;
  status: 'pending' | 'active' | 'error' | 'deleting';
  error_msg?: string;
  last_synced?: string;
  created_at: string;
  updated_at: string;
}

export interface ProxyConfig {
  websocket?: boolean;
  force_https?: boolean;
  max_body_size?: string;
  custom_request_headers?: Record<string, string>;
  custom_response_headers?: Record<string, string>;
  upstream_scheme?: string;
}

export interface AuditLogEntry {
  id: number;
  entity_type: string;
  entity_id: string;
  action: string;
  actor: string;
  /** Channel the action came through: ui | api | mcp | agent | system. */
  source?: string;
  details?: string;
  created_at: string;
}

export interface Setting {
  key: string;
  value: string;
  updated_at: string;
}

export type ArtifactSource = 'generated' | 'manual';
export type ArtifactApplyState = 'live' | 'drifted' | 'apply_failed';
export type TargetKind = 'file' | 'caddy-route';

export interface ArtifactTarget {
  kind: TargetKind;
  path: string;
}

/** A unit of the central managed-config store (§4). */
export interface ConfigArtifact {
  id: string;
  agent_id: string;
  backend: string;
  target: ArtifactTarget;
  source: ArtifactSource;
  domain_id?: number;
  content: string;
  checksum: string;
  live_version: number;
  enabled: boolean;
  drifted: boolean;
  apply_state: ArtifactApplyState;
  last_error?: string;
  updated_at: string;
}

/** One entry in an artifact's append-only version history (§4, §11). */
export interface ConfigArtifactVersion {
  id: number;
  artifact_id: string;
  version: number;
  content: string;
  checksum: string;
  source: ArtifactSource;
  actor?: string;
  note?: string;
  created_at: string;
}
