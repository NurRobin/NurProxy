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

/** One ordered remediation step: a human title plus copy-paste shell commands. */
export interface RemediationStep {
  title: string;
  commands: string[];
}

/** Least-privilege fix for missing existing-mode grants (§12/§19). */
export interface Remediation {
  steps?: RemediationStep[];
  sudoers_line?: string;
}

/**
 * The agent's structured §12 permission self-test for an existing-mode backend:
 * can it WRITE the config dir and RELOAD the service. Carries the targeted
 * remediation when a grant is missing, so the dashboard shows exactly what to fix
 * instead of one opaque error. checked=false means built-in mode (nothing to probe).
 */
export interface ProxyPermissions {
  checked: boolean;
  ok: boolean;
  can_write: boolean;
  can_reload: boolean;
  write_error?: string;
  reload_error?: string;
  dirs?: string[];
  remediation?: Remediation;
}

// On-demand log tail (§15). The dashboard opens a session, polls for lines past a
// cursor, and stops the session when the view closes. The agent dials out for
// every hop — the orchestrator never reads the agent inbound.
export interface LogTailLine {
  seq: number;
  text: string;
}

export interface LogTailPoll {
  lines: LogTailLine[];
  cursor: number;
  done: boolean;
  error?: string;
}

/**
 * The agent's last-reported capability matrix (§8) for its selected backend. A
 * false field means the backend cannot honor that option, so the dashboard
 * greys it out and the agent drops it during Render with an audited warning.
 */
export interface ProxyCapabilities {
  reverse_proxy: boolean;
  websocket: boolean;
  force_https: boolean;
  custom_headers: boolean;
  path_rewrite: boolean;
  basic_auth: boolean;
  ip_filter: boolean;
  rate_limit: boolean;
  central_tls: boolean;
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
  /**
   * The agent's CURRENT live reverse-proxy mode (§19): 'built-in' (bundled Caddy)
   * or 'existing' (a host-installed nginx/apache/caddy after a hot-switch). Owned
   * by the agent via heartbeat, so the dashboard reflects reality after a switch
   * instead of assuming built-in. Defaults to 'built-in'.
   */
  proxy_mode?: 'built-in' | 'existing';
  last_error?: string;
  dns_error?: string;
  proxy_detection?: ProxyDetection;
  proxy_detected_at?: string;
  proxy_capabilities?: ProxyCapabilities;
  /**
   * The agent's §12 permission self-test for an existing-mode backend (config dir
   * writable? service reloadable?) plus the targeted remediation when a grant is
   * missing. Re-probed each heartbeat, so it clears on its own once granted.
   * Absent in built-in mode or before the first existing-mode beat.
   */
  proxy_permissions?: ProxyPermissions;
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
  // tls_policy selects how the public-listener cert is provisioned:
  // "central" (DNS-01 provided cert, the default), "self-acme", or "off".
  tls_policy?: string;
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

/** Op type for a pending agent admin op (§19). Only set_proxy_mode for now. */
export type AdminOpType = 'set_proxy_mode';

/** Lifecycle of a pending admin op (§19). */
export type AdminOpStatus = 'pending' | 'applied' | 'expired' | 'canceled';

/** Payload for a set_proxy_mode admin op (§19). Mirrors the agent config keys. */
export interface SetProxyModePayload {
  proxy_mode: 'existing' | 'built-in';
  proxy_type?: string;
  proxy_config_dir?: string;
  proxy_reload_cmd?: string;
  proxy_test_cmd?: string;
  proxy_service?: string;
  proxy_log_paths?: string[];
}

/** The one-time result of preparing an admin op — the code is shown only here (§19). */
export interface PreparedAdminOp {
  id: string;
  code: string;
  expires_at: string;
}

/** The code-free projection of a pending admin op returned to the dashboard (§19). */
export interface AdminOpView {
  id: string;
  op_type: AdminOpType;
  status: AdminOpStatus;
  created_at: string;
  expires_at: string;
  applied_at?: string;
  result?: string;
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

/** Backend-neutral proxy route — the structured "mask" recovered from a config (§6). */
export interface ProxyRoute {
  Host?: string;
  Upstream?: { Addr?: string; Port?: number; Scheme?: string };
  WebSocket?: boolean;
  ForceHTTPS?: boolean;
  MaxBodySize?: string;
  RequestHeaders?: Record<string, string>;
  ResponseHeaders?: Record<string, string>;
  Path?: { StripPrefix?: string; Rewrite?: string };
  Timeouts?: { Read?: number; Write?: number; Idle?: number };
  BasicAuth?: { Username?: string } | null;
  IPAllowlist?: string[];
  IPBlocklist?: string[];
  RateLimit?: { RequestsPerSecond?: number };
  TLS?: { Policy?: string; Wildcard?: boolean };
}

/**
 * The structured "mask" view of an artifact's config (§6). The mask is a
 * toggleable, best-effort view: `ok` reports whether it losslessly represents
 * the config; when false the raw text stays authoritative and `unparsed` holds
 * the bytes the parser could not map (never destroyed).
 */
export interface ArtifactMask {
  backend: string;
  ok: boolean;
  route: ProxyRoute;
  unparsed?: string[];
  notes?: string[];
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
