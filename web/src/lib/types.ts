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
  discovered_upstreams?: DiscoveredUpstream[];
  networks?: DiscoveredNetwork[];
}

/** An IP subnet attached to the agent host — a CIDR suggestion for the Server
 *  address dialog (§38). */
export interface DiscoveredNetwork {
  interface?: string;
  address?: string;
  prefix_length?: number;
  network: string;
}

/** A backend target found in the host proxy's existing config — a suggestion
 *  source for Servers (§52). */
export interface DiscoveredUpstream {
  scheme?: string;
  host: string;
  port?: number;
  server_names?: string[];
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
 * How the agent is installed and running: OS/distro, the service manager that
 * started it, whether it runs as root, and whether its filesystem is sandboxed.
 * This is the context that decides which remediation applies — a root agent under
 * a systemd sandbox needs a ReadWritePaths drop-in, an unprivileged one needs
 * group ownership + scoped sudoers.
 */
export interface RuntimeEnv {
  os?: string;
  distro?: string;
  init_system?: string;
  managed: boolean;
  unit?: string;
  sandboxed: boolean;
  user?: string;
  is_root: boolean;
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
  /** How the agent is installed/running — the context behind the remediation. */
  runtime_env?: RuntimeEnv;
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
  /**
   * Computed server-side: how the agent's version compares to the orchestrator's
   * ('current' | 'outdated' | 'ahead'). 'unknown' when either side is missing or
   * a non-release (dev) build.
   */
  version_status?: 'current' | 'outdated' | 'ahead' | 'unknown';
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
  safe_auto_repair_override?: boolean | null;
  safe_auto_repair_effective: boolean;
  recovery_capability?: RecoveryCapability;
  created_at: string;
  updated_at: string;
  servers?: Server[];
}

export type RecoveryCode =
  | 'managed_orphan_config' | 'managed_stale_temp' | 'managed_cert_file_missing'
  | 'managed_runtime_key_missing' | 'managed_runtime_key_mismatch'
  | 'generated_config_invalid' | 'operator_config_invalid' | 'permission_denied'
  | 'systemd_sandbox_denied' | 'proxy_reload_failed' | 'proxy_not_running'
  | 'port_conflict' | 'proxy_binary_missing' | 'unknown_proxy_error';

export type RecoverySeverity = 'info' | 'warning' | 'error' | 'critical';
export type RecoveryOwnership = 'nurproxy' | 'operator' | 'system' | 'unknown';
export type RecoveryAction =
  | 'prune_managed_orphan' | 'remove_managed_temp' | 'rematerialize_cert_bundle'
  | 'rematerialize_runtime_key' | 'restore_last_live_artifact';
export type RecoveryOperationState =
  | 'detected' | 'diagnosis_only' | 'planned' | 'snapshotted' | 'applying'
  | 'validating' | 'succeeded' | 'rolling_back' | 'rolled_back'
  | 'rollback_failed' | 'suppressed';

export interface RecoveryCapability {
  stage: number;
  actions: RecoveryAction[];
}

export interface RecoveryDiagnostic {
  id: string;
  code: RecoveryCode;
  subsystem: string;
  severity: RecoverySeverity;
  ownership: RecoveryOwnership;
  ownership_confidence?: 'certain' | 'inferred' | 'unknown';
  summary: string;
  evidence: string;
  affected_paths: string[];
  resource_fingerprint: string;
  proposed_action: RecoveryAction | '';
  auto_repair_eligible: boolean;
  hard_change: boolean;
  repair_scope?: string;
  repair_eligible?: boolean;
  repair_refusal_code?: string;
  first_seen_at: string;
  last_seen_at: string;
  occurrences: number;
  resolved_at?: string;
  resolution_reason?: 'repaired' | 'resource_disappeared' | 'desired_state_changed'
    | 'operator_resolved' | 'superseded' | 'condition_no_longer_observed';
  resolution_operation_id?: string;
  breaker?: RecoveryBreaker;
}

export type HardRecoveryAction =
  | 'repair_agent_sandbox_paths' | 'repair_managed_path_access'
  | 'validate_reload_proxy' | 'start_proxy' | 'restart_proxy'
  | 'install_supported_proxy_package' | 'open_proxy_firewall_ports';

export interface HardRecoveryPlanStep {
  kind: string;
  summary: string;
}

export interface HardRecoveryPlan {
  agent_id: string;
  operation_id: string;
  helper_plan_id: string;
  helper_instance_id: string;
  diagnostic_id: string;
  action: HardRecoveryAction;
  logical_target: string;
  display_plan_hash: string;
  execution_plan_hash: string;
  resource_fingerprint: string;
  rollback_coverage: 'full' | 'partial' | 'none';
  signed_plan: {
    envelope: {
      payload: {
        steps: HardRecoveryPlanStep[];
        expires_at: string;
      };
    };
  };
  received_at: string;
  expires_at: string;
  confirmation_event_ids: string[];
  confirmation_times: string[];
  signed_execution_grant?: unknown;
  signed_helper_receipt?: { envelope: { payload: { state: string; sanitized_result: string } } };
}

export interface RecoveryHelperInstance {
  agent_id: string;
  helper_instance_id: string;
  helper_build_id: string;
  attestation_key_id: string;
  hello_digest: string;
  enrolled_at: string;
}

export type RecoveryHelperStatus =
  | { enrolled: false }
  | { enrolled: true; helper: RecoveryHelperInstance };

export interface RecoveryBreaker {
  open: boolean;
  reason?: 'failure_threshold' | 'rollback_failed_latched';
  expires_at?: string;
}

export interface RecoveryStep {
  name: string;
  summary: string;
  state: RecoveryOperationState;
  at: string;
}

export interface RecoveryOperation {
  operation_id: string;
  diagnostic_id: string;
  action: RecoveryAction;
  source: 'automatic' | 'user';
  state: RecoveryOperationState;
  steps: RecoveryStep[];
  snapshot_reference: string;
  validation_outcome: string;
  rollback_outcome: string;
  error: string;
  started_at: string;
  finished_at?: string | null;
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
  /** cert_only: NurProxy issues + renews the TLS cert and installs it on the
   *  agent without serving a vhost; the operator hand-writes the config. */
  cert_only?: boolean;
  dns_record_id?: string;
  status: 'pending' | 'active' | 'error' | 'deleting' | 'degraded';
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
  /** Operator's on-disk content captured while drifted (§11): diff baseline + Accept payload. */
  drift_content?: string;
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
