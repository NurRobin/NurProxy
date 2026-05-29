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
  details?: string;
  created_at: string;
}

export interface Setting {
  key: string;
  value: string;
  updated_at: string;
}
