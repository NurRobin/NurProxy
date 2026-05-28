import type { Provider, Zone, Agent, Server, Domain, AuditLogEntry, Setting } from './types';

const BASE = '/api/v1';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API error ${res.status}: ${body}`);
  }
  return res.json();
}

export interface AuthStatus {
  setup_required: boolean;
  authenticated: boolean;
}

export interface AuditLogResponse {
  entries: AuditLogEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface HealthResponse {
  status: string;
  version: string;
}

export interface TestProviderZone {
  id: string;
  name: string;
}

export interface DomainConfig {
  manual: boolean;
  config: unknown;
}

export const api = {
  // Auth
  authStatus: () => request<AuthStatus>('/auth/status'),
  setup: (password: string) => request<{ message: string }>('/auth/setup', { method: 'POST', body: JSON.stringify({ password }) }),
  login: (password: string) => request<{ message: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ password }) }),
  logout: () => request<{ message: string }>('/auth/logout', { method: 'POST' }),
  changePassword: (current_password: string, new_password: string) =>
    request<{ message: string }>('/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),

  // Providers
  listProviders: () => request<Provider[]>('/providers'),
  getProvider: (id: string) => request<Provider>(`/providers/${id}`),
  createProvider: (data: { type: string; name: string; config: unknown }) =>
    request<{ id: string; name: string }>('/providers', { method: 'POST', body: JSON.stringify(data) }),
  updateProvider: (id: string, data: Partial<Provider>) =>
    request<{ message: string }>(`/providers/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteProvider: (id: string) => request<{ message: string }>(`/providers/${id}`, { method: 'DELETE' }),
  testProvider: (data: { type: string; config: unknown }) =>
    request<{ valid: boolean; message: string; zones?: TestProviderZone[] }>('/providers/test', { method: 'POST', body: JSON.stringify(data) }),
  listProviderZones: (id: string) => request<Zone[]>(`/providers/${id}/zones`),

  // Zones
  listAllZones: () => request<Zone[]>('/zones'),
  createZonesBatch: (data: { provider_id: string; zones: Array<{ external_id: string; name: string }> }) =>
    request<Array<{ id: string; name: string }>>('/zones/batch', { method: 'POST', body: JSON.stringify(data) }),
  deleteZone: (id: string) => request<{ message: string }>(`/zones/${id}`, { method: 'DELETE' }),

  // Agents
  listAgents: () => request<Agent[]>('/agents'),
  updateAgent: (id: string, data: { name?: string; zone_ids?: string[]; dns_mode?: string; ddns_interval?: number }) =>
    request<Agent>(`/agents/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  adoptAgent: (id: string, data: { name?: string; zone_ids?: string[]; dns_mode?: string; ddns_interval?: number }) =>
    request<Agent>(`/agents/${id}/adopt`, { method: 'PUT', body: JSON.stringify(data) }),
  rejectAgent: (id: string) => request<{ message: string }>(`/agents/${id}/reject`, { method: 'PUT' }),
  deleteAgent: (id: string) => request<{ message: string }>(`/agents/${id}`, { method: 'DELETE' }),

  // Servers
  listServers: (agentId: string) => request<Server[]>(`/agents/${agentId}/servers`),
  createServer: (agentId: string, data: { name: string; address: string; notes?: string }) =>
    request<Server>(`/agents/${agentId}/servers`, { method: 'POST', body: JSON.stringify(data) }),
  updateServer: (id: string, data: Partial<Server>) =>
    request<Server>(`/servers/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteServer: (id: string) => request<{ message: string }>(`/servers/${id}`, { method: 'DELETE' }),

  // Domains
  listDomains: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<Domain[]>(`/domains${qs}`);
  },
  createDomain: (data: Partial<Domain>) =>
    request<Domain>('/domains', { method: 'POST', body: JSON.stringify(data) }),
  getDomain: (id: number) => request<Domain>(`/domains/${id}`),
  updateDomain: (id: number, data: Partial<Domain>) =>
    request<Domain>(`/domains/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteDomain: (id: number) => request<{ message: string }>(`/domains/${id}`, { method: 'DELETE' }),
  getDomainConfig: (id: number) => request<DomainConfig>(`/domains/${id}/config`),
  updateDomainConfig: (id: number, config: unknown) =>
    request<{ message: string }>(`/domains/${id}/config`, { method: 'PUT', body: JSON.stringify({ config }) }),
  resetDomainConfig: (id: number) =>
    request<{ message: string }>(`/domains/${id}/config/reset`, { method: 'POST' }),

  // System
  health: () => request<HealthResponse>('/health'),
  getAuditLog: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<AuditLogResponse>(`/audit-log${qs}`);
  },
  getSettings: () => request<Setting[]>('/settings'),
  updateSetting: (key: string, value: string) =>
    request<{ key: string; value: string }>(`/settings/${key}`, { method: 'PUT', body: JSON.stringify({ value }) }),

  // Admin API key
  getAPIKey: () => request<{ exists: boolean; masked?: string }>('/api-key'),
  generateAPIKey: () => request<{ api_key: string }>('/api-key', { method: 'POST' }),
  revokeAPIKey: () => request<{ message: string }>('/api-key', { method: 'DELETE' }),
};
