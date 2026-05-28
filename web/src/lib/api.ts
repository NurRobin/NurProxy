import type { Provider, Agent, Server, Domain, AuditLogEntry, Setting } from './types';

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

export const api = {
  // Providers
  listProviders: () => request<Provider[]>('/providers'),
  createProvider: (data: Partial<Provider>) => request<Provider>('/providers', { method: 'POST', body: JSON.stringify(data) }),
  deleteProvider: (id: string) => request<void>(`/providers/${id}`, { method: 'DELETE' }),
  testProvider: (data: unknown) => request<void>('/providers/test', { method: 'POST', body: JSON.stringify(data) }),

  // Agents
  listAgents: () => request<Agent[]>('/agents'),
  adoptAgent: (id: string, data: unknown) => request<Agent>(`/agents/${id}/adopt`, { method: 'PUT', body: JSON.stringify(data) }),
  rejectAgent: (id: string) => request<void>(`/agents/${id}/reject`, { method: 'PUT' }),
  deleteAgent: (id: string) => request<void>(`/agents/${id}`, { method: 'DELETE' }),

  // Servers
  listServers: (agentId: string) => request<Server[]>(`/agents/${agentId}/servers`),
  createServer: (agentId: string, data: Partial<Server>) => request<Server>(`/agents/${agentId}/servers`, { method: 'POST', body: JSON.stringify(data) }),
  deleteServer: (id: string) => request<void>(`/servers/${id}`, { method: 'DELETE' }),

  // Domains
  listDomains: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<Domain[]>(`/domains${qs}`);
  },
  createDomain: (data: Partial<Domain>) => request<Domain>('/domains', { method: 'POST', body: JSON.stringify(data) }),
  getDomain: (id: number) => request<Domain>(`/domains/${id}`),
  updateDomain: (id: number, data: Partial<Domain>) => request<Domain>(`/domains/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteDomain: (id: number) => request<void>(`/domains/${id}`, { method: 'DELETE' }),

  // System
  health: () => request<{ status: string }>('/health'),
  getAuditLog: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<AuditLogEntry[]>(`/audit-log${qs}`);
  },
  getSettings: () => request<Setting[]>('/settings'),
  updateSetting: (key: string, value: string) => request<void>(`/settings/${key}`, { method: 'PUT', body: JSON.stringify({ value }) }),
};
