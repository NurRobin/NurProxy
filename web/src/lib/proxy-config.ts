import type { ProxyConfig } from './types';

/**
 * Body for proxy_config in PUT /domains/{id}. The API merges it key by key onto
 * the stored config: absent keys keep their value, null clears the field.
 */
export type ProxyConfigUpdate = { [K in keyof ProxyConfig]?: ProxyConfig[K] | null };

/** The proxy settings the domain detail form (General and Headers tabs) edits. */
export interface ProxyConfigFormEdits {
  websocket: boolean;
  force_https: boolean;
  max_body_size: string;
  custom_request_headers: { key: string; value: string }[];
}

/**
 * Builds the proxy_config to save from the stored one plus the form edits, so
 * every setting the form doesn't show (basic auth, IP lists, TLS policy, raw
 * config, timeouts, ...) is sent back unchanged instead of being dropped.
 */
export function proxyConfigForSave(stored: ProxyConfig | undefined, edits: ProxyConfigFormEdits): ProxyConfigUpdate {
  const next: ProxyConfigUpdate = stored ? structuredClone(stored) : {};
  const headers: Record<string, string> = {};
  for (const h of edits.custom_request_headers) if (h.key.trim()) headers[h.key.trim()] = h.value;
  next.websocket = edits.websocket;
  next.force_https = edits.force_https;
  next.max_body_size = edits.max_body_size || null;
  next.custom_request_headers = Object.keys(headers).length > 0 ? headers : null;
  return next;
}
