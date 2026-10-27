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

function sameHeaders(a: Record<string, string>, b: Record<string, string>): boolean {
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((k) => Object.hasOwn(b, k) && a[k] === b[k]);
}

/**
 * Returns only the proxy_config keys the form changed compared with the config
 * stored when the form opened; a field emptied by the user is sent as null so
 * the API clears it. Settings the form doesn't show are never sent, so the API
 * keeps them as stored. Returns undefined when nothing changed.
 */
export function proxyConfigChanges(stored: ProxyConfig | undefined, edits: ProxyConfigFormEdits): ProxyConfigUpdate | undefined {
  const changes: ProxyConfigUpdate = {};
  if (edits.websocket !== (stored?.websocket ?? false)) changes.websocket = edits.websocket;
  if (edits.force_https !== (stored?.force_https ?? false)) changes.force_https = edits.force_https;
  if (edits.max_body_size !== (stored?.max_body_size ?? '')) changes.max_body_size = edits.max_body_size || null;

  const headers: Record<string, string> = {};
  for (const h of edits.custom_request_headers) if (h.key.trim()) headers[h.key.trim()] = h.value;
  if (!sameHeaders(headers, stored?.custom_request_headers ?? {})) {
    changes.custom_request_headers = Object.keys(headers).length > 0 ? headers : null;
  }
  return Object.keys(changes).length > 0 ? changes : undefined;
}
