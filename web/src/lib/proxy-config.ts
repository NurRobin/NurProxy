import type { PathRoute, ProxyConfig } from './types';

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
  /** "" keeps the host-wide access log, "off" turns it off. */
  access_log: string;
  /** "" keeps the host default level. */
  error_log_level: string;
  /** Use the zone's shared *.<zone> certificate instead of a per-host one. */
  tls_wildcard: boolean;
  custom_request_headers: { key: string; value: string }[];
  /** Path routes as edited; undefined when the form does not show them. */
  routes?: PathRouteEdit[];
}

/** A path route row in the form; the port is the input's text. */
export interface PathRouteEdit {
  match: 'prefix' | 'exact';
  path: string;
  server_id: string;
  port: string;
  upstream_scheme: string;
  websocket: boolean;
  strip_prefix: boolean;
}

/** Turns a stored route into a form row. */
export function pathRouteEdit(r: PathRoute): PathRouteEdit {
  return {
    match: r.match, path: r.path, server_id: r.server_id, port: String(r.port),
    upstream_scheme: r.upstream_scheme ?? '', websocket: r.websocket ?? false, strip_prefix: r.strip_prefix ?? false,
  };
}

/**
 * Turns form rows into the API shape, leaving out rows without a path. Values
 * are sent as typed; the API reports what it refuses.
 */
export function pathRoutesFromEdits(edits: PathRouteEdit[]): PathRoute[] {
  return edits
    .filter((e) => e.path.trim() !== '')
    .map((e) => {
      const r: PathRoute = { match: e.match, path: e.path.trim(), server_id: e.server_id, port: Number.parseInt(e.port, 10) || 0 };
      if (e.upstream_scheme) r.upstream_scheme = e.upstream_scheme;
      if (e.websocket) r.websocket = true;
      if (e.match === 'prefix' && e.strip_prefix) r.strip_prefix = true;
      return r;
    });
}

function sameRoutes(a: PathRoute[], b: PathRoute[]): boolean {
  const norm = (r: PathRoute) => JSON.stringify([r.match, r.path, r.server_id, r.port, r.upstream_scheme ?? '', !!r.websocket, !!r.strip_prefix]);
  return a.length === b.length && a.every((r, i) => norm(r) === norm(b[i]));
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
  if (edits.access_log !== (stored?.access_log ?? '')) changes.access_log = edits.access_log || null;
  if (edits.error_log_level !== (stored?.error_log_level ?? '')) changes.error_log_level = edits.error_log_level || null;
  if (edits.tls_wildcard !== (stored?.tls_wildcard ?? false)) changes.tls_wildcard = edits.tls_wildcard;

  const headers: Record<string, string> = {};
  for (const h of edits.custom_request_headers) if (h.key.trim()) headers[h.key.trim()] = h.value;
  if (!sameHeaders(headers, stored?.custom_request_headers ?? {})) {
    changes.custom_request_headers = Object.keys(headers).length > 0 ? headers : null;
  }
  if (edits.routes) {
    const routes = pathRoutesFromEdits(edits.routes);
    if (!sameRoutes(routes, stored?.routes ?? [])) changes.routes = routes.length > 0 ? routes : null;
  }
  return Object.keys(changes).length > 0 ? changes : undefined;
}

/**
 * Whether a domain may use its zone's shared *.<zone> certificate. Mirrors the
 * orchestrator's ValidateTLSWildcard: the wildcard covers exactly one label
 * below the zone, so the apex ("@") and deeper names are excluded, and only
 * central TLS serves a provided certificate.
 */
export function wildcardEligible(subdomain: string, sslMode?: string, tlsPolicy?: string): boolean {
  const label = subdomain.trim();
  if (label === '' || label === '@' || label.includes('.')) return false;
  if (tlsPolicy === 'self-acme' || tlsPolicy === 'off') return false;
  return tlsPolicy === 'central' || sslMode !== 'off';
}
