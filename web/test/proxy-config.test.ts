import assert from 'node:assert/strict';
import test from 'node:test';
import { pathRouteEdit, proxyConfigChanges, type ProxyConfigFormEdits } from '../src/lib/proxy-config.ts';
import type { ProxyConfig } from '../src/lib/types.ts';

const stored = {
  websocket: true,
  max_body_size: '10m',
  custom_request_headers: { 'X-A': '1', 'X-B': '2' },
  tls_policy: 'self-acme',
  basic_auth: { username: 'admin', password: '$2a$10$hash' },
  ip_allowlist: ['10.0.0.0/8'],
} as ProxyConfig;

// The form as openDetail fills it from `stored`, with nothing edited.
const unchanged: ProxyConfigFormEdits = {
  websocket: true,
  force_https: false,
  max_body_size: '10m',
  access_log: '',
  error_log_level: '',
  custom_request_headers: [{ key: 'X-B', value: '2' }, { key: 'X-A', value: '1' }],
};

test('nothing changed sends no proxy_config', () => {
  assert.equal(proxyConfigChanges(stored, unchanged), undefined);
});

test('sends only the changed keys, never hidden settings like basic auth (#163)', () => {
  const body = proxyConfigChanges(stored, { ...unchanged, force_https: true, max_body_size: '20m' });
  assert.deepEqual(body, { force_https: true, max_body_size: '20m' });
});

test('a changed header list is sent whole, trimmed and without blank keys', () => {
  const body = proxyConfigChanges(stored, {
    ...unchanged,
    custom_request_headers: [{ key: ' X-A ', value: '1' }, { key: 'X-C', value: '3' }, { key: '', value: 'x' }],
  });
  assert.deepEqual(body, { custom_request_headers: { 'X-A': '1', 'X-C': '3' } });
});

test('fields emptied by the user are sent as null', () => {
  const body = proxyConfigChanges(stored, { ...unchanged, websocket: false, max_body_size: '', custom_request_headers: [] });
  assert.deepEqual(body, { websocket: false, max_body_size: null, custom_request_headers: null });
});

test('logging settings are sent when changed and cleared back to the host default with null (#150)', () => {
  assert.deepEqual(proxyConfigChanges(stored, { ...unchanged, access_log: 'off', error_log_level: 'crit' }), { access_log: 'off', error_log_level: 'crit' });
  const quiet = { ...stored, access_log: 'off', error_log_level: 'crit' } as ProxyConfig;
  assert.equal(proxyConfigChanges(quiet, { ...unchanged, access_log: 'off', error_log_level: 'crit' }), undefined);
  assert.deepEqual(proxyConfigChanges(quiet, unchanged), { access_log: null, error_log_level: null });
});

test('path routes are sent whole when changed and cleared with null (#89)', () => {
  const routes = [
    { match: 'exact', path: '/api/world', server_id: 's2', port: 80 },
    { match: 'prefix', path: '/media', server_id: 's3', port: 9000, strip_prefix: true },
  ] as NonNullable<ProxyConfig['routes']>;
  const withRoutes = { ...stored, routes } as ProxyConfig;
  const rows = routes.map(pathRouteEdit);
  assert.equal(proxyConfigChanges(withRoutes, { ...unchanged, routes: rows }), undefined);
  assert.equal(proxyConfigChanges(withRoutes, unchanged), undefined, 'a form without the routes tab leaves them alone');

  const added = { match: 'exact' as const, path: ' /x ', server_id: 's2', port: '81', upstream_scheme: 'https', websocket: true, strip_prefix: true };
  assert.deepEqual(proxyConfigChanges(withRoutes, { ...unchanged, routes: [...rows, added] }), {
    routes: [...routes, { match: 'exact', path: '/x', server_id: 's2', port: 81, upstream_scheme: 'https', websocket: true }],
  });
  assert.deepEqual(proxyConfigChanges(withRoutes, { ...unchanged, routes: [] }), { routes: null });
  assert.equal(proxyConfigChanges(stored, { ...unchanged, routes: [{ ...added, path: '' }] }), undefined, 'rows without a path are ignored');
});

test('works without a stored config', () => {
  const empty: ProxyConfigFormEdits = { websocket: false, force_https: false, max_body_size: '', access_log: '', error_log_level: '', custom_request_headers: [] };
  assert.equal(proxyConfigChanges(undefined, empty), undefined);
  assert.deepEqual(proxyConfigChanges(undefined, { ...empty, websocket: true }), { websocket: true });
});
