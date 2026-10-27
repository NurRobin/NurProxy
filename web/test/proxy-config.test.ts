import assert from 'node:assert/strict';
import test from 'node:test';
import { proxyConfigChanges, type ProxyConfigFormEdits } from '../src/lib/proxy-config.ts';
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

test('works without a stored config', () => {
  const empty: ProxyConfigFormEdits = { websocket: false, force_https: false, max_body_size: '', custom_request_headers: [] };
  assert.equal(proxyConfigChanges(undefined, empty), undefined);
  assert.deepEqual(proxyConfigChanges(undefined, { ...empty, websocket: true }), { websocket: true });
});
