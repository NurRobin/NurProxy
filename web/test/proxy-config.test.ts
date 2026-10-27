import assert from 'node:assert/strict';
import test from 'node:test';
import { proxyConfigForSave } from '../src/lib/proxy-config.ts';
import type { ProxyConfig } from '../src/lib/types.ts';

const stored = {
  websocket: true,
  max_body_size: '10m',
  custom_request_headers: { 'X-Old': '1' },
  custom_response_headers: { 'X-Frame-Options': 'DENY' },
  upstream_scheme: 'https',
  tls_policy: 'self-acme',
  basic_auth: { username: 'admin', password: '$2a$10$hash' },
  ip_allowlist: ['10.0.0.0/8'],
  raw_config: { backend: 'caddy', content: '{}' },
  timeout_read: 30,
} as ProxyConfig;

const edits = {
  websocket: false,
  force_https: true,
  max_body_size: '20m',
  custom_request_headers: [{ key: ' X-New ', value: '2' }, { key: '', value: 'ignored' }],
};

test('keeps stored settings the form does not show (#163)', () => {
  const body = proxyConfigForSave(stored, edits);
  assert.deepEqual(body, {
    ...stored,
    websocket: false,
    force_https: true,
    max_body_size: '20m',
    custom_request_headers: { 'X-New': '2' },
  });
});

test('does not modify the stored config', () => {
  const before = structuredClone(stored);
  const body = proxyConfigForSave(stored, edits);
  (body.basic_auth as { username: string }).username = 'changed';
  assert.deepEqual(stored, before);
});

test('emptied fields are sent as null so the API clears them', () => {
  const body = proxyConfigForSave(stored, { ...edits, max_body_size: '', custom_request_headers: [] });
  assert.equal(body.max_body_size, null);
  assert.equal(body.custom_request_headers, null);
  assert.deepEqual(body.basic_auth, stored.basic_auth);
});

test('works without a stored config', () => {
  assert.deepEqual(proxyConfigForSave(undefined, edits), {
    websocket: false,
    force_https: true,
    max_body_size: '20m',
    custom_request_headers: { 'X-New': '2' },
  });
});
