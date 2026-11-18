import assert from 'node:assert/strict';
import test from 'node:test';
import { importItems, initialRows, rowsMissingAddress } from '../src/lib/discovery.ts';
import type { DiscoveryCandidate } from '../src/lib/types.ts';

const candidates: DiscoveryCandidate[] = [
  { external_id: 'pve/pve1/qemu/101', name: 'web-01', addresses: [{ ip: '192.168.10.21', kind: 'private' }], suggested_address: '192.168.10.21' },
  { external_id: 'pve/pve1/qemu/102', name: 'db-01', addresses: [{ ip: '192.168.10.22', kind: 'private' }], suggested_address: '192.168.10.22', server_id: 's-1', server_name: 'db' },
  { external_id: 'pve/pve1/qemu/103', name: 'win-desktop', addresses: [] },
];

test('new machines with an address start selected; imported and address-less ones do not', () => {
  const rows = initialRows(candidates);
  assert.deepEqual(rows.map((r) => r.selected), [true, false, false]);
  assert.equal(rows[0].address, '192.168.10.21');
  assert.equal(rows[2].address, '');
});

test('only edited fields are sent and imported machines are never sent', () => {
  const rows = initialRows(candidates);
  rows[1].selected = true;
  rows[2].selected = true;
  rows[2].address = ' 10.0.0.9 ';
  rows[2].name = 'desktop';
  assert.deepEqual(importItems(rows, candidates), [
    { external_id: 'pve/pve1/qemu/101' },
    { external_id: 'pve/pve1/qemu/103', name: 'desktop', address: '10.0.0.9' },
  ]);
});

test('a selected machine without an address blocks the import', () => {
  const rows = initialRows(candidates);
  rows[2].selected = true;
  assert.deepEqual(rowsMissingAddress(rows).map((r) => r.external_id), ['pve/pve1/qemu/103']);
  rows[2].address = '10.0.0.9';
  assert.equal(rowsMissingAddress(rows).length, 0);
});
