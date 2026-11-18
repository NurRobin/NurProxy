import type { DiscoveryCandidate, DiscoveredAddressKind } from './types';

/** One row of the import table: what the operator selected and edited. */
export interface ImportRow {
  external_id: string;
  selected: boolean;
  name: string;
  address: string;
}

/** Address kinds the agent can plausibly reach; the rest stay visible but are never preselected. */
const USABLE: ReadonlySet<DiscoveredAddressKind> = new Set(['private', 'shared', 'public']);

export function isUsableAddress(kind: DiscoveredAddressKind): boolean {
  return USABLE.has(kind);
}

/**
 * Initial rows for a discovery result: every machine that is not imported yet
 * and has a detected address starts selected; machines without an address
 * start unselected until the operator types one.
 */
export function initialRows(candidates: DiscoveryCandidate[]): ImportRow[] {
  return candidates.map((c) => ({
    external_id: c.external_id,
    selected: !c.server_id && !!c.suggested_address,
    name: c.name,
    address: c.suggested_address ?? '',
  }));
}

/** Selected rows that cannot be imported because no address is set. */
export function rowsMissingAddress(rows: ImportRow[]): ImportRow[] {
  return rows.filter((r) => r.selected && r.address.trim() === '');
}

/**
 * The import request items. Name and address are only sent when the operator
 * changed them, so the server applies the candidate's own values otherwise.
 * Already imported machines are never sent.
 */
export function importItems(rows: ImportRow[], candidates: DiscoveryCandidate[]): { external_id: string; name?: string; address?: string }[] {
  const byId = new Map(candidates.map((c) => [c.external_id, c]));
  const items: { external_id: string; name?: string; address?: string }[] = [];
  for (const r of rows) {
    const c = byId.get(r.external_id);
    if (!r.selected || !c || c.server_id) continue;
    const item: { external_id: string; name?: string; address?: string } = { external_id: r.external_id };
    const name = r.name.trim();
    const address = r.address.trim();
    if (name && name !== c.name) item.name = name;
    if (address && address !== (c.suggested_address ?? '')) item.address = address;
    items.push(item);
  }
  return items;
}

/** Sync interval choices for a source, in seconds (0 = manual only). */
export const SYNC_INTERVALS = [0, 900, 3600, 6 * 3600, 24 * 3600] as const;
