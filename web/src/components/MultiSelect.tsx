import { useState } from 'react';
import { Search } from 'lucide-react';

export interface MultiSelectItem {
  id: string;
  label: string;
  meta?: string;
}

interface Props {
  items: MultiSelectItem[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  /** Show the search box once there are more than this many items. */
  searchThreshold?: number;
  maxHeightClass?: string;
  emptyHint?: string;
}

/**
 * A checkbox multi-select with a search box (past a threshold) and a
 * select-all/deselect-all toggle that operates on the currently filtered set.
 * Used wherever zones are picked (setup, adopt, add-provider).
 */
export default function MultiSelect({
  items,
  selected,
  onChange,
  searchThreshold = 6,
  maxHeightClass = 'max-h-52',
  emptyHint = 'Nothing to show.',
}: Props) {
  const [query, setQuery] = useState('');
  const q = query.trim().toLowerCase();
  const filtered = q
    ? items.filter((i) => i.label.toLowerCase().includes(q) || i.meta?.toLowerCase().includes(q))
    : items;

  const allFilteredSelected = filtered.length > 0 && filtered.every((i) => selected.has(i.id));

  function toggle(id: string) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    onChange(next);
  }

  function toggleAllFiltered() {
    const next = new Set(selected);
    if (allFilteredSelected) filtered.forEach((i) => next.delete(i.id));
    else filtered.forEach((i) => next.add(i.id));
    onChange(next);
  }

  const showSearch = items.length > searchThreshold;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-fg-faint">
          {selected.size} of {items.length} selected
        </span>
        {filtered.length > 0 && (
          <button type="button" onClick={toggleAllFiltered} className="text-xs font-medium text-accent hover:underline">
            {allFilteredSelected ? 'Deselect all' : 'Select all'}{q && ' matching'}
          </button>
        )}
      </div>

      {showSearch && (
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={`Search ${items.length} items…`}
            className="block w-full rounded-lg border border-border bg-surface py-2 pl-9 pr-3 text-sm text-fg placeholder:text-fg-faint focus:border-accent focus-visible:outline-none focus:ring-2 focus:ring-accent/30"
          />
        </div>
      )}

      <div className={`${maxHeightClass} space-y-1 overflow-y-auto rounded-lg border border-border bg-surface-2 p-2`}>
        {filtered.length === 0 ? (
          <p className="px-3 py-2 text-sm text-fg-faint">{q ? 'No matches.' : emptyHint}</p>
        ) : (
          filtered.map((item) => (
            <label
              key={item.id}
              className={`flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 transition-colors ${selected.has(item.id) ? 'bg-accent-soft' : 'hover:bg-surface-3'}`}
            >
              <input type="checkbox" checked={selected.has(item.id)} onChange={() => toggle(item.id)} className="h-4 w-4 accent-[var(--accent)]" />
              <span className="text-sm font-medium text-fg">{item.label}</span>
              {item.meta && <span className="ml-auto font-mono text-xs text-fg-faint">{item.meta}</span>}
            </label>
          ))
        )}
      </div>
    </div>
  );
}
