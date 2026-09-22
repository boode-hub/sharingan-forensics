/**
 * Preferences and saved filters, kept in this browser only.
 *
 * Nothing here is evidence and nothing leaves the machine. Storage can be
 * unavailable - a private window, blocked site data - so every read falls back
 * to a default and every write reports whether it worked, rather than letting
 * a preference break the page.
 */

const PREFIX = '4ensics.';

export function read<T>(key: string, fallback: T, valid: (v: unknown) => v is T): T {
  try {
    const raw = localStorage.getItem(PREFIX + key);
    if (raw === null) return fallback;
    const parsed: unknown = JSON.parse(raw);
    return valid(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

export function write(key: string, value: unknown): boolean {
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export type DetailPosition = 'bottom' | 'left' | 'right';

export const isPosition = (v: unknown): v is DetailPosition =>
  v === 'bottom' || v === 'left' || v === 'right';

export const isColour = (v: unknown): v is string =>
  typeof v === 'string' && /^#[0-9a-f]{6}$/i.test(v);

/** A filter an analyst chose to keep: the search, the column filters and any rule. */
export interface SavedFilter {
  name: string;
  /** The kind of artifact it was made for; column names only mean something there. */
  parserId: string;
  search: string;
  columns: Record<string, string>;
  sigma: string | null;
}

export function isSavedList(v: unknown): v is SavedFilter[] {
  return (
    Array.isArray(v) &&
    v.every(
      (f) =>
        f &&
        typeof f === 'object' &&
        typeof f.name === 'string' &&
        typeof f.parserId === 'string' &&
        typeof f.search === 'string' &&
        f.columns !== null &&
        typeof f.columns === 'object' &&
        Object.values(f.columns).every((x) => typeof x === 'string') &&
        (f.sigma === null || typeof f.sigma === 'string'),
    )
  );
}

/**
 * Adds a filter, replacing one of the same name for the same kind of artifact
 * so that saving again updates it instead of piling up copies.
 */
export function upsert(list: SavedFilter[], f: SavedFilter): SavedFilter[] {
  return [...list.filter((x) => !(x.name === f.name && x.parserId === f.parserId)), f].sort((a, b) =>
    a.name.localeCompare(b.name),
  );
}
