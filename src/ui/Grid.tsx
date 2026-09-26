import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { Column, Row } from '../core/types';
import { fmt } from './format';
import { compileQuery, QueryError, type Predicate } from './query';

const ROW_H = 26;
const HEAD_H = 26;
const IDX_W = 62;

/** Fixed width per column type. Predictable beats clever, and it lets the row
 *  be wider than the viewport so a 14-column table scrolls instead of crushing. */
function widthOf(c: Column): number {
  if (c.type === 'num') return 120;
  if (c.type === 'date') return 195;
  if (c.type === 'bool') return 90;
  return 230;
}

/** Sorts nulls last regardless of direction — "not recorded" is never a value. */
function compare(a: unknown, b: unknown): number {
  const an = a === null || a === undefined;
  const bn = b === null || b === undefined;
  if (an || bn) return an && bn ? 0 : an ? 1 : -1;
  if (a instanceof Date && b instanceof Date) return a.getTime() - b.getTime();
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'bigint' && typeof b === 'bigint') return a < b ? -1 : a > b ? 1 : 0;
  return fmt(a).localeCompare(fmt(b), undefined, { numeric: true });
}

/** Compiles a filter, turning a mistake into a message rather than a crash. */
function compile(
  text: string,
  columns: Column[],
  defaultField?: string,
): { test: Predicate; error: string | null } {
  try {
    return { test: compileQuery(text, columns, defaultField), error: null };
  } catch (e) {
    // A filter that cannot be read matches nothing, and says why. Showing every
    // row instead would present an unfiltered table as if it were the answer.
    return { test: () => false, error: e instanceof QueryError ? e.message : String(e) };
  }
}

export function Grid({
  columns,
  rows,
  filter,
  colFilters,
  onColFilters,
  extra,
  extraLabel,
  partial,
  onSelect,
  onContext,
  focus,
  marked,
}: {
  columns: Column[];
  rows: Row[];
  /** The search box, in the filter language. */
  filter: string;
  /** Per-column filters, keyed by column key. Owned by the caller so they can be saved. */
  colFilters: Record<string, string>;
  onColFilters: (f: Record<string, string>) => void;
  /** A further test every row must pass, such as a Sigma rule. */
  extra?: Predicate | null;
  /** What `extra` is, for the footer. */
  extraLabel?: string;
  /** The parser stopped early, so these rows are not the whole artifact. */
  partial?: boolean;
  onSelect: (r: Row) => void;
  /** A right-click on a row, with where it happened. */
  onContext?: (r: Row, x: number, y: number) => void;
  /** A row to scroll to and select, such as one a timeline event came from. */
  focus?: Row | null;
  /** Rows to mark, such as those already on the timeline. */
  marked?: Set<Row>;
}) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [active, setActive] = useState(-1);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [pickerOpen, setPickerOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Every column is shown unless the analyst hides it. Nothing is withheld by
  // default: in a forensic tool, a column you cannot see is evidence you do
  // not know exists.
  const visible = useMemo(() => columns.filter((c) => !hidden.has(c.key)), [columns, hidden]);

  // A new artifact has different columns, so drop stale hides and sorting.
  const colKey = columns.map((c) => c.key).join('|');
  useEffect(() => {
    setHidden(new Set());
    setSort(null);
    setActive(-1);
  }, [colKey]);

  const activeCols = useMemo(
    () => Object.entries(colFilters).filter(([, v]) => v.trim()),
    [colFilters],
  );

  const global = useMemo(() => compile(filter, columns), [filter, columns]);
  const perColumn = useMemo(
    () => activeCols.map(([key, expr]) => ({ key, ...compile(expr, columns, key) })),
    [activeCols, columns],
  );
  const errors = [
    global.error ? `Search: ${global.error}` : null,
    ...perColumn
      .filter((c) => c.error)
      .map((c) => `${columns.find((x) => x.key === c.key)?.label ?? c.key}: ${c.error}`),
  ].filter(Boolean) as string[];

  const view = useMemo(() => {
    // The search box matches across every column, including hidden ones — an
    // analyst searching for a path should not have to know which column holds
    // it. Column filters and any rule then narrow that, all ANDed together.
    let out = filter.trim() ? rows.filter(global.test) : rows;
    if (perColumn.length) out = out.filter((r) => perColumn.every((c) => c.test(r)));
    if (extra) out = out.filter(extra);
    if (sort) {
      out = [...out].sort((a, b) => compare(a[sort.key], b[sort.key]) * sort.dir);
    }
    return out;
  }, [rows, filter, global, perColumn, extra, sort]);

  const virt = useVirtualizer({
    count: view.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_H,
    overscan: 20,
    // The scroll element measures 0 until a ResizeObserver fires. Without a
    // non-zero starting rect the grid renders an empty body while the footer
    // reports the real row count.
    initialRect: { width: 1200, height: 800 },
  });

  // Bring a row asked for into view and select it; it may be sorted or
  // filtered anywhere, so it is looked up in what is showing.
  useEffect(() => {
    if (!focus) return;
    const i = view.indexOf(focus);
    if (i < 0) return;
    setActive(i);
    // Measured from the DOM, not the virtualizer: a grid that has just mounted
    // still carries its placeholder rect, and the details panel opening in the
    // same commit shrinks it, so scrollToIndex would clamp to the top.
    const el = scrollRef.current;
    const body = el?.querySelector<HTMLElement>('.grid-inner > div:last-child');
    if (el && body) {
      const shown = el.clientHeight - body.offsetTop;
      el.scrollTop = i * ROW_H - Math.max(0, (shown - ROW_H) / 2);
    }
    // Only a new row to focus should move the view, not every re-render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus]);

  const toggleSort = (key: string) =>
    setSort((s) => (s?.key !== key ? { key, dir: 1 } : s.dir === 1 ? { key, dir: -1 } : null));

  const totalW = IDX_W + visible.reduce((n, c) => n + widthOf(c), 0);
  const filtered = activeCols.length > 0 || filter.trim().length > 0 || !!extra;

  return (
    <div className="grid">
      <div className="grid-bar">
        <button type="button" className="colbtn" onClick={() => setPickerOpen((o) => !o)}>
          Columns {columns.length - hidden.size}/{columns.length}
        </button>
        {hidden.size > 0 && (
          <button type="button" className="colbtn" onClick={() => setHidden(new Set())}>
            Show all
          </button>
        )}
        {activeCols.length > 0 && (
          <button type="button" className="colbtn warn" onClick={() => onColFilters({})}>
            Clear {activeCols.length} column filter{activeCols.length > 1 ? 's' : ''}
          </button>
        )}
        <span className="hint">
          <code>4624 OR 4625</code> · <code>admin AND -svchost</code> ·{' '}
          <code>CommandLine contains "-enc"</code> · <code>EventId=4624</code> ·{' '}
          <code>&gt;=2019-02-13</code> · <code>Image:*\cmd.exe</code>
        </span>
      </div>

      {errors.length > 0 && (
        <div className="query-error" role="alert">
          {errors.map((e) => (
            <div key={e}>Filter not understood — {e}. No rows are shown until it is fixed.</div>
          ))}
        </div>
      )}

      {pickerOpen && (
        <div className="colpick">
          {columns.map((c) => (
            <label key={c.key}>
              <input
                type="checkbox"
                checked={!hidden.has(c.key)}
                onChange={() =>
                  setHidden((h) => {
                    const n = new Set(h);
                    if (n.has(c.key)) n.delete(c.key);
                    else n.add(c.key);
                    return n;
                  })
                }
              />
              {c.label}
            </label>
          ))}
        </div>
      )}

      <div className="grid-scroll" ref={scrollRef}>
        {/* One scrolling surface so the header, the filter row and the body
            stay aligned horizontally; the first two are sticky vertically. */}
        <div className="grid-inner" style={{ width: totalW }}>
          <div className="grid-head" style={{ height: HEAD_H }}>
            <div className="cell idx" style={{ width: IDX_W }}>
              #
            </div>
            {visible.map((c) => (
              <button
                type="button"
                key={c.key}
                className="cell th"
                style={{ width: widthOf(c) }}
                onClick={() => toggleSort(c.key)}
                title={`Sort by ${c.label}`}
              >
                {c.label}
                <span className="sort">
                  {sort?.key === c.key ? (sort.dir === 1 ? '▲' : '▼') : ''}
                </span>
              </button>
            ))}
          </div>

          <div className="grid-filters" style={{ top: HEAD_H }}>
            <div className="cell idx" style={{ width: IDX_W }} />
            {visible.map((c) => (
              <div className="cell" key={c.key} style={{ width: widthOf(c) }}>
                <input
                  value={colFilters[c.key] ?? ''}
                  aria-label={`Filter ${c.label}`}
                  placeholder={
                    c.type === 'date' ? '>=2019-02-13' : c.type === 'num' ? '4624 OR 4625' : 'filter'
                  }
                  onChange={(e) => onColFilters({ ...colFilters, [c.key]: e.target.value })}
                />
              </div>
            ))}
          </div>

          <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
            {virt.getVirtualItems().map((vi) => {
              const r = view[vi.index];
              return (
                <div
                  key={vi.key}
                  className={`grid-row${vi.index === active ? ' on' : ''}${marked?.has(r) ? ' marked' : ''}`}
                  style={{ transform: `translateY(${vi.start}px)`, height: ROW_H, width: totalW }}
                  onClick={() => {
                    setActive(vi.index);
                    onSelect(r);
                  }}
                  onContextMenu={(e) => {
                    if (!onContext) return;
                    e.preventDefault();
                    setActive(vi.index);
                    onSelect(r);
                    onContext(r, e.clientX, e.clientY);
                  }}
                >
                  <div className="cell idx" style={{ width: IDX_W }}>
                    {vi.index + 1}
                  </div>
                  {visible.map((c) => (
                    <div
                      key={c.key}
                      className={`cell${c.type === 'num' ? ' num' : ''}`}
                      style={{ width: widthOf(c) }}
                      title={fmt(r[c.key])}
                    >
                      {fmt(r[c.key])}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid-foot">
        Showing <strong>{view.length.toLocaleString()}</strong> of{' '}
        {rows.length.toLocaleString()} rows
        {filtered
          ? ` — filtered${
              [
                filter.trim() ? 'by search' : '',
                activeCols.length
                  ? `on ${activeCols.map(([k]) => columns.find((c) => c.key === k)?.label ?? k).join(', ')}`
                  : '',
                extra ? `by ${extraLabel ?? 'rule'}` : '',
              ]
                .filter(Boolean)
                .map((s) => ` ${s}`)
                .join(',') || ''
            }`
          : partial
            ? ''
            : ' — everything in the file'}
        {/* Never let the footer imply completeness when the parse stopped
            early. An analyst reading "everything in the file" over a truncated
            artifact is worse than showing nothing at all. */}
        {partial && <span className="partial"> — PARTIAL, not the whole artifact: see warnings above</span>}
        {hidden.size > 0 && ` · ${hidden.size} column${hidden.size > 1 ? 's' : ''} hidden`}
      </div>
    </div>
  );
}
