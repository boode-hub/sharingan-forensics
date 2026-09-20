import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { Column, Row } from '../core/types';
import { fmt } from './format';

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

/**
 * Matches one cell against one column filter expression.
 *
 * Plain text is a case-insensitive substring match, which is what an analyst
 * reaches for most of the time. The operators exist because substring alone
 * cannot express the two questions forensics actually asks of a large table:
 * "only this window of time" and "only these ids".
 *
 *   4624          contains "4624"
 *   !svchost      does NOT contain "svchost"
 *   >=2019-02-13  on or after that instant — dates compare as time, not text
 *   <100          numerically less than 100
 *   =4624         exactly equal, so 4624 does not also match 14624
 */
export function matches(value: unknown, expr: string): boolean {
  const e = expr.trim();
  if (!e) return true;
  if (e.startsWith('!')) return !matches(value, e.slice(1));

  const op = /^(>=|<=|>|<|=)(.*)$/.exec(e);
  if (!op) return fmt(value).toLowerCase().includes(e.toLowerCase());

  const [, operator, raw] = op;
  const operand = raw.trim();
  if (!operand) return true;

  // Compare as time when the cell is a date and as number when both sides are
  // numeric; fall back to text so the operators still behave sensibly on
  // strings rather than silently matching nothing.
  let a: number | string;
  let b: number | string;
  if (value instanceof Date) {
    // Cells are displayed as ISO UTC, so a bare "2019-02-13T15:00" must mean
    // 15:00 UTC too. JavaScript would otherwise read a date-time with no zone
    // as LOCAL time, so the same text would select a different set of events
    // depending on the analyst's machine — unacceptable in forensic output.
    const hasZone = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(operand);
    const t = Date.parse(hasZone || !operand.includes('T') ? operand : `${operand}Z`);
    if (Number.isNaN(t)) return false;
    a = value.getTime();
    b = t;
  } else if (typeof value === 'number' && operand !== '' && !Number.isNaN(Number(operand))) {
    a = value;
    b = Number(operand);
  } else {
    a = fmt(value).toLowerCase();
    b = operand.toLowerCase();
  }

  if (operator === '=') return a === b;
  if (operator === '>') return a > b;
  if (operator === '<') return a < b;
  if (operator === '>=') return a >= b;
  return a <= b;
}

export function Grid({
  columns,
  rows,
  filter,
  partial,
  onSelect,
}: {
  columns: Column[];
  rows: Row[];
  filter: string;
  /** The parser stopped early, so these rows are not the whole artifact. */
  partial?: boolean;
  onSelect: (r: Row) => void;
}) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [active, setActive] = useState(-1);
  const [colFilters, setColFilters] = useState<Record<string, string>>({});
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [pickerOpen, setPickerOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Every column is shown unless the analyst hides it. Nothing is withheld by
  // default: in a forensic tool, a column you cannot see is evidence you do
  // not know exists.
  const visible = useMemo(() => columns.filter((c) => !hidden.has(c.key)), [columns, hidden]);

  // A new artifact has different columns, so drop stale hides and filters.
  const colKey = columns.map((c) => c.key).join('|');
  useEffect(() => {
    setHidden(new Set());
    setColFilters({});
    setSort(null);
    setActive(-1);
  }, [colKey]);

  const activeCols = useMemo(
    () => Object.entries(colFilters).filter(([, v]) => v.trim()),
    [colFilters],
  );

  const view = useMemo(() => {
    const q = filter.trim().toLowerCase();
    // The global box matches across every column, including hidden ones — an
    // analyst searching for a path should not have to know which column holds
    // it. Per-column filters then narrow that, ANDed together.
    let out = q
      ? rows.filter((r) => columns.some((c) => fmt(r[c.key]).toLowerCase().includes(q)))
      : rows;
    if (activeCols.length) {
      out = out.filter((r) => activeCols.every(([key, expr]) => matches(r[key], expr)));
    }
    if (sort) {
      out = [...out].sort((a, b) => compare(a[sort.key], b[sort.key]) * sort.dir);
    }
    return out;
  }, [rows, columns, filter, sort, activeCols]);

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

  const toggleSort = (key: string) =>
    setSort((s) => (s?.key !== key ? { key, dir: 1 } : s.dir === 1 ? { key, dir: -1 } : null));

  const totalW = IDX_W + visible.reduce((n, c) => n + widthOf(c), 0);
  const filtered = activeCols.length > 0 || filter.trim().length > 0;

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
          <button type="button" className="colbtn warn" onClick={() => setColFilters({})}>
            Clear {activeCols.length} filter{activeCols.length > 1 ? 's' : ''}
          </button>
        )}
        <span className="hint">
          Filter a column: <code>4624</code> contains · <code>=4624</code> exact ·{' '}
          <code>!x</code> excludes · <code>&gt;=2019-02-13</code> from that time (UTC)
        </span>
      </div>

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
                  placeholder={c.type === 'date' ? '>=2019-02-13' : c.type === 'num' ? '=4624' : 'filter'}
                  onChange={(e) => setColFilters((f) => ({ ...f, [c.key]: e.target.value }))}
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
                  className={`grid-row${vi.index === active ? ' on' : ''}`}
                  style={{ transform: `translateY(${vi.start}px)`, height: ROW_H, width: totalW }}
                  onClick={() => {
                    setActive(vi.index);
                    onSelect(r);
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
          ? ` — filtered${activeCols.length ? ` on ${activeCols.map(([k]) => columns.find((c) => c.key === k)?.label ?? k).join(', ')}` : ''}`
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
