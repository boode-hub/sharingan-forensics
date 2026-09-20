import { useVirtualizer } from '@tanstack/react-virtual';
import { useMemo, useRef, useState } from 'react';
import type { Column, Row } from '../core/types';
import { fmt } from './format';

const ROW_H = 26;

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

export function Grid({
  columns,
  rows,
  filter,
  onSelect,
}: {
  columns: Column[];
  rows: Row[];
  filter: string;
  onSelect: (r: Row) => void;
}) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [active, setActive] = useState(-1);
  const scrollRef = useRef<HTMLDivElement>(null);

  const visible = useMemo(() => columns.filter((c) => !c.secondary), [columns]);

  const view = useMemo(() => {
    const q = filter.trim().toLowerCase();
    // Substring match across every column, including hidden ones — an analyst
    // searching for a path should not have to know which column holds it.
    let out = q
      ? rows.filter((r) => columns.some((c) => fmt(r[c.key]).toLowerCase().includes(q)))
      : rows;
    if (sort) {
      out = [...out].sort((a, b) => compare(a[sort.key], b[sort.key]) * sort.dir);
    }
    return out;
  }, [rows, columns, filter, sort]);

  const virt = useVirtualizer({
    count: view.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_H,
    overscan: 20,
    // The scroll element measures 0 until a ResizeObserver fires. Without a
    // non-zero starting rect the grid renders an empty body while the footer
    // reports the real row count. Assume a screenful up front; the observer
    // corrects it on first paint.
    // ponytail: if the virtualizer ever records a 0 height (grid mounted inside
    // a collapsed panel, or a tab that never paints) it stays empty until the
    // observer fires again. Call virt.measure() on a 0 -> non-zero transition
    // if the grid is ever put behind an accordion or a background tab.
    initialRect: { width: 1200, height: 800 },
  });

  const toggle = (key: string) =>
    setSort((s) => (s?.key !== key ? { key, dir: 1 } : s.dir === 1 ? { key, dir: -1 } : null));

  return (
    <div className="grid">
      <div className="grid-head">
        <div className="cell idx">#</div>
        {visible.map((c) => (
          <button
            type="button"
            key={c.key}
            className="cell th"
            onClick={() => toggle(c.key)}
            title={`Sort by ${c.label}`}
          >
            {c.label}
            <span className="sort">
              {sort?.key === c.key ? (sort.dir === 1 ? '▲' : '▼') : ''}
            </span>
          </button>
        ))}
      </div>

      <div className="grid-scroll" ref={scrollRef}>
        <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
          {virt.getVirtualItems().map((vi) => {
            const r = view[vi.index];
            return (
              <div
                key={vi.key}
                className={`grid-row${vi.index === active ? ' on' : ''}`}
                style={{ transform: `translateY(${vi.start}px)`, height: ROW_H }}
                onClick={() => {
                  setActive(vi.index);
                  onSelect(r);
                }}
              >
                <div className="cell idx">{vi.index + 1}</div>
                {visible.map((c) => (
                  <div
                    key={c.key}
                    className={`cell${c.type === 'num' ? ' num' : ''}`}
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

      <div className="grid-foot">
        {view.length.toLocaleString()} of {rows.length.toLocaleString()} rows
        {filter.trim() && ' (filtered)'}
      </div>
    </div>
  );
}
