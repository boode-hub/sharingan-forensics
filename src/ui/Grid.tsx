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
  });

  const toggle = (key: string) =>
    setSort((s) => (s?.key !== key ? { key, dir: 1 } : s.dir === 1 ? { key, dir: -1 } : null));

  return (
    <div className="grid">
      <div className="grid-scroll" ref={scrollRef}>
        <table style={{ width: '100%' }}>
          <thead>
            <tr>
              <th className="num" style={{ width: 64 }}>
                #
              </th>
              {visible.map((c) => (
                <th
                  key={c.key}
                  onClick={() => toggle(c.key)}
                  title={`Sort by ${c.label}`}
                  aria-sort={
                    sort?.key === c.key ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'
                  }
                >
                  {c.label}
                  <span className="sort">
                    {sort?.key === c.key ? (sort.dir === 1 ? '▲' : '▼') : ''}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody style={{ height: virt.getTotalSize(), position: 'relative' }}>
            {virt.getVirtualItems().map((vi) => {
              const r = view[vi.index];
              return (
                <tr
                  key={vi.key}
                  className={vi.index === active ? 'on' : ''}
                  style={{ position: 'absolute', top: vi.start, height: ROW_H, width: '100%' }}
                  onClick={() => {
                    setActive(vi.index);
                    onSelect(r);
                  }}
                >
                  <td className="num idx">{vi.index + 1}</td>
                  {visible.map((c) => (
                    <td key={c.key} className={c.type === 'num' ? 'num' : undefined}>
                      {fmt(r[c.key])}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="grid-foot">
        {view.length.toLocaleString()} of {rows.length.toLocaleString()} rows
        {filter.trim() && ' (filtered)'}
      </div>
    </div>
  );
}
