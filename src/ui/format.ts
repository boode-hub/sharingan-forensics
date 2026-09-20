import type { Column, Row } from '../core/types';

/** Display form of a cell. `null`/`undefined` render empty — missing is not zero. */
export function fmt(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? 'invalid date' : v.toISOString();
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

const needsQuote = /[",\r\n]/;

export function toCsv(columns: Column[], rows: Row[]): string {
  const cell = (v: unknown) => {
    const s = fmt(v);
    return needsQuote.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
  };
  const head = columns.map((c) => cell(c.label)).join(',');
  const body = rows.map((r) => columns.map((c) => cell(r[c.key])).join(','));
  return [head, ...body].join('\r\n');
}

export function toJson(rows: Row[]): string {
  return JSON.stringify(rows, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
}

/** Triggers a client-side download. Nothing is uploaded — this is the only export path. */
export function download(filename: string, text: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function bytes(n: number): string {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${i === 0 ? n : n.toFixed(1)} ${u[i]}`;
}
