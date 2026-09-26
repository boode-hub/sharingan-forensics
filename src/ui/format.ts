import { createContext } from 'react';
import { iso, parseIso, preciseDate, subTicks } from '../core/binary';
import type { Column, Row } from '../core/types';
import { TICKS } from './fields';

/**
 * Where times are shown: 'UTC', or an IANA zone ('Africa/Cairo'). Everything
 * is read and kept in UTC; this only changes what is displayed, and every
 * displayed time carries its offset, so no time on screen is ever zone-less.
 */
export const ZoneContext = createContext('UTC');

const formatters = new Map<string, Intl.DateTimeFormat>();

/** The zone's wall clock at an instant, and its offset from UTC in minutes. */
function wall(ms: number, zone: string) {
  let f = formatters.get(zone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: zone,
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    formatters.set(zone, f);
  }
  const p: Record<string, string> = {};
  for (const x of f.formatToParts(ms)) p[x.type] = x.value;
  const utc = new Date(0);
  utc.setUTCFullYear(+p.year, +p.month - 1, +p.day);
  utc.setUTCHours(+p.hour, +p.minute, +p.second);
  return { p, offset: Math.round((utc.getTime() - Math.floor(ms / 1000) * 1000) / 60000) };
}

/** The UTC offset of a zone at an instant, in minutes. */
export const offsetMinutes = (ms: number, zone: string) => (zone === 'UTC' ? 0 : wall(ms, zone).offset);

/**
 * A time as it is shown and exported: ISO 8601 with all seven fractional
 * digits and its zone, 2024-05-01T10:00:05.1234567Z in UTC or
 * 2024-05-01T13:00:05.1234567+03:00 elsewhere.
 */
export function formatTime(d: Date, zone = 'UTC'): string {
  const ms = d.getTime();
  if (Number.isNaN(ms)) return 'invalid date';
  if (zone === 'UTC') return iso(d);
  const { p, offset } = wall(ms, zone);
  const frac = String(((ms % 1000) + 1000) % 1000).padStart(3, '0') + String(subTicks(d)).padStart(4, '0');
  const a = Math.abs(offset);
  const off = `${offset < 0 ? '-' : '+'}${String(Math.floor(a / 60)).padStart(2, '0')}:${String(a % 60).padStart(2, '0')}`;
  return `${p.year.padStart(4, '0')}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}.${frac}${off}`;
}

/** Times written into text (event data, property values) are UTC with a Z; shown in the zone like any other. */
const ISO_IN_TEXT = /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z/g;
export const localize = (s: string, zone: string) =>
  zone === 'UTC' ? s : s.replace(ISO_IN_TEXT, (m) => {
    const d = parseIso(m);
    return d ? formatTime(d, zone) : m;
  });

/**
 * A time typed by the analyst. One with a zone (Z, +03:00) means that zone;
 * one without means the zone times are shown in, so what is typed matches
 * what is on screen. Never JavaScript's own parsing, which reads
 * "2024-05-01 14:00" as the examiner machine's local time.
 */
export function parseTime(text: string, zone = 'UTC'): Date | null {
  const m = /^(\d{4})[-/](\d{2})[-/](\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i.exec(text.trim());
  if (!m) return null;
  const f = (m[7] ?? '').padEnd(7, '0');
  const t = new Date(0);
  t.setUTCFullYear(+m[1], +m[2] - 1, +m[3]);
  t.setUTCHours(+(m[4] ?? 0), +(m[5] ?? 0), +(m[6] ?? 0), +f.slice(0, 3));
  // setUTCFullYear rolls 2024-02-30 into March; a date that is not one is refused.
  if (t.getUTCDate() !== +m[3] || +(m[4] ?? 0) > 23 || +(m[5] ?? 0) > 59 || +(m[6] ?? 0) > 59) return null;
  let ms = t.getTime();
  if (m[8]) {
    const z = m[8].toUpperCase();
    if (z !== 'Z') {
      const [, sign, hh, mm] = /^([+-])(\d{2}):?(\d{2})$/.exec(z) as RegExpExecArray;
      ms -= (sign === '-' ? -1 : 1) * (+hh * 60 + +mm) * 60000;
    }
  } else if (zone !== 'UTC') {
    // The wall clock in the zone: its offset at the guess, then again at the
    // answer, which settles the hour either side of a daylight-saving change.
    const guess = ms - offsetMinutes(ms, zone) * 60000;
    ms -= offsetMinutes(guess, zone) * 60000;
  }
  return preciseDate(ms, Number(f.slice(3)));
}

/** Orders two times to the 100ns tick. */
export const compareTimes = (a: Date, b: Date) => a.getTime() - b.getTime() || subTicks(a) - subTicks(b);

/**
 * Display form of a cell, in the zone times are shown in. `null`/`undefined`
 * render empty — missing is not zero.
 */
export function fmt(v: unknown, zone = 'UTC'): string {
  if (v === null || v === undefined) return '';
  if (v instanceof Date) return formatTime(v, zone);
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'object') return JSON.stringify(v);
  return localize(String(v), zone);
}

const needsQuote = /[",\r\n]/;

/**
 * Leading characters that make Excel, LibreOffice and Google Sheets treat a
 * cell as a formula rather than as text.
 */
const FORMULA_LEAD = /^[=+\-@\t\r]/;

/**
 * Neutralises spreadsheet formula injection.
 *
 * Evidence is attacker-controlled: malware chooses its own file names,
 * registry value names and event payloads. A value such as
 * `=cmd|'/c calc.exe'!A1` executes when the analyst opens the export, and
 * exporting to CSV then opening it in Excel is routine work, so the value
 * cannot be handed through untouched.
 *
 * The cell is prefixed with an apostrophe and quoted; spreadsheets strip the
 * apostrophe on display and treat the remainder as literal text. That alters
 * the exported bytes by one character, so the JSON export is deliberately left
 * byte-faithful for when exact content matters.
 */
export function neutralizeFormula(s: string): string {
  return FORMULA_LEAD.test(s) ? `'${s}` : s;
}

export function toCsv(columns: Column[], rows: Row[]): string {
  const cell = (v: unknown) => {
    const raw = fmt(v);
    const s = neutralizeFormula(raw);
    return needsQuote.test(s) || FORMULA_LEAD.test(raw)
      ? `"${s.replaceAll('"', '""')}"`
      : s;
  };
  const head = columns.map((c) => cell(c.label)).join(',');
  const body = rows.map((r) => columns.map((c) => cell(r[c.key])).join(','));
  return [head, ...body].join('\r\n');
}

export function toJson(rows: Row[]): string {
  // `this[k]` is the value before Date's own toJSON cut it to milliseconds.
  return JSON.stringify(
    rows,
    function (this: Record<string, unknown>, k, v) {
      if (k === TICKS) return undefined;
      const raw = this[k];
      return raw instanceof Date ? formatTime(raw) : typeof v === 'bigint' ? v.toString() : v;
    },
    2,
  );
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
