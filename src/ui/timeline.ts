/**
 * The investigation timeline: events an examiner picks out of artifacts as
 * they go, each placed on a lane (a host, a user, anything they name), with
 * the row it came from kept so it can be opened again, and exported as a
 * report at any point.
 */
import type { Column, Row } from '../core/types';
import { parseIso } from '../core/binary';
import { compareTimes, fmt, formatTime, localize, neutralizeFormula } from './format';

/** An event's stored UTC time as it is shown in a zone. */
export const showTime = (t: string, zone: string) => {
  const d = parseIso(t);
  return d ? formatTime(d, zone) : t;
};

export interface TimelineSource {
  /** The navigator key of the artifact: a case artifact's id, or "r<id>" in a session. */
  key: string;
  fileName: string;
  path: string;
  parser: string;
  table: string | null;
  /** Index of the row among the artifact's parsed rows; parsing is deterministic, so it finds the row again. */
  rowIndex: number;
}

export interface TimelineEvent {
  id: string;
  /** ISO time, or null for an event the examiner could not date. */
  time: string | null;
  /** Which of the row's columns the time came from, if any. */
  timeField: string | null;
  lane: string;
  label: string;
  tag: string;
  note: string;
  source: TimelineSource;
  /** Every field of the row when it was added, as text. */
  data: Record<string, string>;
  added: string;
}

export interface Timeline {
  lanes: string[];
  events: TimelineEvent[];
}

export const EMPTY_TIMELINE: Timeline = { lanes: [], events: [] };

const isStr = (v: unknown): v is string => typeof v === 'string';

export function isTimeline(v: unknown): v is Timeline {
  if (!v || typeof v !== 'object') return false;
  const t = v as Timeline;
  return (
    Array.isArray(t.lanes) &&
    t.lanes.every(isStr) &&
    Array.isArray(t.events) &&
    t.events.every(
      (e) =>
        e &&
        isStr(e.id) &&
        (e.time === null || isStr(e.time)) &&
        isStr(e.lane) &&
        isStr(e.label) &&
        isStr(e.tag) &&
        isStr(e.note) &&
        e.source &&
        isStr(e.source.key) &&
        Number.isInteger(e.source.rowIndex) &&
        e.data &&
        typeof e.data === 'object',
    )
  );
}

/** Tags offered when adding an event: the ATT&CK tactics, and a few everyday ones. */
export const TAGS = [
  'Initial access',
  'Execution',
  'Persistence',
  'Privilege escalation',
  'Defense evasion',
  'Credential access',
  'Discovery',
  'Lateral movement',
  'Collection',
  'Command and control',
  'Exfiltration',
  'Impact',
  'Logon',
  'File activity',
  'USB / removable media',
  'Network',
  'Benign',
  'Note',
];

/** The row's date columns that hold a time, in column order. */
export function timeFields(columns: Column[], row: Row): Column[] {
  return columns.filter((c) => c.type === 'date' && row[c.key] instanceof Date && !Number.isNaN((row[c.key] as Date).getTime()));
}

// Fields that say what happened, most telling first, across the parsers.
const SUMMARY_KEYS = [
  'mapDescription',
  'MapDescription',
  'eventId',
  'provider',
  'ExecutableName',
  'executableName',
  'ExeInfo',
  'Executable',
  'DisplayText',
  'FileName',
  'fileName',
  'Name',
  'name',
  'targetPath',
  'TargetPath',
  'LocalPath',
  'Path',
  'path',
  'keyPath',
  'valueName',
  'valueData',
  'Url',
  'URL',
  'Title',
  'ParentPath',
  'Reason',
  'UpdateReasons',
];

/** A one-line label for a row: its most telling fields. */
export function summarise(row: Row, columns: Column[]): string {
  const keys = new Set(columns.map((c) => c.key));
  const parts: string[] = [];
  for (const k of SUMMARY_KEYS) {
    if (!keys.has(k)) continue;
    const v = fmt(row[k]).trim();
    if (!v || parts.includes(v)) continue;
    parts.push(k === 'eventId' ? `Event ${v}` : v);
    if (parts.length === 3) break;
  }
  // Nothing telling: the first two filled text fields (numbers and flags say little on their own).
  const fallback = columns
    .filter((c) => (c.type ?? 'str') === 'str' && c.key !== 'table')
    .map((c) => fmt(row[c.key]).trim())
    .filter(Boolean)
    .slice(0, 2);
  return (parts.length ? parts : fallback).join(' · ').slice(0, 200);
}

/** A lane to suggest: the row's computer or user when it names one. */
export function guessLane(row: Row, lanes: string[], last: string | null): string {
  for (const k of ['computer', 'Computer', 'MachineName', 'machineID', 'userName', 'UserName', 'User', 'Sid']) {
    const v = fmt(row[k]).trim();
    if (v) return lanes.find((l) => l.toLowerCase() === v.toLowerCase()) ?? v;
  }
  return last ?? lanes[0] ?? 'Host';
}

/** Every field of a row as text, for the event's record of what it saw. */
export function snapshot(row: Row, columns: Column[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of columns) {
    const v = fmt(row[c.key]);
    if (v !== '') out[c.label] = v;
  }
  return out;
}

/** Undated events first (they need attention), then by time, then by when they were added. */
export function sortEvents(events: TimelineEvent[]): TimelineEvent[] {
  return [...events].sort((a, b) => {
    if (a.time === null || b.time === null) return a.time === b.time ? a.added.localeCompare(b.added) : a.time === null ? -1 : 1;
    // To the 100ns tick; a time saved before seven digits were kept still orders.
    const [ta, tb] = [parseIso(a.time), parseIso(b.time)];
    return (ta && tb ? compareTimes(ta, tb) : a.time.localeCompare(b.time)) || a.added.localeCompare(b.added);
  });
}

/** "+2h 13m" between two events. */
export function gap(from: string, to: string): string {
  let s = Math.round((Date.parse(to) - Date.parse(from)) / 1000);
  if (s <= 0) return s === 0 ? 'same time' : '';
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts = d ? [`${d}d`, `${h}h`] : h ? [`${h}h`, `${m}m`] : m ? [`${m}m`, `${sec}s`] : [`${sec}s`];
  return `+${parts.join(' ')}`;
}

const CSV_COLS = ['Time (UTC)', 'Lane', 'Tag', 'Label', 'Note', 'Artifact', 'Path', 'Parser', 'Table', 'Row', 'Time field'];

export function timelineCsv(t: Timeline): string {
  const cell = (s: string) => {
    const v = neutralizeFormula(s);
    return /[",\r\n]/.test(v) || v !== s ? `"${v.replaceAll('"', '""')}"` : v;
  };
  const rows = sortEvents(t.events).map((e) =>
    [
      e.time ?? '',
      e.lane,
      e.tag,
      e.label,
      e.note,
      e.source.fileName,
      e.source.path,
      e.source.parser,
      e.source.table ?? '',
      String(e.source.rowIndex + 1),
      e.timeField ?? '',
    ]
      .map(cell)
      .join(','),
  );
  return [CSV_COLS.join(','), ...rows].join('\r\n');
}

const esc = (s: string) =>
  s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');

export interface ReportInfo {
  caseName: string;
  customer: string;
  reference: string;
  examiner: string;
  notes: string;
}

/**
 * A self-contained HTML report: case details, a summary by lane and tag, the
 * timeline, and each event's recorded fields. Every piece of evidence text is
 * escaped: it is attacker-controlled and the report will be opened in a browser.
 */
export function timelineReport(t: Timeline, info: ReportInfo, generated = new Date(), zone = 'UTC'): string {
  const at = (s: string) => showTime(s, zone);
  const events = sortEvents(t.events);
  const count = (key: (e: TimelineEvent) => string) => {
    const m = new Map<string, number>();
    for (const e of events) m.set(key(e), (m.get(key(e)) ?? 0) + 1);
    return [...m].sort((a, b) => b[1] - a[1]);
  };
  const dated = events.filter((e) => e.time);
  const span = dated.length ? `${at(dated[0].time ?? '')} → ${at(dated[dated.length - 1].time ?? '')}` : 'no dated events';
  let lastDay = '';
  let lastTime: string | null = null;
  const items = events
    .map((e) => {
      const day = e.time ? at(e.time).slice(0, 10) : 'Undated';
      const header = day !== lastDay ? `<li class="day">${esc(day)}</li>` : '';
      lastDay = day;
      const g = e.time && lastTime ? gap(lastTime, e.time) : '';
      if (e.time) lastTime = e.time;
      const fields = Object.entries(e.data)
        .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(localize(v, zone))}</td></tr>`)
        .join('');
      return `${header}<li class="ev">
  <div class="when">${esc(e.time ? at(e.time) : 'Undated')}${g ? `<span class="gap">${esc(g)}</span>` : ''}</div>
  <div class="card"><div class="top"><span class="lane">${esc(e.lane)}</span>${e.tag ? `<span class="tag">${esc(e.tag)}</span>` : ''}</div>
  <div class="label">${esc(e.label)}</div>
  ${e.note ? `<div class="note">${esc(e.note)}</div>` : ''}
  <div class="src">${esc(e.source.path || e.source.fileName)} · ${esc(e.source.parser)}${e.source.table ? ` · ${esc(e.source.table)}` : ''} · row ${e.source.rowIndex + 1}${e.timeField ? ` · time from ${esc(e.timeField)}` : ''}</div>
  <details><summary>Recorded fields</summary><table>${fields}</table></details></div></li>`;
    })
    .join('\n');
  const list = (rows: Array<[string, number]>) => rows.map(([k, n]) => `<li>${esc(k || '(none)')} <b>${n}</b></li>`).join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Timeline — ${esc(info.caseName || 'Investigation')}</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--dim:#57606a;--line:#d0d7de;--accent:#2f81f7;--card:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--dim:#8b949e;--line:#30363d;--accent:#9fef00;--card:#161b22}}
body{margin:0;padding:32px 16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto}h1{margin:0 0 4px;font-size:24px}.meta{color:var(--dim);margin:0 0 24px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0 0 24px}dt{color:var(--dim)}dd{margin:0}
.sums{display:flex;flex-wrap:wrap;gap:32px;margin:0 0 28px}.sums ul{list-style:none;margin:6px 0 0;padding:0}.sums b{color:var(--accent);margin-left:6px}
ol{list-style:none;margin:0;padding:0 0 0 18px;border-left:2px solid var(--line)}
.day{margin:22px 0 8px -26px;padding-left:26px;font-weight:600;color:var(--dim)}
.ev{position:relative;margin:0 0 14px;padding-left:18px}.ev::before{content:"";position:absolute;left:-25px;top:18px;width:10px;height:10px;border-radius:50%;background:var(--accent);border:2px solid var(--bg)}
.ev::after{content:"";position:absolute;left:-15px;top:23px;width:24px;border-top:2px solid var(--line)}
.when{font:12px ui-monospace,Consolas,monospace;color:var(--dim);margin-left:8px}.gap{margin-left:10px;color:var(--accent)}
.card{margin:4px 0 0 8px;padding:10px 12px;background:var(--card);border:1px solid var(--line);border-radius:8px}
.top{display:flex;gap:8px;margin-bottom:4px}.lane,.tag{font-size:11px;padding:1px 8px;border-radius:10px;border:1px solid var(--line)}.tag{border-color:var(--accent);color:var(--accent)}
.label{font-weight:600}.note{margin-top:6px;white-space:pre-wrap}.src{margin-top:6px;font-size:12px;color:var(--dim);overflow-wrap:anywhere}
details{margin-top:6px}summary{cursor:pointer;color:var(--dim);font-size:12px}table{border-collapse:collapse;margin-top:6px;font-size:12px;width:100%}
th,td{text-align:left;vertical-align:top;padding:3px 8px;border-top:1px solid var(--line)}th{color:var(--dim);font-weight:500;white-space:nowrap}td{overflow-wrap:anywhere;font-family:ui-monospace,Consolas,monospace}
@media print{details{display:none}.card{break-inside:avoid}}
</style></head><body><main>
<h1>Investigation timeline</h1>
<p class="meta">Generated ${esc(formatTime(generated, zone))} by 4NSEC · ${events.length} event${events.length === 1 ? '' : 's'} · ${esc(span)}</p>
<p class="meta">All times are shown in ${esc(zone === 'UTC' ? 'UTC' : `${zone} (UTC offset on each time)`)}.</p>
<dl><dt>Case</dt><dd>${esc(info.caseName || '—')}</dd><dt>Customer</dt><dd>${esc(info.customer || '—')}</dd><dt>Reference</dt><dd>${esc(info.reference || '—')}</dd><dt>Examiner</dt><dd>${esc(info.examiner || '—')}</dd>${info.notes ? `<dt>Notes</dt><dd>${esc(info.notes)}</dd>` : ''}</dl>
<div class="sums"><div>By lane<ul>${list(count((e) => e.lane))}</ul></div><div>By tag<ul>${list(count((e) => e.tag))}</ul></div></div>
<ol>
${items}
</ol></main></body></html>`;
}
