import { describe, expect, it } from 'vitest';
import type { Column } from '../core/types';
import { gap, guessLane, isTimeline, snapshot, sortEvents, summarise, timeFields, timelineCsv, timelineReport, type TimelineEvent } from './timeline';

const cols: Column[] = [
  { key: 'timeCreated', label: 'Time Created', type: 'date' },
  { key: 'eventId', label: 'Event Id', type: 'num' },
  { key: 'provider', label: 'Provider', type: 'str' },
  { key: 'computer', label: 'Computer', type: 'str' },
  { key: 'mapDescription', label: 'Map Description', type: 'str' },
  { key: 'writtenTime', label: 'Written Time', type: 'date' },
];
const row = {
  timeCreated: new Date('2026-09-20T14:02:03.000Z'),
  eventId: 4624,
  provider: 'Microsoft-Windows-Security-Auditing',
  computer: 'WS-042',
  mapDescription: 'Successful logon',
  writtenTime: null,
};

const ev = (id: string, time: string | null, extra: Partial<TimelineEvent> = {}): TimelineEvent => ({
  id,
  time,
  timeField: 'Time Created',
  lane: 'WS-042',
  label: 'Successful logon · Event 4624',
  tag: 'Logon',
  note: '',
  source: { key: 'a1', fileName: 'Security.evtx', path: 'C/Windows/System32/winevt/Logs/Security.evtx', parser: 'Windows Event Log', table: null, rowIndex: 41 },
  data: { 'Event Id': '4624' },
  added: `2026-09-25T00:00:0${id}.000Z`,
  ...extra,
});

describe('adding an event', () => {
  it('offers only the date columns that hold a time', () => {
    expect(timeFields(cols, row).map((c) => c.key)).toEqual(['timeCreated']);
  });

  it('labels a row by its most telling fields and suggests its computer as the lane', () => {
    expect(summarise(row, cols)).toBe('Successful logon · Event 4624 · Microsoft-Windows-Security-Auditing');
    expect(guessLane(row, ['ws-042'], null)).toBe('ws-042');
    expect(guessLane({}, [], 'Laptop')).toBe('Laptop');
    expect(guessLane({}, [], null)).toBe('Host');
  });

  it('records every non-empty field by its label', () => {
    expect(snapshot(row, cols)).toEqual({
      'Time Created': '2026-09-20T14:02:03.000Z',
      'Event Id': '4624',
      Provider: 'Microsoft-Windows-Security-Auditing',
      Computer: 'WS-042',
      'Map Description': 'Successful logon',
    });
  });
});

describe('the timeline', () => {
  it('puts undated events first, then orders by time', () => {
    const sorted = sortEvents([ev('1', '2026-09-20T15:00:00.000Z'), ev('2', null), ev('3', '2026-09-20T14:00:00.000Z')]);
    expect(sorted.map((e) => e.id)).toEqual(['2', '3', '1']);
  });

  it('describes the gap between events', () => {
    expect(gap('2026-09-20T14:00:00Z', '2026-09-20T16:13:05Z')).toBe('+2h 13m');
    expect(gap('2026-09-20T14:00:00Z', '2026-09-22T15:00:00Z')).toBe('+2d 1h');
    expect(gap('2026-09-20T14:00:00Z', '2026-09-20T14:00:42Z')).toBe('+42s');
    expect(gap('2026-09-20T14:00:00Z', '2026-09-20T14:00:00Z')).toBe('same time');
  });

  it('accepts what it stores and rejects anything else', () => {
    expect(isTimeline({ lanes: ['WS-042'], events: [ev('1', null)] })).toBe(true);
    expect(isTimeline({ lanes: [1], events: [] })).toBe(false);
    expect(isTimeline({ lanes: [], events: [{ ...ev('1', null), source: { key: 'a', rowIndex: 1.5 } }] })).toBe(false);
  });
});

describe('exports', () => {
  it('writes CSV with formula-looking evidence neutralised', () => {
    const csv = timelineCsv({ lanes: [], events: [ev('1', '2026-09-20T14:00:00.000Z', { label: '=cmd|calc!A1' })] });
    const [head, line] = csv.split('\r\n');
    expect(head).toBe('Time (UTC),Lane,Tag,Label,Note,Artifact,Path,Parser,Table,Row,Time field');
    expect(line).toBe("2026-09-20T14:00:00.000Z,WS-042,Logon,\"'=cmd|calc!A1\",,Security.evtx,C/Windows/System32/winevt/Logs/Security.evtx,Windows Event Log,,42,Time Created");
  });

  it('writes an HTML report with every piece of evidence escaped', () => {
    const html = timelineReport(
      { lanes: ['WS-042'], events: [ev('1', '2026-09-20T14:00:00.000Z', { label: '<script>alert(1)</script>', note: 'a & b' })] },
      { caseName: 'ACME', customer: 'ACME Corp', reference: 'IR-7', examiner: 'A', notes: '' },
      new Date('2026-09-26T00:00:00Z'),
    );
    expect(html).not.toContain('<script>alert');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('a &amp; b');
    expect(html).toContain('row 42');
    expect(html).toContain('Generated 2026-09-26T00:00:00.000Z');
  });
});
