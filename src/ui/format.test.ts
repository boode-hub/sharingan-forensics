import { describe, expect, it } from 'vitest';
import type { Column } from '../core/types';
import { filetime } from '../core/binary';
import { dateKeys, packTicks, TICKS, unpackTicks } from './fields';
import { compareTimes, fmt, formatTime, localize, parseTime, toCsv, toJson } from './format';

const cols: Column[] = [
  { key: 'path', label: 'Original Path' },
  { key: 'when', label: 'Deleted On', type: 'date' },
  { key: 'size', label: 'Size', type: 'num' },
];

describe('fmt', () => {
  it('renders missing values as empty, never as 0 or "null"', () => {
    expect(fmt(null)).toBe('');
    expect(fmt(undefined)).toBe('');
    expect(fmt(0)).toBe('0');
  });
  it('renders dates as ISO and flags an invalid one', () => {
    expect(fmt(new Date('2020-01-01T00:00:00Z'))).toBe('2020-01-01T00:00:00.0000000Z');
    expect(fmt(new Date('nope'))).toBe('invalid date');
  });
  it('shows a time in another zone with its offset, daylight saving included', () => {
    const d = filetime(133498044001234567n) as Date; // 2024-01-15T15:00:00.1234567Z
    expect(fmt(d)).toBe('2024-01-15T15:00:00.1234567Z');
    expect(fmt(d, 'America/New_York')).toBe('2024-01-15T10:00:00.1234567-05:00');
    expect(formatTime(new Date('2024-07-15T15:00:00Z'), 'America/New_York')).toBe('2024-07-15T11:00:00.0000000-04:00');
    expect(formatTime(new Date('2024-07-15T15:00:00Z'), 'Asia/Kolkata')).toBe('2024-07-15T20:30:00.0000000+05:30');
  });
  it('shows times written into text in the same zone, and leaves them alone in UTC', () => {
    const s = 'Created: 2024-01-15T15:00:00.1234567Z, Modified: 2024-07-15T15:00:00.0000000Z';
    expect(fmt(s)).toBe(s);
    expect(localize(s, 'America/New_York')).toBe('Created: 2024-01-15T10:00:00.1234567-05:00, Modified: 2024-07-15T11:00:00.0000000-04:00');
  });
  it('renders bigint without precision loss', () => {
    expect(fmt(12345678901234567890n)).toBe('12345678901234567890');
  });
});

describe('toCsv', () => {
  it('quotes commas, quotes and newlines so a path cannot break the row', () => {
    const csv = toCsv(cols, [
      { path: 'C:\\a,b\\c "quoted"\\d\r\ne.txt', when: null, size: 5 },
    ]);
    const [head, ...body] = csv.split('\r\n');
    expect(head).toBe('Original Path,Deleted On,Size');
    // The embedded CRLF splits the raw text, but it stays inside one quoted field.
    expect(body.join('\r\n')).toBe('"C:\\a,b\\c ""quoted""\\d\r\ne.txt",,5');
  });

  it('leaves an ordinary row unquoted', () => {
    expect(toCsv(cols, [{ path: 'C:\\x.txt', when: null, size: 1 }]).split('\r\n')[1]).toBe(
      'C:\\x.txt,,1',
    );
  });
});

describe('times typed by the analyst', () => {
  it('reads a time without a zone in the zone shown, never the machine\'s own', () => {
    expect(parseTime('2024-05-01 14:00')?.toISOString()).toBe('2024-05-01T14:00:00.000Z');
    expect(parseTime('2024-05-01T14:00:05.1234567')?.toISOString()).toBe('2024-05-01T14:00:05.123Z');
    expect(parseTime('2024-07-15 11:00', 'America/New_York')?.toISOString()).toBe('2024-07-15T15:00:00.000Z');
    expect(parseTime('2024-01-15 10:00', 'America/New_York')?.toISOString()).toBe('2024-01-15T15:00:00.000Z');
    expect(parseTime('2024-05-01', 'Asia/Kolkata')?.toISOString()).toBe('2024-04-30T18:30:00.000Z');
  });
  it('honours a zone written with the time', () => {
    expect(parseTime('2024-05-01T17:00+03:00', 'America/New_York')?.toISOString()).toBe('2024-05-01T14:00:00.000Z');
    expect(parseTime('2024-05-01T14:00Z', 'Asia/Kolkata')?.toISOString()).toBe('2024-05-01T14:00:00.000Z');
  });
  it('refuses what is not a time rather than guessing', () => {
    expect(parseTime('2024-02-30')).toBeNull();
    expect(parseTime('May 1 2024')).toBeNull();
    expect(parseTime('2024-05-01 25:00')).toBeNull();
  });
  it('orders to the 100ns tick', () => {
    const a = filetime(133498044001234567n) as Date;
    const b = filetime(133498044001234568n) as Date;
    expect(compareTimes(a, b)).toBeLessThan(0);
    expect(compareTimes(b, a)).toBeGreaterThan(0);
  });
});

describe('ticks across the worker', () => {
  it('survive a structured clone, as a worker message is made', () => {
    const rows = [{ t: filetime(133498044001234567n), n: 1 }, { t: new Date(0), n: 2 }, { t: null, n: 3 }];
    packTicks(rows, dateKeys([{ key: 't', label: 'T', type: 'date' }]));
    const lost = structuredClone(rows.map(({ t, n }) => ({ t, n })));
    expect(fmt(lost[0].t)).toBe('2024-01-15T15:00:00.1230000Z');
    const back = structuredClone(rows);
    unpackTicks(back);
    expect(back.map((r) => fmt(r.t))).toEqual(['2024-01-15T15:00:00.1234567Z', '1970-01-01T00:00:00.0000000Z', '']);
  });
  it('are in the JSON export, and the carrier is not', () => {
    const json = JSON.parse(toJson([{ t: filetime(133498044001234567n), [TICKS]: { t: 4567 } }]));
    expect(json).toEqual([{ t: '2024-01-15T15:00:00.1234567Z' }]);
  });
});
