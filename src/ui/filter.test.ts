import { describe, expect, it } from 'vitest';
import { matches } from './query';
import { toCsv, toJson } from './format';

describe('column filter matching', () => {
  it('matches a substring case-insensitively', () => {
    expect(matches('C:\\Windows\\System32', 'system')).toBe(true);
    expect(matches('C:\\Windows\\System32', 'temp')).toBe(false);
  });

  it('treats an empty expression as no filter', () => {
    expect(matches(null, '')).toBe(true);
    expect(matches('anything', '   ')).toBe(true);
  });

  it('negates with a leading bang', () => {
    expect(matches('svchost.exe', '!svchost')).toBe(false);
    expect(matches('cmd.exe', '!svchost')).toBe(true);
  });

  it('compares numbers numerically, not as text', () => {
    // The whole point: as text, "9" would sort after "100".
    expect(matches(9, '<100')).toBe(true);
    expect(matches(9, '>100')).toBe(false);
    expect(matches(4624, '=4624')).toBe(true);
  });

  it('does not let = match a longer number containing it', () => {
    expect(matches(14624, '=4624')).toBe(false);
    // ...whereas a plain substring deliberately would.
    expect(matches(14624, '4624')).toBe(true);
  });

  it('compares dates as instants rather than strings', () => {
    const d = new Date('2019-02-13T15:15:04.135Z');
    expect(matches(d, '>=2019-02-13')).toBe(true);
    expect(matches(d, '>=2019-02-14')).toBe(false);
    expect(matches(d, '<2020-01-01')).toBe(true);
  });

  it('rejects a date filter that is not a parsable date', () => {
    expect(matches(new Date('2019-02-13T00:00:00Z'), '>=notadate')).toBe(false);
  });

  it('falls back to text comparison for strings', () => {
    expect(matches('beta', '>alpha')).toBe(true);
    expect(matches('alpha', '>beta')).toBe(false);
  });

  it('treats a bare operator with no operand as no filter', () => {
    expect(matches(5, '>=')).toBe(true);
  });

  it('renders null as empty, so it never matches a real substring', () => {
    expect(matches(null, 'x')).toBe(false);
  });
});

describe('date filters are interpreted as UTC', () => {
  // Cells render as ISO UTC, so a bare date-time in a filter must mean UTC.
  // Left to JavaScript's default it would be read as local time, and the same
  // filter text would select different events on different machines.
  const d = new Date('2019-02-13T15:00:00.000Z');

  it('treats a bare date-time as UTC, not local', () => {
    expect(matches(d, '>=2019-02-13T15:00')).toBe(true);
    expect(matches(d, '>2019-02-13T15:00')).toBe(false);
    expect(matches(d, '<2019-02-13T15:01')).toBe(true);
  });

  it('still honours an explicit zone when one is given', () => {
    expect(matches(d, '>=2019-02-13T15:00:00Z')).toBe(true);
    // 16:00+01:00 is 15:00Z, so the instant is equal and > must be false.
    expect(matches(d, '>2019-02-13T16:00:00+01:00')).toBe(false);
  });

  it('handles a date with no time component', () => {
    expect(matches(d, '>=2019-02-13')).toBe(true);
    expect(matches(d, '>=2019-02-14')).toBe(false);
  });
});

describe('CSV export is safe to open in a spreadsheet', () => {
  const cols = [{ key: 'v', label: 'Value' }];

  it('neutralises every formula lead character', () => {
    for (const payload of ["=cmd|'/c calc'!A1", '+1+1', '-2+3', '@SUM(1)', '\tx', '\rx']) {
      const line = toCsv(cols, [{ v: payload }]).split('\r\n')[1];
      expect(line.startsWith('"\''), `unsafe for ${JSON.stringify(payload)}`).toBe(true);
    }
  });

  it('leaves ordinary values untouched', () => {
    const line = toCsv(cols, [{ v: 'C:/Windows/notepad.exe' }]).split(/\r\n/)[1];
    expect(line).toBe('C:/Windows/notepad.exe');
  });

  it('still quotes and escapes embedded quotes and commas', () => {
    expect(toCsv(cols, [{ v: 'a,b"c' }]).split('\r\n')[1]).toBe('"a,b""c"');
  });

  it('keeps the JSON export byte-faithful, so exact content is recoverable', () => {
    expect(JSON.parse(toJson([{ v: "=cmd|'/c calc'!A1" }]))[0].v).toBe("=cmd|'/c calc'!A1");
  });
});
