import { describe, expect, it } from 'vitest';
import type { Column } from '../core/types';
import { fmt, toCsv } from './format';

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
    expect(fmt(new Date('2020-01-01T00:00:00Z'))).toBe('2020-01-01T00:00:00.000Z');
    expect(fmt(new Date('nope'))).toBe('invalid date');
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
