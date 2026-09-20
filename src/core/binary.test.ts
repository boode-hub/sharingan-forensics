import { describe, expect, it } from 'vitest';
import { Cursor, ascii, dosDateTime, filetime, guid, magic, utf16 } from './binary';

describe('filetime', () => {
  it('converts a known tick count', () => {
    // 2020-01-01T00:00:00Z == 132223104000000000 ticks since 1601-01-01.
    expect(filetime(132223104000000000n)?.toISOString()).toBe('2020-01-01T00:00:00.000Z');
  });
  it('treats 0 and max as unset rather than year 1601', () => {
    expect(filetime(0n)).toBeNull();
    expect(filetime(0xffffffffffffffffn)).toBeNull();
  });
  it('surfaces an implausible-but-valid tick count instead of hiding it', () => {
    expect(filetime(0x7fffffffffffffffn)?.getUTCFullYear()).toBe(30828);
  });
});

describe('dosDateTime', () => {
  it('unpacks a known FAT date/time', () => {
    // 2020-01-01 12:00:00 -> date=(40<<9)|(1<<5)|1, time=(12<<11)
    expect(dosDateTime(20513, 24576)?.toISOString()).toBe('2020-01-01T12:00:00.000Z');
  });
  it('rejects impossible month/day instead of rolling over', () => {
    expect(dosDateTime((40 << 9) | (13 << 5) | 1, 0)).toBeNull();
    expect(dosDateTime(0, 0)).toBeNull();
  });
});

describe('guid', () => {
  it('applies Microsoft mixed-endian byte order', () => {
    const b = Uint8Array.from({ length: 16 }, (_, i) => i);
    expect(guid(b)).toBe('03020100-0504-0706-0809-0a0b0c0d0e0f');
  });
  it('returns empty on a short buffer rather than throwing', () => {
    expect(guid(new Uint8Array(4))).toBe('');
  });
});

describe('string decoding', () => {
  it('truncates UTF-16LE at the first NUL', () => {
    const b = new Uint8Array([0x41, 0, 0x42, 0, 0, 0, 0x43, 0]);
    expect(utf16(b)).toBe('AB');
  });
  it('decodes cp1252 high bytes', () => {
    expect(ascii(new Uint8Array([0xe9, 0x41]))).toBe('éA');
  });
});

describe('Cursor', () => {
  const buf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

  it('reads little-endian integers sequentially', () => {
    const c = new Cursor(buf);
    expect(c.u8()).toBe(1);
    expect(c.u16()).toBe(0x0302);
    expect(c.u32()).toBe(0x07060504);
    expect(c.pos).toBe(7);
    expect(c.overran).toBe(false);
  });

  it('flags overrun and returns zero instead of throwing', () => {
    const c = new Cursor(buf);
    c.seek(6);
    expect(c.u32()).toBe(0);
    expect(c.overran).toBe(true);
  });

  it('short-reads take() at EOF', () => {
    const c = new Cursor(buf);
    c.seek(6);
    expect(c.take(10).length).toBe(2);
    expect(c.overran).toBe(true);
  });

  it('reads NUL-terminated UTF-16 and advances past the terminator', () => {
    const c = new Cursor(new Uint8Array([0x41, 0, 0x42, 0, 0, 0, 0x5a, 0]));
    expect(c.utf16z()).toBe('AB');
    expect(c.pos).toBe(6);
    expect(c.utf16z()).toBe('Z');
    expect(c.overran).toBe(true); // no terminator on the second string
  });

  it('respects byteOffset on a subarray view', () => {
    const c = new Cursor(buf.subarray(4));
    expect(c.u32()).toBe(0x08070605);
  });
});

describe('magic', () => {
  const pf = new Uint8Array([0x1e, 0, 0, 0, 0x53, 0x43, 0x43, 0x41]);
  it('matches a string signature at an offset', () => {
    expect(magic(pf, 'SCCA', 4)).toBe(true);
    expect(magic(pf, 'SCCA', 0)).toBe(false);
  });
  it('matches a byte signature', () => {
    expect(magic(pf, [0x1e, 0x00])).toBe(true);
  });
  it('is false rather than throwing when the buffer is too short', () => {
    expect(magic(new Uint8Array([0x1e]), 'SCCA', 4)).toBe(false);
  });
});
