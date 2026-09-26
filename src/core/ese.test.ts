import { describe, expect, it } from 'vitest';
import { eseDecompress, oaDate } from './ese';
import { xpressDecompress } from './xpress';

describe('ESE column compression', () => {
  it('expands plain LZ77 Xpress: the [MS-XCA] 3.1 example, "abc" 100 times', () => {
    const packed = Uint8Array.of(0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01);
    expect(new TextDecoder().decode(xpressDecompress(packed, 300))).toBe('abc'.repeat(100));
    // As ESE stores it: a 0x18 lead byte and the uncompressed size first.
    expect(new TextDecoder().decode(eseDecompress(Uint8Array.of(0x18, 0x2c, 0x01, ...packed)))).toBe('abc'.repeat(100));
  });

  it('unpacks 7-bit values, least significant bits first, after the lead byte', () => {
    // 'a' 0x61, 'b' 0x62, 'c' 0x63 packed 7 bits each: 0x61 | 0x62 << 7 | 0x63 << 14 = 0x18f161.
    expect(new TextDecoder().decode(eseDecompress(Uint8Array.of(0x10, 0x61, 0xf1, 0x18)))).toBe('abc');
  });
});

describe('OLE Automation dates', () => {
  const ole = (d: number) => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setFloat64(0, d, true);
    return oaDate(b)?.toISOString();
  };
  it('counts days from 1899-12-30, the fraction a time of day even before it, as DateTime.FromOADate does', () => {
    expect(ole(0)).toBe('1899-12-30T00:00:00.000Z');
    expect(ole(45000.5)).toBe('2023-03-15T12:00:00.000Z');
    expect(ole(-1.25)).toBe('1899-12-29T06:00:00.000Z');
    expect(ole(3e6)).toBe(undefined);
  });
});
