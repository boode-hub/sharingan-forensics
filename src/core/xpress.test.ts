import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { magic } from './binary';
import { XpressError, unwrapMam, xpressHuffmanDecompress } from './xpress';

/**
 * Builds a valid Xpress Huffman chunk by hand. Encoding is not something the
 * app ever needs, so this lives in the test: it exists purely to give the
 * decoder a stream whose correct output is known from the [MS-XCA] rules
 * rather than from the decoder's own behaviour.
 */
function chunk(lengths: Record<number, number>, bits: string): Uint8Array {
  const table = new Uint8Array(256);
  for (const [s, len] of Object.entries(lengths)) {
    const sym = Number(s);
    // Two symbols per byte, low nibble first.
    if (sym % 2 === 0) table[sym >> 1] |= len;
    else table[sym >> 1] |= len << 4;
  }
  // The bitstream is read as 16-bit little-endian words, MSB first.
  const padded = bits.padEnd(Math.ceil(bits.length / 16) * 16, '0');
  const words: number[] = [];
  for (let i = 0; i < padded.length; i += 16) {
    const w = Number.parseInt(padded.slice(i, i + 16), 2);
    words.push(w & 0xff, w >> 8);
  }
  // Pad with empty words so the reader's 32-bit lookahead never runs dry.
  return Uint8Array.from([...table, ...words, 0, 0, 0, 0, 0, 0, 0, 0]);
}

describe('xpressHuffmanDecompress', () => {
  it('decodes literal-only output', () => {
    // All 256 literals at 8 bits is a complete code, so each literal's canonical
    // code is simply its own byte value.
    const lengths: Record<number, number> = {};
    for (let i = 0; i < 256; i++) lengths[i] = 8;
    const text = 'HELLO';
    const bits = [...text].map((c) => c.charCodeAt(0).toString(2).padStart(8, '0')).join('');
    const out = xpressHuffmanDecompress(chunk(lengths, bits), text.length);
    expect(new TextDecoder().decode(out)).toBe(text);
  });

  it('expands an overlapping back-reference', () => {
    // Two symbols at 1 bit each: 'A' (65) gets code 0, symbol 256 gets code 1.
    // Symbol 256 means length nibble 0 and distance width 0, i.e. distance 1,
    // length 3 — an overlapping run that must read bytes it is still writing.
    const out = xpressHuffmanDecompress(chunk({ 65: 1, 256: 1 }, '01'), 4);
    expect(new TextDecoder().decode(out)).toBe('AAAA');
  });

  it('rejects an invalid prefix code instead of emitting garbage', () => {
    expect(() => xpressHuffmanDecompress(chunk({ 65: 1 }, '1'), 4)).toThrow(XpressError);
  });

  it('passes a non-MAM buffer through untouched', () => {
    const raw = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(unwrapMam(raw)).toBe(raw);
  });

  it('round-trips the committed MAM fixture back to the plain one', () => {
    const dir = new URL('../../fixtures/prefetch/', import.meta.url);
    const plain = new Uint8Array(readFileSync(new URL('NOTEPAD.EXE-AAAAAAAA.pf', dir)));
    const packed = new Uint8Array(readFileSync(new URL('NOTEPAD.EXE-MAMTEST.pf', dir)));
    expect(unwrapMam(packed)).toEqual(plain);
  });

  it('decompresses the committed multi-chunk sample without desync', () => {
    // The real Win10 Prefetch corpus sample: 6 chunks, declared size 380690.
    // Its 403 filename strings must stay intact, which is where the old decoder
    // desynchronised and produced 592 corrupted strings.
    const dir = new URL('../../fixtures/prefetch/', import.meta.url);
    const path = new URL('DEVENV.EXE-854D7862.pf', dir);
    const buf = new Uint8Array(readFileSync(path));

    expect(magic(buf, 'MAM')).toBe(true);
    const declared = (buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24)) >>> 0;
    expect(declared).toBe(380690);

    const out = unwrapMam(buf);
    expect(out.length).toBe(380690);

    const version = out[0] | (out[1] << 8) | (out[2] << 16) | (out[3] << 24);
    expect(version).toBe(30);
    expect(magic(out, 'SCCA', 4)).toBe(true);

    const hash = new DataView(out.buffer, out.byteOffset + 76, 4).getUint32(0, true);
    expect(hash.toString(16).toUpperCase().padStart(8, '0')).toBe('854D7862');

    // File-metrics entry count at header offset 88 says 403; that many
    // NUL-terminated UTF-16LE strings must split the filename region cleanly.
    const entryCount = new DataView(out.buffer, out.byteOffset + 88, 4).getUint32(0, true);
    expect(entryCount).toBe(403);

    const stringsOffset = new DataView(out.buffer, out.byteOffset + 100, 4).getUint32(0, true);
    const stringsSize = new DataView(out.buffer, out.byteOffset + 104, 4).getUint32(0, true);
    expect(stringsOffset + stringsSize).toBeLessThanOrEqual(out.length);

    const strings: string[] = [];
    let pos = stringsOffset;
    const end = stringsOffset + stringsSize;
    const dv = new DataView(out.buffer, out.byteOffset, out.length);
    while (pos < end) {
      let strEnd = pos;
      while (strEnd + 1 < end && dv.getUint16(strEnd, true) !== 0) strEnd += 2;
      strings.push(new TextDecoder('utf-16le').decode(out.subarray(pos, strEnd)));
      pos = strEnd + 2;
    }
    expect(strings.length).toBe(403);
    // Every path must be clean readable text: no stray C0-control glyphs and
    // the last one a real path rather than the single garbage char `ʩ`.
    for (const s of strings) {
      expect(s.length).toBeGreaterThan(0);
      expect(/[\u0000-\u001f\u007f-\u009f]/.test(s)).toBe(false);
    }
    expect(strings[strings.length - 1].length).toBeGreaterThan(2);
  });
});

/**
 * Synthetic streams prove the rules; only a real file proves the implementation.
 * This one is read from the local machine and never committed — real Prefetch
 * names executables the analyst ran. Skipped wherever the file is absent,
 * including CI.
 */
const REAL_PF = 'C:/Windows/Prefetch/ANTIGRAVITY.EXE-6247EA31.pf';

describe.skipIf(!existsSync(REAL_PF))('real Windows Prefetch', () => {
  it('decompresses a MAM container to a valid SCCA body', () => {
    const buf = new Uint8Array(readFileSync(REAL_PF));
    expect(magic(buf, 'MAM')).toBe(true);

    const out = unwrapMam(buf);
    const declared = (buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24)) >>> 0;
    expect(out.length).toBe(declared);

    // A correctly decompressed Prefetch body is version 30/31 then "SCCA".
    const version = out[0] | (out[1] << 8) | (out[2] << 16) | (out[3] << 24);
    expect([23, 26, 30, 31]).toContain(version);
    expect(magic(out, 'SCCA', 4)).toBe(true);
  });
});
