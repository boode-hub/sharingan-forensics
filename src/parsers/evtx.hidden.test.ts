/**
 * A second event record hidden inside another.
 *
 * The DanderSpritz eventlogedit module conceals an event by writing a complete
 * record into the slack of the record before it: the outer record's size
 * covers both, so a reader that stops at the end of the first BinXML stream
 * never sees the second. EvtxECmd looks for the 0x2a2a record signature within
 * fifteen bytes of where the stream ended and reports what it finds as
 * HiddenRecord; this checks we do the same, and that we do not claim to have
 * found one when there is nothing there.
 */
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { evtx } from './evtx';

const CHUNK_SIZE = 65536;
const RECORDS_START = 512;
const HEADER_SIZE = 4096;
const NAME_OFFSET = 1000;

/** A string-table entry: next-in-bucket, hash, character count, chars, NUL. */
function stringEntry(str: string): Uint8Array {
  const out = new Uint8Array(8 + str.length * 2 + 2);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, 0, true);
  dv.setUint16(4, 0x1234, true);
  dv.setUint16(6, str.length, true);
  for (let i = 0; i < str.length; i++) dv.setUint16(8 + i * 2, str.charCodeAt(i), true);
  return out;
}

/**
 * The smallest BinXML that renders to something: one empty element whose name
 * comes from the chunk's string table. Enough for the record to decode, which
 * is the precondition for looking at its slack at all.
 */
function payload(): Uint8Array {
  const out = new Uint8Array(32);
  const dv = new DataView(out.buffer);
  let p = 0;
  out[p++] = 0x0f; // start of stream
  out[p++] = 1;
  out[p++] = 1;
  out[p++] = 0;
  out[p++] = 0x01; // open start element, no attributes
  dv.setInt16(p, -1, true); // dependency identifier
  p += 2;
  const sizePos = p;
  p += 4; // element data size, filled in below
  dv.setUint32(p, NAME_OFFSET, true);
  p += 4;
  out[p++] = 0x02; // close start element
  out[p++] = 0x04; // end element
  dv.setUint32(sizePos, p - (sizePos + 4), true);
  out[p++] = 0x00; // end of BinXML stream
  return out.subarray(0, p);
}

/** One record: 24-byte prologue, payload, then a copy of the size. */
function record(id: number, body: Uint8Array): Uint8Array {
  const size = 24 + body.length + 4;
  const rec = new Uint8Array(size);
  const dv = new DataView(rec.buffer);
  dv.setUint32(0, 0x00002a2a, true);
  dv.setUint32(4, size, true);
  dv.setBigUint64(8, BigInt(id), true);
  dv.setBigUint64(16, 133590024000000000n, true); // 2024-05-01 10:00:00Z
  rec.set(body, 24);
  dv.setUint32(size - 4, size, true);
  return rec;
}

/** The outer record of a nested pair: its size covers the record inside it. */
function nested(outerId: number, innerId: number, body: Uint8Array): Uint8Array {
  const inner = record(innerId, body);
  const size = 24 + body.length + inner.length + 4;
  const rec = new Uint8Array(size);
  const dv = new DataView(rec.buffer);
  dv.setUint32(0, 0x00002a2a, true);
  dv.setUint32(4, size, true);
  dv.setBigUint64(8, BigInt(outerId), true);
  dv.setBigUint64(16, 133590024000000000n, true);
  rec.set(body, 24);
  rec.set(inner, 24 + body.length);
  dv.setUint32(size - 4, size, true);
  return rec;
}

function file(records: Uint8Array[]): Uint8Array {
  const chunk = new Uint8Array(CHUNK_SIZE);
  const dv = new DataView(chunk.buffer);
  for (let i = 0; i < 8; i++) chunk[i] = 'ElfChnk\0'.charCodeAt(i);
  dv.setBigUint64(8, 1n, true);
  dv.setBigUint64(16, BigInt(records.length), true);
  dv.setBigUint64(24, 1n, true);
  dv.setBigUint64(32, BigInt(records.length), true);
  dv.setUint32(40, 128, true);

  chunk.set(stringEntry('Event'), NAME_OFFSET);

  let pos = RECORDS_START;
  let last = RECORDS_START;
  for (const r of records) {
    last = pos;
    chunk.set(r, pos);
    pos += r.length;
  }
  dv.setUint32(44, last, true);
  dv.setUint32(48, pos, true);

  const out = new Uint8Array(HEADER_SIZE + CHUNK_SIZE);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) out[i] = 'ElfFile\0'.charCodeAt(i);
  odv.setBigUint64(24, BigInt(records.length + 1), true);
  odv.setUint32(32, 128, true);
  odv.setUint16(36, 1, true);
  odv.setUint16(38, 3, true);
  odv.setUint16(40, 4096, true);
  odv.setUint16(42, 1, true);
  out.set(chunk, HEADER_SIZE);
  return out;
}

describe('hidden event records', () => {
  it('finds the concealed record and names the technique', async () => {
    const outcome = await run(evtx, bufReader(file([nested(1, 999, payload())]), 'hidden.evtx'));

    expect(outcome.rows.length).toBe(2);
    const [outer, hidden] = outcome.rows;

    expect(outer.recordNumber).toBe(1);
    expect(outer.hiddenRecord).toBe(false);
    expect(outer.extraDataOffset).toBeGreaterThan(0);

    expect(hidden.recordNumber).toBe(999);
    expect(hidden.hiddenRecord).toBe(true);
    // The concealed record decodes like any other, which is the point of
    // reporting it rather than merely noting that something is there.
    expect(hidden.xml).toContain('<Event');

    expect(outcome.warnings.some((w) => /hidden inside record/.test(String(w.message)))).toBe(true);
  });

  it('does not cry wolf on an ordinary record', async () => {
    const outcome = await run(evtx, bufReader(file([record(1, payload())]), 'plain.evtx'));

    expect(outcome.rows.length).toBe(1);
    expect(outcome.rows[0].hiddenRecord).toBe(false);
    expect(outcome.rows[0].extraDataOffset).toBeNull();
    expect(outcome.warnings).toEqual([]);
  });
});
