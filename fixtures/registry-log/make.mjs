// Builds a dirty registry hive and the transaction log that brings it up to
// date, from the documented on-disk layout.
//
// The point of the pair is that reading the hive alone gives a stale answer
// that looks perfectly valid: the value reads OLD, with nothing to suggest a
// newer one exists. Replaying the log gives NEW, which is what the machine
// would have seen. Every large hive captured from a running system is in this
// state, so a parser that cannot do this is quietly reporting history.
//
// Layout references:
//   https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
//   https://github.com/EricZimmerman/Registry (TransactionLog, Marvin)
import { writeFileSync } from 'node:fs';

const HBIN_START = 4096;
const HBIN_SIZE = 4096;

// ---------------------------------------------------------------- Marvin ---
// Written here from the algorithm rather than imported from src/, so the
// fixture is an independent check on the parser's copy.
const rotl = (v, s) => ((v << s) | (v >>> (32 - s))) >>> 0;

function marvin(data, seed = 0x82ef4d887a4e55c5n) {
  let p0 = Number(seed & 0xffffffffn) >>> 0;
  let p1 = Number((seed >> 32n) & 0xffffffffn) >>> 0;
  const block = () => {
    p1 ^= p0;
    p0 = rotl(p0, 20);
    p0 = (p0 + p1) >>> 0;
    p1 = rotl(p1, 9);
    p1 ^= p0;
    p0 = rotl(p0, 27);
    p0 = (p0 + p1) >>> 0;
    p1 = rotl(p1, 19);
  };
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let at = 0;
  let left = data.length;
  while (left >= 8) {
    p0 = (p0 + dv.getUint32(at, true)) >>> 0;
    block();
    p0 = (p0 + dv.getUint32(at + 4, true)) >>> 0;
    block();
    at += 8;
    left -= 8;
  }
  if (left >= 4) {
    p0 = (p0 + dv.getUint32(at, true)) >>> 0;
    block();
    at += 4;
    left -= 4;
  }
  if (left === 3) p0 = (p0 + (0x80000000 | (data[at + 2] << 16) | dv.getUint16(at, true))) >>> 0;
  else if (left === 2) p0 = (p0 + (0x800000 | dv.getUint16(at, true))) >>> 0;
  else if (left === 1) p0 = (p0 + (0x8000 | data[at])) >>> 0;
  else p0 = (p0 + 0x80) >>> 0;
  block();
  block();
  return ((BigInt(p1) << 32n) | BigInt(p0)) & 0xffffffffffffffffn;
}

// ------------------------------------------------------------------ hive ---
const FT_EPOCH = 11644473600000n;
const ft = (iso) => (BigInt(Date.parse(iso)) + FT_EPOCH) * 10000n;

/**
 * The hbin holding a root key with one value, whose data is `data`.
 *
 * Cells sit back to back and are a multiple of eight bytes, because a reader
 * walks them by size from the start of the hbin: a gap is not skipped, it ends
 * the walk. Whatever is left over becomes one free cell, which is what Windows
 * does with the tail of an hbin.
 */
function hbin(data) {
  const b = Buffer.alloc(HBIN_SIZE);
  b.write('hbin', 0, 'latin1');
  b.writeUInt32LE(0, 4); // offset of this hbin from the first
  b.writeUInt32LE(HBIN_SIZE, 8);
  b.writeBigUInt64LE(ft('2024-01-01T00:00:00Z'), 20);

  const align = (n) => Math.ceil(n / 8) * 8;
  const name = 'ROOT';
  const vname = 'Status';

  const nkAt = 0x20;
  const nkSize = align(0x50 + name.length);
  const listAt = nkAt + nkSize;
  const listSize = 8;
  const vkAt = listAt + listSize;
  const vkSize = align(0x18 + vname.length);
  // REG_SZ is UTF-16, and only four bytes fit inside a value record, so the
  // data goes in a cell of its own like any string longer than two characters.
  const dataBytes = Buffer.from(`${data}\0`, 'utf16le');
  const dataAt = vkAt + vkSize;
  const dataSize = align(4 + dataBytes.length);

  // Root key. Field offsets are from the start of the cell.
  b.writeInt32LE(-nkSize, nkAt); // negative size means allocated
  b.write('nk', nkAt + 4, 'latin1');
  b.writeUInt16LE(0x0004 | 0x0020, nkAt + 6); // hive root, name is ASCII
  b.writeBigUInt64LE(ft('2024-03-02T04:05:06Z'), nkAt + 8);
  b.writeUInt32LE(0xffffffff, nkAt + 20); // parent
  b.writeUInt32LE(0, nkAt + 24); // subkey count
  b.writeUInt32LE(0xffffffff, nkAt + 32); // subkey list
  b.writeUInt32LE(1, nkAt + 40); // value count
  b.writeUInt32LE(listAt, nkAt + 44); // value list offset
  b.writeUInt32LE(0xffffffff, nkAt + 48); // security
  b.writeUInt32LE(0xffffffff, nkAt + 52); // class
  b.writeUInt16LE(name.length, nkAt + 76); // name length
  b.write(name, nkAt + 80, 'latin1');

  // Value list: one offset, pointing at the vk record.
  b.writeInt32LE(-listSize, listAt);
  b.writeUInt32LE(vkAt, listAt + 4);

  // The value itself, with its data stored inside the record.
  b.writeInt32LE(-vkSize, vkAt);
  b.write('vk', vkAt + 4, 'latin1');
  b.writeUInt16LE(vname.length, vkAt + 6);
  b.writeUInt32LE(dataBytes.length, vkAt + 8);
  b.writeUInt32LE(dataAt, vkAt + 12);
  b.writeUInt32LE(1, vkAt + 16); // REG_SZ
  b.writeUInt16LE(1, vkAt + 20); // name is ASCII
  b.write(vname, vkAt + 24, 'latin1');

  // The value's data, in its own cell.
  b.writeInt32LE(-dataSize, dataAt);
  dataBytes.copy(b, dataAt + 4);

  // The rest of the hbin as one free cell: a positive size marks it unused.
  const freeAt = dataAt + dataSize;
  b.writeInt32LE(HBIN_SIZE - freeAt, freeAt);

  return b;
}

/** A hive file whose two sequence numbers disagree, so it reads as dirty. */
function hive(primary, secondary, body) {
  const head = Buffer.alloc(HBIN_START);
  head.write('regf', 0, 'latin1');
  head.writeUInt32LE(primary, 4);
  head.writeUInt32LE(secondary, 8);
  head.writeBigUInt64LE(ft('2024-03-02T04:05:06Z'), 12);
  head.writeUInt32LE(1, 20); // major
  head.writeUInt32LE(5, 24); // minor
  head.writeUInt32LE(0, 28); // file type: primary
  head.writeUInt32LE(1, 32); // format
  head.writeUInt32LE(0x20, 36); // root key offset
  head.writeUInt32LE(HBIN_SIZE, 40); // hbin area length
  head.writeUInt32LE(1, 44); // clustering factor
  Buffer.from('SYNTHETIC.DAT\0', 'utf16le').copy(head, 48);
  return Buffer.concat([head, body]);
}

/** A log holding one entry that supersedes the whole hbin. */
function log(sequence, page) {
  const head = Buffer.alloc(512);
  head.write('regf', 0, 'latin1');
  head.writeUInt32LE(sequence, 4);
  head.writeUInt32LE(sequence, 8);
  head.writeUInt32LE(1, 20);
  head.writeUInt32LE(5, 24);
  head.writeUInt32LE(6, 28); // file type: transaction log
  head.writeUInt32LE(1, 32);
  head.writeUInt32LE(0x20, 36);
  head.writeUInt32LE(HBIN_SIZE, 40);
  Buffer.from('SYNTHETIC.DAT\0', 'utf16le').copy(head, 48);

  const entry = Buffer.alloc(40 + 8 + page.length);
  entry.write('HvLE', 0, 'latin1');
  entry.writeUInt32LE(entry.length, 4);
  entry.writeUInt32LE(1, 8); // flags
  entry.writeUInt32LE(sequence, 12);
  entry.writeUInt32LE(HBIN_SIZE, 16); // hive bin data size
  entry.writeUInt32LE(1, 20); // one dirty page
  // 24..39 are the two hashes, filled in below.
  entry.writeUInt32LE(0, 40); // page offset within the hbin area
  entry.writeUInt32LE(page.length, 44);
  page.copy(entry, 48);

  // Hash 1 covers everything past the hashes; hash 2 covers the 32 bytes
  // before them. Windows refuses an entry whose hashes do not match, and so
  // does anything replaying the log.
  entry.writeBigUInt64LE(marvin(new Uint8Array(entry.subarray(40))), 24);
  entry.writeBigUInt64LE(marvin(new Uint8Array(entry.subarray(0, 32))), 32);

  return Buffer.concat([head, entry]);
}

const stale = hbin('OLD');
const current = hbin('NEW');

const cases = {
  // Primary 3, secondary 2: written but not yet flushed, which is what a hive
  // copied from a running machine looks like.
  'SYNTHETIC.DAT': hive(3, 2, stale),
  'SYNTHETIC.DAT.LOG1': log(3, current),
};

for (const [name, buf] of Object.entries(cases)) {
  writeFileSync(new URL(name, import.meta.url), buf);
  console.log(name, buf.length, 'bytes');
}
