// Builds a synthetic .evtx from the documented on-disk layout.
//
// Scope: file header, one chunk, and the event-record framing. The BinXML
// payload inside each record is NOT generated — it is deliberately a short
// opaque blob, because record framing is a separate, testable concern from
// BinXML decoding and shipping it first gives a usable event timeline.
//
// Layout reference:
//   https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
import { writeFileSync } from 'node:fs';

const FT_EPOCH = 11644473600000n;
const ft = (iso) => (BigInt(Date.parse(iso)) + FT_EPOCH) * 10000n;

// Standard CRC-32 (the zlib polynomial), which is what EVTX checksums use.
const TABLE = Int32Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(...buffers) {
  let c = 0 ^ -1;
  for (const buf of buffers) {
    for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ TABLE[(c ^ buf[i]) & 0xff];
  }
  return ((c ^ -1) >>> 0);
}

const CHUNK_SIZE = 65536;
const RECORDS_START = 512;

/** One event record: 24-byte prologue, payload, then a u32 copy of the size. */
function record({ id, written, payload }) {
  const size = 24 + payload.length + 4;
  const b = Buffer.alloc(size);
  b.writeUInt32LE(0x00002a2a, 0); // "**\0\0"
  b.writeUInt32LE(size, 4);
  b.writeBigUInt64LE(BigInt(id), 8);
  b.writeBigUInt64LE(ft(written), 16);
  payload.copy(b, 24);
  b.writeUInt32LE(size, size - 4); // trailing size, used to walk backwards
  return b;
}

function chunk({ firstNum, records }) {
  const body = Buffer.concat(records);
  if (RECORDS_START + body.length > CHUNK_SIZE) throw new Error('records overflow chunk');

  const c = Buffer.alloc(CHUNK_SIZE);
  c.write('ElfChnk\0', 0, 'latin1');
  c.writeBigUInt64LE(BigInt(firstNum), 8); // first event record number
  c.writeBigUInt64LE(BigInt(firstNum + records.length - 1), 16); // last number
  c.writeBigUInt64LE(BigInt(firstNum), 24); // first event record identifier
  c.writeBigUInt64LE(BigInt(firstNum + records.length - 1), 32); // last identifier
  c.writeUInt32LE(128, 40); // header size

  // Offset of the LAST record, and the first free byte after all records.
  let off = RECORDS_START;
  let lastOff = RECORDS_START;
  for (const r of records) {
    lastOff = off;
    off += r.length;
  }
  c.writeUInt32LE(lastOff, 44);
  c.writeUInt32LE(off, 48);
  c.writeUInt32LE(crc32(body), 52); // checksum over the record data

  body.copy(c, RECORDS_START);

  // Header checksum covers bytes 0..119 and 128..511.
  c.writeUInt32LE(crc32(c.subarray(0, 120), c.subarray(128, 512)), 124);
  return c;
}

function evtx(chunks) {
  const head = Buffer.alloc(4096);
  head.write('ElfFile\0', 0, 'latin1');
  head.writeBigUInt64LE(0n, 8); // first chunk number
  head.writeBigUInt64LE(BigInt(chunks.length - 1), 16); // last chunk number
  head.writeBigUInt64LE(4n, 24); // next record identifier
  head.writeUInt32LE(128, 32); // header size
  head.writeUInt16LE(1, 36); // minor version
  head.writeUInt16LE(3, 38); // major version
  head.writeUInt16LE(4096, 40); // header block size
  head.writeUInt16LE(chunks.length, 42); // number of chunks
  head.writeUInt32LE(0, 120); // file flags: clean, not full
  head.writeUInt32LE(crc32(head.subarray(0, 120)), 124);
  return Buffer.concat([head, ...chunks]);
}

const payload = (tag) => Buffer.concat([Buffer.from([0x0f, 0x01, 0x01, 0x00]), Buffer.from(tag, 'latin1')]);

const cases = {
  'Synthetic.evtx': evtx([
    chunk({
      firstNum: 1,
      records: [
        record({ id: 1, written: '2024-05-01T10:00:00Z', payload: payload('EVENT-ONE') }),
        record({ id: 2, written: '2024-05-01T10:00:05Z', payload: payload('EVENT-TWO') }),
        record({ id: 3, written: '2024-05-02T23:59:59Z', payload: payload('EVENT-THREE') }),
      ],
    }),
  ]),
};

for (const [name, buf] of Object.entries(cases)) {
  writeFileSync(new URL(name, import.meta.url), buf);
  console.log(name, buf.length, 'bytes');
}
