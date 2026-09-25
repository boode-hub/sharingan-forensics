// Builds a small $MFT, record by record, in which each record exercises one
// of the rules MFTECmd applies when it writes its CSV.
//
// A real $MFT holds the paths and times of everything on its owner's disk,
// and EZ's own test MFTs carry no expected output to check against (his
// MFT.Test asserts almost nothing about them; they are used here as a local
// smoke test only). So this one is written from the NTFS record layout, and
// src/parsers/mft.test.ts states by hand what his tool writes for each record.
//
// Layout references:
//   https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc
//   https://github.com/EricZimmerman/MFT (FileRecord.cs and Attributes/*.cs, for which fields he reads)
import { writeFileSync } from 'node:fs';

const FT_EPOCH = 11644473600000n;
/** A FILETIME at an ISO instant plus some 100 ns ticks. */
const ft = (iso, ticks = 0n) => (BigInt(Date.parse(iso)) + FT_EPOCH) * 10000n + ticks;
const align8 = (n) => (n + 7) & ~7;
const SIZE = 1024;

function resident(type, content, name = '', number = 0) {
  const nameBytes = Buffer.from(name, 'utf16le');
  const cOff = align8(0x18 + nameBytes.length);
  const a = Buffer.alloc(align8(cOff + content.length));
  a.writeInt32LE(type, 0);
  a.writeInt32LE(a.length, 4);
  a[8] = 0;
  a[9] = name.length;
  a.writeUInt16LE(0x18, 0xa);
  a.writeUInt16LE(number, 0xe);
  a.writeUInt32LE(content.length, 0x10);
  a.writeUInt16LE(cOff, 0x14);
  nameBytes.copy(a, 0x18);
  content.copy(a, cOff);
  return a;
}

function nonResident(type, { name = '', startVcn = 0n, actualSize, number = 0 }) {
  const nameBytes = Buffer.from(name, 'utf16le');
  const runOff = align8(0x40 + nameBytes.length);
  const run = Buffer.from([0x11, 0x01, 0x10, 0x00]); // one cluster at LCN 16, then the end marker
  const a = Buffer.alloc(align8(runOff + run.length));
  a.writeInt32LE(type, 0);
  a.writeInt32LE(a.length, 4);
  a[8] = 1;
  a[9] = name.length;
  a.writeUInt16LE(0x40, 0xa);
  a.writeUInt16LE(number, 0xe);
  a.writeBigUInt64LE(startVcn, 0x10);
  a.writeBigUInt64LE(startVcn, 0x18);
  a.writeUInt16LE(runOff, 0x20);
  a.writeBigUInt64LE((actualSize + 4095n) & ~4095n, 0x28);
  a.writeBigUInt64LE(actualSize, 0x30);
  a.writeBigUInt64LE(actualSize, 0x38);
  nameBytes.copy(a, 0x40);
  run.copy(a, runOff);
  return a;
}

function si({ created, modified, record, accessed, flags = 0x20, securityId = 0x100, usn = 0n }) {
  const c = Buffer.alloc(0x48);
  c.writeBigInt64LE(created, 0);
  c.writeBigInt64LE(modified, 8);
  c.writeBigInt64LE(record, 0x10);
  c.writeBigInt64LE(accessed, 0x18);
  c.writeUInt32LE(flags, 0x20);
  c.writeUInt32LE(securityId, 0x34);
  c.writeBigInt64LE(usn, 0x40);
  return resident(0x10, c);
}

function fn({ parent, name, type = 1, times, size = 0n }) {
  const [entry, seq, high = 0] = parent;
  const nb = Buffer.from(name, 'utf16le');
  const c = Buffer.alloc(0x42 + nb.length);
  c.writeUInt32LE(entry, 0);
  c.writeUInt16LE(high, 4);
  c.writeUInt16LE(seq, 6);
  c.writeBigInt64LE(times.created, 8);
  c.writeBigInt64LE(times.modified, 0x10);
  c.writeBigInt64LE(times.record, 0x18);
  c.writeBigInt64LE(times.accessed, 0x20);
  c.writeBigUInt64LE(size, 0x28);
  c.writeBigUInt64LE(size, 0x30);
  c[0x40] = name.length;
  c[0x41] = type;
  nb.copy(c, 0x42);
  return resident(0x30, c);
}

function reparse(tag, first, second, symlink) {
  // PathBuffer laid out as Windows writes it (see `fsutil reparsepoint query`
  // on "C:\Users\All Users" and "C:\Documents and Settings"): a junction holds
  // its substitute name, a NUL, its print name and a NUL; a symbolic link
  // holds its print name followed directly by its substitute name.
  const a = Buffer.from(first, 'utf16le');
  const b = Buffer.from(second, 'utf16le');
  const head = symlink ? 12 : 8;
  const gap = symlink ? 0 : 2;
  const c = Buffer.alloc(8 + head + a.length + gap + b.length + gap);
  c.writeUInt32LE(tag, 0);
  c.writeUInt16LE(c.length - 8, 4);
  if (symlink) {
    c.writeUInt16LE(a.length, 8);
    c.writeUInt16LE(b.length, 10);
    c.writeUInt16LE(0, 12);
    c.writeUInt16LE(a.length, 14);
  } else {
    c.writeUInt16LE(0, 8);
    c.writeUInt16LE(a.length, 10);
    c.writeUInt16LE(a.length + 2, 12);
    c.writeUInt16LE(b.length, 14);
  }
  a.copy(c, 8 + head);
  b.copy(c, 8 + head + a.length + gap);
  return resident(0xc0, c);
}

/** A FILE record, with its fixup array applied as NTFS writes it. */
function record({ entry, seq, flags, attrs, base = [0, 0], sig = 'FILE', torn = false }) {
  const b = Buffer.alloc(SIZE);
  b.write(sig, 0, 'latin1');
  b.writeUInt16LE(0x30, 4);
  b.writeUInt16LE(3, 6); // the check value and one saved pair per 512-byte sector
  b.writeBigInt64LE(0x100000n + BigInt(entry), 8);
  b.writeUInt16LE(seq, 0x10);
  b.writeUInt16LE(1, 0x12);
  b.writeUInt16LE(0x38, 0x14);
  b.writeUInt16LE(flags, 0x16);
  let at = 0x38;
  for (const a of attrs) {
    a.copy(b, at);
    at += a.length;
  }
  if (at + 8 > SIZE) throw new Error(`entry ${entry} does not fit`);
  b.writeInt32LE(-1, at);
  b.writeUInt32LE(at + 8, 0x18);
  b.writeUInt32LE(SIZE, 0x1c);
  b.writeUInt32LE(base[0], 0x20);
  b.writeUInt16LE(base[1], 0x26);
  b.writeUInt16LE(attrs.length, 0x28);
  b.writeUInt32LE(entry, 0x2c);
  const usn = 0x0007;
  b.writeUInt16LE(usn, 0x30);
  for (let i = 1; i <= 2; i++) {
    const end = i * 512 - 2;
    b.copy(b, 0x30 + i * 2, end, end + 2);
    b.writeUInt16LE(torn && i === 2 ? 0x1234 : usn, end);
  }
  return b;
}

const same = (t) => ({ created: t, modified: t, record: t, accessed: t });
const T0 = ft('2023-05-01T08:00:00.000Z', 1234n);
const root = [5, 5];
const folder = [6, 1];

const slots = [];
slots[0] = record({
  entry: 0,
  seq: 1,
  flags: 1,
  attrs: [
    si({ ...same(T0), flags: 0x06 }),
    fn({ parent: root, name: '$MFT', type: 3, times: same(T0), size: 0n }),
    nonResident(0x80, { actualSize: 25600n }),
  ],
});
slots[5] = record({
  entry: 5,
  seq: 5,
  flags: 3,
  attrs: [si({ ...same(T0), flags: 0x06 }), fn({ parent: root, name: '.', type: 3, times: same(T0) })],
});
// A folder with a DOS 8.3 name first: the long name is the one he keeps.
slots[6] = record({
  entry: 6,
  seq: 1,
  flags: 3,
  attrs: [
    si(same(T0)),
    fn({ parent: root, name: 'LONGFO~1', type: 2, times: same(T0) }),
    fn({ parent: root, name: 'LongFolderName', type: 1, times: same(T0) }),
  ],
});

// SI created is earlier than FN created (SI<FN), SI modified has zero
// milliseconds (uSecZeros), and the Zone.Identifier text straddles the end of
// the first sector, so it only reads right once the fixup is applied.
const created7 = ft('2024-03-01T10:00:00.123Z', 4567n);
const fnCreated7 = ft('2024-03-02T11:30:00.456Z', 1n);
const modified7 = ft('2024-03-05T09:15:30.000Z', 42n);
const record7 = ft('2024-03-06T12:00:00.789Z');
const zone = Buffer.from('[ZoneTransfer]\r\nZoneId=3\r\n', 'latin1');
const oid = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const attrs7 = [
  si({ created: created7, modified: modified7, record: record7, accessed: record7, flags: 0x26, securityId: 0x105, usn: 0x1234n }),
  fn({
    parent: folder,
    name: 'report.docx',
    times: { created: fnCreated7, modified: modified7, record: record7, accessed: ft('2024-03-02T11:30:00.456Z') },
    size: 4096n,
  }),
  resident(0x40, oid),
];
const before = 0x38 + attrs7.reduce((n, a) => n + a.length, 0);
// Pad the file's own data so the stream's content starts just before the sector end.
const dataLen = 0x1fe - 16 - 0x38 - before - 0x18;
attrs7.push(resident(0x80, Buffer.alloc(dataLen, 0x41)), resident(0x80, zone, 'Zone.Identifier', 3));
slots[7] = record({ entry: 7, seq: 2, flags: 1, attrs: attrs7 });

// Hard links (two long names in two folders) plus a DOS name; no $DATA, so
// the size comes from the first $FILE_NAME. Modified before created: Copied.
const created8 = ft('2024-04-10T00:00:00.500Z');
const modified8 = ft('2024-01-01T00:00:00.250Z');
slots[8] = record({
  entry: 8,
  seq: 1,
  flags: 1,
  attrs: [
    si({ created: created8, modified: modified8, record: created8, accessed: created8 }),
    fn({ parent: root, name: 'a.txt', type: 1, times: same(created8), size: 77n }),
    fn({ parent: folder, name: 'b.txt', type: 0, times: same(created8), size: 88n }),
    fn({ parent: root, name: 'A~1.TXT', type: 2, times: same(created8), size: 99n }),
  ],
});

// A deleted folder (keyed with sequence 3 - 1) and a deleted file inside it.
slots[9] = record({ entry: 9, seq: 3, flags: 2, attrs: [si(same(T0)), fn({ parent: folder, name: 'OldDir', times: same(T0) })] });
slots[10] = record({
  entry: 10,
  seq: 2,
  flags: 0,
  attrs: [si(same(T0)), fn({ parent: [9, 2], name: 'gone.txt', times: same(T0), size: 10n }), resident(0x80, Buffer.from('0123456789'))],
});
// A parent that is not in the table.
slots[11] = record({ entry: 11, seq: 1, flags: 1, attrs: [si(same(T0)), fn({ parent: [0x63, 1], name: 'orphan.txt', times: same(T0) })] });

// A base record whose name and data live in an extension record.
slots[12] = record({ entry: 12, seq: 1, flags: 1, attrs: [si(same(T0)), resident(0x20, Buffer.alloc(0x40))] });
slots[13] = record({
  entry: 13,
  seq: 1,
  flags: 1,
  base: [12, 1],
  attrs: [
    fn({ parent: root, name: 'big.bin', times: same(T0) }),
    nonResident(0x80, { actualSize: 5000000n }),
    nonResident(0x80, { name: 'stream', actualSize: 300000n }),
    nonResident(0x80, { name: 'stream', startVcn: 10n, actualSize: 300000n }),
  ],
});

slots[14] = record({
  entry: 14,
  seq: 1,
  flags: 1,
  attrs: [
    si({ ...same(T0), flags: 0x420 }),
    fn({ parent: root, name: 'link.txt', times: same(T0) }),
    reparse(0xa000000c, 'C:\\Target\\file.txt', '\\??\\C:\\Target\\file.txt', true),
  ],
});
slots[15] = record({
  entry: 15,
  seq: 1,
  flags: 3,
  attrs: [
    si({ ...same(T0), flags: 0x410 }),
    fn({ parent: root, name: 'Junction', times: same(T0) }),
    reparse(0xa0000003, '\\??\\C:\\Users', 'C:\\Users', false),
  ],
});

// No $STANDARD_INFORMATION at all.
slots[16] = record({
  entry: 16,
  seq: 1,
  flags: 1,
  attrs: [
    fn({
      parent: root,
      name: 'nosi.txt',
      times: {
        created: ft('2022-01-01T01:01:01.001Z'),
        modified: ft('2022-02-02T02:02:02.002Z'),
        record: ft('2022-03-03T03:03:03.003Z'),
        accessed: ft('2022-04-04T04:04:04.004Z'),
      },
    }),
  ],
});

slots[17] = record({ entry: 17, seq: 1, flags: 1, sig: 'BAAD', attrs: [] });
// A second in-use record claiming entry 7 sequence 2: he keeps the first.
slots[19] = record({ entry: 7, seq: 2, flags: 1, attrs: [si(same(T0)), fn({ parent: root, name: 'dupe.txt', times: same(T0) })] });
// Parent reference with a non-zero upper word: his MftEntryInfo multiplies it by 2^24.
slots[20] = record({ entry: 20, seq: 1, flags: 1, attrs: [si(same(T0)), fn({ parent: [5, 1, 1], name: 'far.txt', times: same(T0) })] });
// A flag bit with no name, a logged utility stream, and a torn second sector.
slots[21] = record({
  entry: 21,
  seq: 1,
  flags: 1,
  torn: true,
  attrs: [
    si({ ...same(T0), flags: 0x800020 }),
    fn({ parent: root, name: 'odd.bin', times: same(T0) }),
    resident(0x100, Buffer.alloc(8), '$EFS'),
  ],
});
// An extension record whose base record is gone still names its directory.
slots[23] = record({
  entry: 23,
  seq: 1,
  flags: 3,
  base: [50, 1],
  attrs: [fn({ parent: root, name: 'Lost', times: same(T0) })],
});
slots[24] = record({ entry: 24, seq: 1, flags: 1, attrs: [si(same(T0)), fn({ parent: [50, 1], name: 'found.txt', times: same(T0) })] });

const out = Buffer.concat(Array.from({ length: 25 }, (_, i) => slots[i] ?? Buffer.alloc(SIZE)));
writeFileSync(new URL('./$MFT', import.meta.url), out);
console.log(`$MFT: ${out.length} bytes, ${out.length / SIZE} records`);
