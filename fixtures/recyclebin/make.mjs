// Builds synthetic $I / INFO2 samples from the documented on-disk layout.
// Written independently of the parser on purpose: the fixture is the oracle, so
// a parser that agrees with it is agreeing with the format, not with itself.
//
// $I layout   - https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Recycle%20Bin.asciidoc
// INFO2 layout- same reference, "INFO2 file format"
import { writeFileSync } from 'node:fs';

const FT_EPOCH = 11644473600000n;
const ft = (iso) => (BigInt(Date.parse(iso)) + FT_EPOCH) * 10000n;

function dollarI({ version, size, deleted, path }) {
  const p = Buffer.from(path + '\0', 'utf16le');
  const head = Buffer.alloc(24);
  head.writeBigUInt64LE(BigInt(version), 0);
  head.writeBigUInt64LE(BigInt(size), 8);
  head.writeBigUInt64LE(ft(deleted), 16);
  if (version === 1) {
    // v1: fixed 520-byte path field, NUL padded to 260 UTF-16 chars.
    const fixed = Buffer.alloc(520);
    p.copy(fixed, 0, 0, Math.min(p.length, 520));
    return Buffer.concat([head, fixed]);
  }
  // v2: u32 character count (including the terminator), then the string.
  const len = Buffer.alloc(4);
  len.writeUInt32LE(p.length / 2, 0);
  return Buffer.concat([head, len, p]);
}

function info2(records) {
  // The INFO2 header is five 32-bit fields, so 20 bytes, not 16. Getting this
  // wrong shifts every record by four bytes and quietly corrupts all of them.
  const head = Buffer.alloc(20);
  head.writeUInt32LE(5, 0); // version (Win2000/XP)
  head.writeUInt32LE(records.length, 8);
  head.writeUInt32LE(800, 12); // record size
  head.writeUInt32LE(0, 16); // unknown, zero on every sample
  const recs = records.map((r, i) => {
    const b = Buffer.alloc(800);
    b.write(r.ansiPath + '\0', 0, 'latin1'); // 260-byte ANSI path
    b.writeUInt32LE(i, 260); // record index (0-based: 0 is a VALID index)
    b.writeUInt32LE(r.drive, 264); // 0 = A:
    b.writeBigUInt64LE(ft(r.deleted), 268);
    b.writeUInt32LE(r.size, 276);
    Buffer.from(r.path + '\0', 'utf16le').copy(b, 280);
    return b;
  });
  return Buffer.concat([head, ...recs]);
}

// Same bytes as v2.$I, under a name an analyst might give it on export.
// Detection has to come from the content, not from a "$I" filename prefix.
const v2 = dollarI({
  version: 2,
  size: 4294967296, // >4GB, proves the 64-bit size field is read as such
  deleted: '2021-11-15T23:59:59Z',
  path: 'D:\\Evidence\\big file with spaces.vhdx',
});

const cases = {
  'v1.$I': dollarI({
    version: 1,
    size: 1024,
    deleted: '2019-06-01T10:30:00Z',
    path: 'C:\\Users\\suspect\\Documents\\notes.txt',
  }),
  'v2.$I': v2,
  'renamed-v2.bin': v2,
  // Non-ASCII path: catches a parser that decodes UTF-16 one byte at a time.
  'v2-unicode.$I': dollarI({
    version: 2,
    size: 0,
    deleted: '2024-02-29T12:00:00Z',
    path: 'C:\\Users\\\u0645\u0633\u062a\u062e\u062f\u0645\\\u6587\u4ef6.docx',
  }),
  INFO2: info2([
    {
      ansiPath: 'C:\\WINDOWS\\Temp\\old.log',
      path: 'C:\\WINDOWS\\Temp\\old.log',
      drive: 2,
      size: 512,
      deleted: '2003-04-05T06:07:08Z',
    },
    {
      ansiPath: 'C:\\Docs\\report.doc',
      path: 'C:\\Docs\\report.doc',
      drive: 2,
      size: 65536,
      deleted: '2004-12-25T00:00:01Z',
    },
  ]),
};

for (const [name, buf] of Object.entries(cases)) {
  writeFileSync(new URL(name, import.meta.url), buf);
  console.log(name, buf.length, 'bytes');
}
