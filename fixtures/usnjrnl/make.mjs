// Builds a small $J (USN change journal) as NTFS leaves it: sparse zeros up
// to where the live records begin, then 4 KB pages packed with USN_RECORD_V2
// entries, each page's unused tail left as zeros.
//
// Its parent references point into fixtures/mft/$MFT, so opening the two
// together checks the paths MFTECmd writes when given the $MFT with -m.
//
// Pages after the sparse run:
//   A  the records the tests look at, then filler up to the page's end
//   B  starts with a version 3 record: he skips the whole page
//   C  starts with a size larger than a page: skipped as junk
//   D  one record, then filler
//   E  a record cut off by the end of the file
//
// Layout reference: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
import { writeFileSync } from 'node:fs';

const FT_EPOCH = 11644473600000n;
const ft = (iso) => (BigInt(Date.parse(iso)) + FT_EPOCH) * 10000n;
const PAGE = 0x1000;
const LEAD = 16 * PAGE;

function rec({ name, file, parent, usn, time, reasons, attrs, major = 2 }) {
  const nb = Buffer.from(name, 'utf16le');
  const b = Buffer.alloc((0x3c + nb.length + 7) & ~7);
  b.writeUInt32LE(b.length, 0);
  b.writeInt16LE(major, 4);
  b.writeInt16LE(0, 6);
  const ref = (at, [entry, seq, high = 0]) => {
    b.writeUInt32LE(entry, at);
    b.writeUInt16LE(high, at + 4);
    b.writeUInt16LE(seq, at + 6);
  };
  ref(8, file);
  ref(16, parent);
  b.writeBigUInt64LE(BigInt(usn), 24);
  b.writeBigInt64LE(time, 32);
  b.writeUInt32LE(reasons >>> 0, 40);
  b.writeUInt32LE(0, 44);
  b.writeInt32LE(0x10a, 48);
  b.writeInt32LE(attrs, 52);
  b.writeInt16LE(nb.length, 56);
  b.writeInt16LE(0x3c, 58);
  nb.copy(b, 0x3c);
  return b;
}

let fill = 0;
/** A page of the given records, topped up with filler until less than a record's room is left. */
function page(at, specs, { major = 2 } = {}) {
  const p = Buffer.alloc(PAGE);
  let o = 0;
  const put = (spec) => {
    const r = rec({ usn: at + o, ...spec });
    if (o + r.length > PAGE) return false;
    r.copy(p, o);
    o += r.length;
    return true;
  };
  for (const s of specs) put(s);
  for (;;) {
    const n = fill;
    const ok = put({
      name: `fill-${String(n).padStart(4, '0')}.tmp`,
      file: [100 + n, 1],
      parent: [5, 5],
      time: ft('2024-06-01T00:00:00Z') + BigInt(n) * 10000000n,
      reasons: 0x80000002,
      attrs: 0x20,
      major,
    });
    if (!ok) break;
    fill++;
  }
  return p;
}

const A = LEAD;
const pageA = page(A, [
  { name: 'report.docx', file: [7, 2], parent: [6, 1], time: ft('2024-03-01T10:00:00.123Z') + 4567n, reasons: 0x80000100, attrs: 0x20 },
  { name: 'gone.txt', file: [10, 2], parent: [9, 2], time: ft('2024-03-02T08:30:00Z'), reasons: 0x80000200, attrs: 0x2020 },
  { name: 'NewFolder', file: [30, 1], parent: [5, 5], time: ft('2024-03-03T09:00:00Z'), reasons: 0x100, attrs: 0x10 },
  { name: 'far.txt', file: [31, 1], parent: [5, 1, 1], time: ft('2024-03-04T09:00:00Z'), reasons: 0x3000, attrs: 0x20 },
  // A reason and an attribute bit his enums do not name, and all-zero fields.
  { name: 'odd.bin', file: [32, 1], parent: [5, 5], time: ft('2024-03-05T09:00:00Z'), reasons: 0x81000000, attrs: 0x80020 },
  { name: 'zero', file: [33, 1], parent: [5, 5], time: ft('2024-03-06T09:00:00Z'), reasons: 0, attrs: 0 },
]);
const fillA = fill;
const pageB = page(A + PAGE, [{ name: 'v3.txt', file: [40, 1], parent: [5, 5], time: ft('2024-03-07T00:00:00Z'), reasons: 0x100, attrs: 0x20, major: 3 }]);
const pageC = Buffer.alloc(PAGE, 0xaa);
pageC.writeUInt32LE(0x2000, 0);
const fillD = fill;
const pageD = page(A + 3 * PAGE, [{ name: 'last.txt', file: [41, 1], parent: [6, 1], time: ft('2024-03-08T00:00:00Z'), reasons: 0x80000100, attrs: 0x20 }]);
const cut = rec({ name: 'ab', file: [42, 1], parent: [5, 5], usn: A + 4 * PAGE, time: ft('2024-03-09T00:00:00Z'), reasons: 0x100, attrs: 0x20 });
cut.writeUInt32LE(0x48, 0); // claims more than the file has left

const out = Buffer.concat([Buffer.alloc(LEAD), pageA, pageB, pageC, pageD, cut.subarray(0, 0x40)]);
writeFileSync(new URL('./$J', import.meta.url), out);
console.log(`$J: ${out.length} bytes; filler records A ${fillA}, B ${fillD - fillA}, D ${fill - fillD}`);
