// Builds a small $Secure:$SDS stream: security descriptor entries in the
// first 256 KB block and, as NTFS writes it, a mirror copy of them in the
// next.
//
// Each entry is a 0x14-byte header (hash, security id, the entry's offset in
// the stream, its size) and a self-relative descriptor laid out as NTFS lays
// it out: SACL, DACL, owner SID, group SID. Entries start on 16-byte
// boundaries.
//
// Layout references:
//   https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc (the $Secure section)
//   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d (SECURITY_DESCRIPTOR)
import { writeFileSync } from 'node:fs';

function sid(text) {
  const [, rev, auth, ...subs] = text.split('-');
  const b = Buffer.alloc(8 + subs.length * 4);
  b[0] = Number(rev);
  b[1] = subs.length;
  b.writeUIntBE(Number(auth), 2, 6);
  subs.forEach((s, i) => b.writeUInt32LE(Number(s) >>> 0, 8 + i * 4));
  return b;
}

function ace(type, flags, mask, who) {
  const s = sid(who);
  const b = Buffer.alloc(8 + s.length);
  b[0] = type;
  b[1] = flags;
  b.writeUInt16LE(b.length, 2);
  b.writeUInt32LE(mask >>> 0, 4);
  s.copy(b, 8);
  return b;
}

function acl(aces) {
  const body = Buffer.concat(aces);
  const h = Buffer.alloc(8);
  h[0] = 2;
  h.writeUInt16LE(8 + body.length, 2);
  h.writeUInt16LE(aces.length, 4);
  return Buffer.concat([h, body]);
}

function descriptor({ control, sacl, dacl, owner, group }) {
  const h = Buffer.alloc(0x14);
  h[0] = 1;
  h.writeUInt16LE(control, 2);
  const parts = [];
  let at = 0x14;
  const put = (buf, field) => {
    h.writeUInt32LE(at, field);
    parts.push(buf);
    at += buf.length;
  };
  if (sacl) put(sacl, 12);
  if (dacl) put(dacl, 16);
  put(sid(owner), 4);
  put(sid(group), 8);
  return Buffer.concat([h, ...parts]);
}

const FULL = 0x1f01ff;
const specs = [
  {
    hash: 0x11223344,
    id: 0x100,
    sd: { control: 0x8004, dacl: acl([ace(0, 0, FULL, 'S-1-5-18'), ace(0, 0, FULL, 'S-1-5-32-544')]), owner: 'S-1-5-32-544', group: 'S-1-5-18' },
  },
  {
    hash: 0xa1b2c3d4,
    id: 0x101,
    sd: {
      control: 0x9414,
      sacl: acl([ace(0x11, 0, 1, 'S-1-16-12288'), ace(2, 0xc0, FULL, 'S-1-1-0')]),
      dacl: acl([ace(0, 0x10, FULL, 'S-1-5-18'), ace(1, 0, 0x10000, 'S-1-1-0'), ace(0, 0x13, 0x1200a9, 'S-1-5-32-545')]),
      owner: 'S-1-5-21-2127521184-1604012920-1887927527-72713',
      group: 'S-1-5-21-2127521184-1604012920-1887927527-513',
    },
  },
  // Security id 0: he steps over it.
  { hash: 0x55555555, id: 0, sd: { control: 0x8000, owner: 'S-1-5-18', group: 'S-1-5-18' } },
  // No DACL at all.
  { hash: 0x01020304, id: 0x102, sd: { control: 0x8000, owner: 'S-1-5-18', group: 'S-1-5-32-544' } },
];

const entries = [];
let at = 0;
for (const s of specs) {
  const body = descriptor(s.sd);
  const h = Buffer.alloc(0x14);
  h.writeUInt32LE(s.hash, 0);
  h.writeUInt32LE(s.id, 4);
  h.writeBigUInt64LE(BigInt(at), 8);
  h.writeUInt32LE(0x14 + body.length, 16);
  const e = Buffer.alloc(Math.ceil((0x14 + body.length) / 16) * 16);
  Buffer.concat([h, body]).copy(e);
  entries.push(e);
  at += e.length;
}
const block = Buffer.concat(entries);
// The mirror is a byte-for-byte copy, so its entries still name their offsets in the first block.
const out = Buffer.concat([block, Buffer.alloc(0x40000 - block.length), block, Buffer.alloc(16)]);
writeFileSync(new URL('./$SDS', import.meta.url), out);
console.log(`$SDS: ${out.length} bytes, entries at ${entries.map((_, i) => entries.slice(0, i).reduce((n, e) => n + e.length, 0)).join(', ')}`);
