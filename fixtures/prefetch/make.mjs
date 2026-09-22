// Builds synthetic Prefetch samples from the v30/v31 on-disk layout, plus a
// MAM-compressed copy of the same body.
//
// The layout below was cross-checked against a real Windows 11 v31 Prefetch
// file: its embedded name hash matched the hash in its own filename, and its
// declared size matched the decompressed length exactly.
//
// Layout reference:
//   https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
import { writeFileSync } from 'node:fs';

const FT_EPOCH = 11644473600000n;
const ft = (iso) => (BigInt(Date.parse(iso)) + FT_EPOCH) * 10000n;
const utf16 = (s) => Buffer.from(s, 'utf16le');

/** Windows' Prefetch name hash (the "scca" variant used for v17/v23+). */
function prefetchHash(path) {
  let hash = 314159265;
  for (const ch of path.toUpperCase()) {
    hash = ((hash * 37) + ch.charCodeAt(0)) >>> 0;
  }
  hash = (hash * 314159269) >>> 0;
  if (hash & 0x80000000) hash = (~hash + 1) >>> 0;
  return hash % 1000000007;
}

function prefetch({ version, exe, runTimes, runCount, files, volume }) {
  // Filename strings: NUL-terminated UTF-16 paths, back to back.
  const strings = Buffer.concat(files.map((f) => Buffer.concat([utf16(f), Buffer.alloc(2)])));

  // One 96-byte volume entry (v30/v31), followed by its device path.
  const devPath = Buffer.concat([utf16(volume.device), Buffer.alloc(2)]);
  const volEntry = Buffer.alloc(96);
  volEntry.writeUInt32LE(96, 0); // device path offset, relative to volOff
  volEntry.writeUInt32LE(volume.device.length, 4); // in characters, excluding NUL
  volEntry.writeBigUInt64LE(ft(volume.created), 8);
  volEntry.writeUInt32LE(volume.serial, 16);
  const volBlock = Buffer.concat([volEntry, devPath]);

  const HEADER = 84;
  const INFO = version >= 30 ? 224 : 156; // file-information block size
  const strOff = HEADER + INFO;
  const volOff = strOff + strings.length;

  const head = Buffer.alloc(HEADER);
  head.writeUInt32LE(version, 0);
  head.write('SCCA', 4, 'latin1');
  head.writeUInt32LE(0x11, 8);
  // byte 12 (total file size) is filled in once the length is known
  utf16(exe).copy(head, 16, 0, Math.min(utf16(exe).length, 58));
  head.writeUInt32LE(prefetchHash(`\\VOLUME{01}\\${exe}`), 76);

  const info = Buffer.alloc(INFO);
  info.writeUInt32LE(strOff, 100 - HEADER);
  info.writeUInt32LE(strings.length, 104 - HEADER);
  info.writeUInt32LE(volOff, 108 - HEADER);
  info.writeUInt32LE(1, 112 - HEADER);
  info.writeUInt32LE(volBlock.length, 116 - HEADER);
  // Eight last-run slots at offset 128; unused slots stay zero (= never run).
  runTimes.forEach((t, i) => info.writeBigUInt64LE(ft(t), 128 - HEADER + i * 8));
  // Run count sits at 208 in version 30/31 and at 200 before that. Windows 10
  // builds that still used 200 leave the slot at 204 populated, which is how
  // PECmd tells the two apart, so a v30/v31 fixture has to use 208 or it is
  // not modelling a real file.
  info.writeUInt32LE(runCount, (version >= 30 ? 208 : 200) - HEADER);

  const buf = Buffer.concat([head, info, strings, volBlock]);
  buf.writeUInt32LE(buf.length, 12);
  return buf;
}

/**
 * Wraps a body in a MAM container using a literals-only Xpress Huffman stream.
 * Real Windows uses matches too; this only has to be a *valid* stream, and the
 * real-file test in src/core/xpress.test.ts covers match decoding.
 */
function mam(body) {
  // All 256 literals at 8 bits is a complete code (256 * 2^-8 == 1), so each
  // literal's canonical code is its own byte value and the bitstream is simply
  // the body. The 256 match symbols must be left at length 0: giving them codes
  // too would over-subscribe the code and make the table invalid.
  // Two symbols per byte, so the literals occupy bytes 0..127 only.
  const table = Buffer.alloc(256, 0x00);
  table.fill(0x88, 0, 128);
  const header = Buffer.alloc(8);
  header.write('MAM', 0, 'latin1');
  header.writeUInt8(0x04, 3);
  header.writeUInt32LE(body.length, 4);
  // The bitstream is read as 16-bit little-endian words, MSB first, so each
  // pair of literal bytes is byte-swapped. Pad so the reader never runs dry.
  const words = Buffer.alloc(Math.ceil(body.length / 2) * 2 + 8);
  for (let i = 0; i < body.length; i += 2) {
    words[i] = body[i + 1] ?? 0;
    words[i + 1] = body[i];
  }
  return Buffer.concat([header, table, words]);
}

const v31 = prefetch({
  version: 31,
  exe: 'NOTEPAD.EXE',
  runTimes: ['2024-03-01T08:15:00Z', '2024-02-28T17:42:10Z'],
  runCount: 7,
  files: ['\\VOLUME{01}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE', '\\VOLUME{01}\\WINDOWS\\SYSTEM32\\NTDLL.DLL'],
  volume: { device: '\\DEVICE\\HARDDISKVOLUME3', serial: 0xa1b2c3d4, created: '2023-01-05T09:00:00Z' },
});

const cases = {
  'NOTEPAD.EXE-AAAAAAAA.pf': v31,
  // Same body behind a MAM header: the parser must decompress transparently.
  'NOTEPAD.EXE-MAMTEST.pf': mam(v31),
};

for (const [name, buf] of Object.entries(cases)) {
  writeFileSync(new URL(name, import.meta.url), buf);
  console.log(name, buf.length, 'bytes');
}
