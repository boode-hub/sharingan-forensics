/**
 * $J, the USN change journal ($Extend\$UsnJrnl:$J): a record for every
 * create, write, rename and delete on the volume, kept until the journal
 * wraps.
 *
 * Ported from Eric Zimmerman's Usn library (https://github.com/EricZimmerman/MFT:
 * Usn/UsnFile.cs, Usn/Usn.cs, Usn/UsnEntry.cs, Usn/MFTInformation.cs) and
 * MFTECmd's ProcessJ and JEntryOut (https://github.com/EricZimmerman/MFTECmd).
 *
 * Parent paths come from a $MFT opened alongside, as his -m option takes one;
 * without it the column is empty, as his is.
 */
import type { Column, ColType, Ctx, Parser, Reader, Row } from '../core/types';
import { filetime } from '../core/binary';
import { dotnetFlags, extension, mft, mftParentPaths } from './mft';

// JEntryOut, automapped in declaration order.
const columns: Column[] = [
  ['Name'],
  ['Extension'],
  ['EntryNumber', 'num'],
  ['SequenceNumber', 'num'],
  ['ParentEntryNumber', 'num'],
  ['ParentSequenceNumber', 'num'],
  ['ParentPath'],
  ['UpdateSequenceNumber', 'num'],
  ['UpdateTimestamp', 'date'],
  ['UpdateReasons'],
  ['FileAttributes'],
  ['OffsetToData', 'num'],
  ['SourceFile'],
].map(([key, type = 'str']) => ({
  key,
  label: key.replace(/([a-z])([A-Z])/g, '$1 $2'),
  type: type as ColType,
}));

// His UpdateReasonFlag and FileAttributeFlag, in ascending value order.
const REASONS: Array<[number, string]> = [
  [0x1, 'DataOverwrite'],
  [0x2, 'DataExtend'],
  [0x4, 'DataTruncation'],
  [0x10, 'NamedDataOverwrite'],
  [0x20, 'NamedDataExtend'],
  [0x40, 'NamedDataTruncation'],
  [0x100, 'FileCreate'],
  [0x200, 'FileDelete'],
  [0x400, 'EaChange'],
  [0x800, 'SecurityChange'],
  [0x1000, 'RenameOldName'],
  [0x2000, 'RenameNewName'],
  [0x4000, 'IndexableChange'],
  [0x8000, 'BasicInfoChange'],
  [0x10000, 'HardLinkChange'],
  [0x20000, 'CompressionChange'],
  [0x40000, 'EncryptionChange'],
  [0x80000, 'ObjectIdChange'],
  [0x100000, 'ReparsePointChange'],
  [0x200000, 'StreamChange'],
  [0x400000, 'TransactedChange'],
  [0x800000, 'IntegrityChange'],
  [0x80000000, 'Close'],
];
const ATTRIBUTES: Array<[number, string]> = [
  [0x1, 'ReadOnly'],
  [0x2, 'Hidden'],
  [0x4, 'System'],
  [0x8, 'VolumeLabel'],
  [0x10, 'Directory'],
  [0x20, 'Archive'],
  [0x40, 'Device'],
  [0x80, 'Normal'],
  [0x100, 'Temporary'],
  [0x200, 'SparseFile'],
  [0x400, 'ReparsePoint'],
  [0x800, 'Compressed'],
  [0x1000, 'Offline'],
  [0x2000, 'NotContentIndexed'],
  [0x4000, 'Encrypted'],
  [0x8000, 'IntegrityStream'],
  [0x10000, 'Virtual'],
  [0x20000, 'NoScrubData'],
  [0x40000, 'HasEa'],
  [0x10000000, 'IsDirectory'],
  [0x20000000, 'IsIndexView'],
];

const PAGE = 0x1000;

const isZero = (b: Uint8Array) => b.every((x) => x === 0);

/** A plausible first USN_RECORD_V2: size, version 2.0, and the name where V2 puts it. */
function looksLikeRecord(b: Uint8Array): boolean {
  if (b.length < 0x3c) return false;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const size = dv.getUint32(0, true);
  return (
    size >= 0x3c &&
    size <= 0x250 &&
    size % 8 === 0 &&
    dv.getInt16(4, true) === 2 &&
    dv.getInt16(6, true) === 0 &&
    dv.getInt16(58, true) === 0x3c &&
    0x3c + dv.getInt16(56, true) <= size
  );
}

/**
 * His FindStartingOffset. A journal is sparse up to where its live records
 * begin, so he bisects for the first 0x90 bytes that are not all zero and
 * walks forward from the last all-zero point to the first non-zero byte.
 */
async function startingOffset(reader: Reader): Promise<number | null> {
  if ((await reader.bytes(0, 1))[0] !== 0) return 0;
  let lastChecked = 0;
  let lastData = 0;
  let cur = Math.floor(reader.size / 2);
  // His loop has no bound; it settles within a few dozen probes on any real
  // journal, and one of only zeros would spin for ever.
  for (let probes = 0; !(lastData > 0 && lastData - lastChecked < 300); probes++) {
    if (probes > 500) return null;
    const prev = cur;
    if (!isZero(await reader.bytes(cur, 0x90))) {
      lastData = cur;
      cur = lastChecked + Math.floor((cur - lastChecked) / 2);
    } else {
      lastChecked = cur;
      cur = cur + Math.floor((reader.size - cur) / 2);
    }
    if (cur === prev && lastData === 0) return null;
  }
  let at = lastChecked;
  for (;;) {
    const chunk = await reader.bytes(at, 0x10000);
    if (chunk.length === 0) return null;
    const i = chunk.findIndex((x) => x !== 0);
    if (i >= 0) return at + i;
    at += chunk.length;
  }
}

/** His MftInformation: the upper 16 bits of the entry count 2^24 each. */
function mftInfo(dv: DataView, at: number) {
  const high = dv.getUint16(at + 4, true);
  return { entry: dv.getUint32(at, true) + high * 16_777_216, seq: dv.getUint16(at + 6, true) };
}

/** DateTimeOffset.FromFileTime's range; he cannot represent anything outside it. */
const MAX_FILETIME = 2650467743999999999n;

export const usnJrnl: Parser = {
  id: 'usnjrnl',
  name: '$J (USN journal)',
  ezTool: 'MFTECmd',
  extensions: [],
  columns,
  sniff(head: Uint8Array, filename: string): boolean {
    // A journal copied whole starts with zeros, so it is known by its name.
    return looksLikeRecord(head) || (/^\$j$|usnjrnl/i.test(filename) && head.length >= 8 && isZero(head.subarray(0, 8)));
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    let paths: ((entry: number, seq: number) => string) | null = null;
    for (const s of ctx.siblings ?? []) {
      if (!mft.sniff(await s.bytes(0, 512), s.name)) continue;
      paths = await mftParentPaths(s, { warn: (o, m) => ctx.warn(o, `${s.name}: ${m}`), signal: ctx.signal });
      break;
    }

    const start = await startingOffset(reader);
    if (start === null) {
      ctx.warn(0, 'the journal holds nothing but zeros');
      return;
    }

    // Records are read from a window of the file, a megabyte at a time.
    let win: Uint8Array = new Uint8Array(0);
    let winAt = 0;
    const view = async (pos: number, len: number) => {
      if (pos < winAt || pos + len > winAt + win.length) {
        win = await reader.bytes(pos, Math.max(len, 1 << 20));
        winAt = pos;
      }
      return win.subarray(pos - winAt, pos - winAt + len);
    };

    // His Usn constructor. A size of zero, one past a page, or a record that
    // is not version 2 sends him to the page after the last one a record
    // started on; that is how he steps over page slack and damage alike.
    let pos = start;
    let lastGood = start;
    while (pos < reader.size) {
      if (ctx.signal?.aborted) return;
      const head = new Uint8Array(8);
      head.set(await view(pos, 8)); // a read past the end leaves zeros, as his buffer does
      const hv = new DataView(head.buffer);
      const size = hv.getUint32(0, true);
      const major = hv.getInt16(4, true);
      if (size === 0) {
        pos = lastGood + PAGE;
        lastGood += PAGE;
        continue;
      }
      if (size > PAGE || size < 0x38 || size > 0x250 || major !== 2) {
        lastGood += PAGE;
        pos = lastGood;
        continue;
      }
      if (pos % PAGE === 0) lastGood = pos;

      const offset = pos;
      const b = new Uint8Array(size);
      const got = await view(pos, size);
      b.set(got); // as with the header, a record cut off by the end of the file reads as zeros
      if (got.length < size) ctx.warn(offset, `the last record is cut off by the end of the file (${got.length} of ${size} bytes)`);
      pos += size;
      const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
      const nameSize = dv.getInt16(56, true);
      const nameOffset = dv.getInt16(58, true);
      if (nameOffset < 0 || nameSize < 0 || nameOffset + nameSize > size) {
        ctx.warn(offset, `record name at 0x${nameOffset.toString(16)}+${nameSize} lies outside the ${size}-byte record; skipped`);
        continue;
      }
      const name = new TextDecoder('utf-16le').decode(b.subarray(nameOffset, nameOffset + nameSize));
      const file = mftInfo(dv, 8);
      const parent = mftInfo(dv, 16);
      const ticks = dv.getBigInt64(32, true);
      if (ticks < 0n || ticks > MAX_FILETIME) ctx.warn(offset, `timestamp 0x${ticks.toString(16)} is outside what a FILETIME can hold`);
      yield {
        Name: name,
        Extension: extension(name),
        EntryNumber: file.entry,
        SequenceNumber: file.seq,
        ParentEntryNumber: parent.entry,
        ParentSequenceNumber: parent.seq,
        ParentPath: paths ? paths(parent.entry, parent.seq) : '',
        UpdateSequenceNumber: Number(dv.getBigUint64(24, true)),
        UpdateTimestamp: ticks >= 0n && ticks <= MAX_FILETIME ? filetime(ticks) : null,
        UpdateReasons: dotnetFlags(dv.getUint32(40, true), REASONS),
        FileAttributes: dotnetFlags(dv.getInt32(52, true), ATTRIBUTES),
        // His record offset is a uint, so past 4 GB it wraps.
        OffsetToData: offset % 2 ** 32,
        SourceFile: reader.name,
      };
    }
  },
};
