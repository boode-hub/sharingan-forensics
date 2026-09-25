/**
 * $MFT, the NTFS master file table: one record for every file and directory
 * the volume has, or had.
 *
 * Ported from Eric Zimmerman's MFT library (https://github.com/EricZimmerman/MFT:
 * FileRecord.cs, Mft.cs, Attributes/*.cs, Other/MftEntryInfo.cs,
 * Other/ExtensionMethods.cs) and MFTECmd's CSV output
 * (https://github.com/EricZimmerman/MFTECmd: ProcessRecords, GetCsvData,
 * MFTRecordOut and the column map in ProcessMft).
 *
 * His library loads every record into memory before writing anything. A
 * $MFT can be gigabytes, so this reads it more than once instead: the first
 * pass keeps only what path building needs (each directory's name and parent)
 * and where the extension records are; then his rows are written in his
 * order - every in-use record, then every free one, one row per file name
 * that is not a DOS 8.3 name, each followed by a row per alternate data stream.
 *
 * Timestamps are shown to the millisecond. His comparisons between them (SI<FN,
 * uSecZeros, Copied, and whether a $FILE_NAME time differs from its
 * $STANDARD_INFORMATION twin) are made on the full 100 ns values, as his are.
 */
import type { Column, ColType, Ctx, Parser, Reader, Row } from '../core/types';
import { filetime, guid, magic } from '../core/binary';

const spaced = (name: string) =>
  name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');

function cols(spec: string, secondary = false): Column[] {
  return spec
    .trim()
    .split(/\s+/)
    .map((s) => {
      const [key, type = 'str', label] = s.split(':');
      return { key, label: label ?? spaced(key), type: type as ColType, ...(secondary ? { secondary } : {}) };
    });
}

// His column map: explicit indexes 0-33, then the resident-data columns he
// leaves unindexed, which are empty unless his --ir option is given.
const columns = [
  ...cols(`EntryNumber:num SequenceNumber:num InUse:bool ParentEntryNumber:num ParentSequenceNumber:num
    ParentPath FileName Extension FileSize:num ReferenceCount:num ReparseTarget IsDirectory:bool HasAds:bool
    IsAds:bool Timestomped:bool:SI<FN uSecZeros:bool Copied:bool SiFlags NameType Created0x10:date
    Created0x30:date LastModified0x10:date LastModified0x30:date LastRecordChange0x10:date
    LastRecordChange0x30:date LastAccess0x10:date LastAccess0x30:date UpdateSequenceNumber:num
    LogfileSequenceNumber:num SecurityId:num ObjectIdFileDroid LoggedUtilStream ZoneIdContents SourceFile`),
  ...cols('ResidentDataBase64 ResidentDataHex ResidentDataASCII Offset:num', true),
];

const FILE = 0x454c4946;

/** His MftEntryInfo: the upper 16 bits of the entry are multiplied by 2^24, not 2^32. */
function entryInfo(dv: DataView, at: number): { entry: number; seq: number } {
  const low = dv.getUint32(at, true);
  const high = dv.getUint16(at + 4, true);
  return { entry: high === 0 ? low : (low + high * 16_777_216) >>> 0, seq: dv.getUint16(at + 6, true) };
}

/**
 * His "XXXXXXXX-XXXXXXXX" record key as a number. A free record is keyed with
 * its sequence number less one, which is -1 for a free record at sequence 0 -
 * a key no parent reference can reach, so the numbering keeps it distinct.
 */
const keyOf = (entry: number, seq: number) => entry * 65537 + seq + 1;
const hex8 = (n: number) => (n >>> 0).toString(16).toUpperCase().padStart(8, '0');
const keyText = (key: number) => `${hex8(Math.floor(key / 65537))}-${hex8((key % 65537) - 1)}`;
const ROOT = keyOf(5, 5);

type Ticks = bigint | null;

/** DateTimeOffset.FromFileTime rejects anything past 9999-12-31, and he then leaves the time empty. */
const MAX_FILETIME = 2650467743999999999n;

const ticksAt = (dv: DataView, at: number): Ticks => {
  if (at + 8 > dv.byteLength) return null;
  const v = dv.getBigInt64(at, true);
  return v > 0n && v <= MAX_FILETIME ? v : null;
};
const toDate = (t: Ticks) => (t === null ? null : filetime(t));

const utf16 = (b: Uint8Array, at: number, len: number) =>
  new TextDecoder('utf-16le').decode(b.subarray(at, Math.max(at, Math.min(at + len, b.length))));

interface FileNameAttr {
  parent: number;
  parentEntry: number;
  parentSeq: number;
  created: Ticks;
  modified: Ticks;
  record: Ticks;
  accessed: Ticks;
  logicalSize: bigint;
  nameType: number;
  name: string;
}

interface Attr {
  type: number;
  name: string;
  resident: boolean;
  /** The whole attribute, header included: $STANDARD_INFORMATION is read from it at his offsets. */
  raw: Uint8Array;
  /** Resident content, AttributeContentLength bytes from the content offset. */
  content: Uint8Array | null;
  startVcn: bigint;
  actualSize: bigint;
  fn?: FileNameAttr;
}

interface Rec {
  offset: number;
  entry: number;
  seq: number;
  flags: number;
  lsn: bigint;
  /** The base record's key when this is an extension record, else null. */
  base: number | null;
  attrs: Attr[];
}

type Warn = (offset: number, message: string) => void;
const quiet: Warn = () => undefined;

/**
 * One FILE record, with the fixup array applied: the last two bytes of every
 * 512-byte sector were swapped for a check value when the record was
 * written, and the real bytes kept in the fixup array.
 */
function parseRecord(raw: Uint8Array, offset: number, warn: Warn): Rec | null {
  const b = raw.slice(); // fixups are applied to a copy, never to the source bytes
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  // BAAD (a record NTFS found torn) and anything without a signature are
  // counted by his library and never written out.
  if (dv.getInt32(0, true) !== FILE) return null;

  const fixupOffset = dv.getInt16(4, true);
  const fixupCount = dv.getInt16(6, true);
  const flags = dv.getInt16(0x16, true);
  const seq = dv.getUint16(0x10, true);
  const entry = dv.getUint32(0x2c, true);
  if (fixupOffset >= 0 && fixupOffset + Math.max(0, fixupCount) * 2 <= b.length) {
    const expected = dv.getInt16(fixupOffset, true);
    for (let i = 1; i < fixupCount; i++) {
      const at = i * 512 - 2;
      if (at + 2 > b.length) break;
      if (dv.getInt16(at, true) !== expected && flags !== 0) {
        warn(offset + at, `entry/seq 0x${entry.toString(16)}/0x${seq.toString(16)}: fixup value does not match; the sector may be torn`);
      }
      b[at] = b[fixupOffset + i * 2];
      b[at + 1] = b[fixupOffset + i * 2 + 1];
    }
  }

  const base = entryInfo(dv, 0x20);
  const rec: Rec = {
    offset,
    entry,
    seq,
    flags,
    lsn: dv.getBigInt64(0x8, true),
    base: base.entry > 0 && base.seq > 0 ? keyOf(base.entry, base.seq) : null,
    attrs: [],
  };

  const used = dv.getInt32(0x18, true);
  let at = dv.getInt16(0x14, true);
  while (at >= 0 && at < used && at + 8 <= b.length) {
    const type = dv.getInt32(at, true);
    const size = dv.getInt32(at + 4, true);
    if (size === 0 || type === -1) break;
    if (size < 0x18 || at + size > b.length) {
      warn(offset + at, `entry 0x${entry.toString(16)}: attribute 0x${(type >>> 0).toString(16)} of ${size} bytes does not fit the record; the rest of the record is skipped`);
      break;
    }
    const a = b.subarray(at, at + size);
    const av = new DataView(a.buffer, a.byteOffset, a.byteLength);
    const resident = a[8] === 0;
    const nameSize = a[9];
    const attr: Attr = {
      type,
      name: nameSize > 0 ? utf16(a, av.getInt16(0xa, true), nameSize * 2) : '',
      resident,
      raw: a,
      content: null,
      startVcn: 0n,
      actualSize: 0n,
    };
    const cOff = av.getInt16(0x14, true);
    if (resident) {
      attr.content = a.subarray(cOff, Math.min(cOff + av.getInt32(0x10, true), a.length));
    } else if (size >= 0x38) {
      attr.startVcn = av.getBigUint64(0x10, true);
      attr.actualSize = av.getBigUint64(0x30, true);
    }
    // A $FILE_NAME is read from its content offset to the end of the attribute.
    const fc = type === 0x30 ? a.subarray(Math.max(0, cOff)) : null;
    if (fc && fc.length >= 0x42) {
      const cv = new DataView(fc.buffer, fc.byteOffset, fc.byteLength);
      const parent = entryInfo(cv, 0);
      attr.fn = {
        parent: keyOf(parent.entry, parent.seq),
        parentEntry: parent.entry,
        parentSeq: parent.seq,
        created: ticksAt(cv, 0x8),
        modified: ticksAt(cv, 0x10),
        record: ticksAt(cv, 0x18),
        accessed: ticksAt(cv, 0x20),
        logicalSize: cv.getBigUint64(0x30, true),
        nameType: fc[0x41],
        name: utf16(fc, 0x42, fc[0x40] * 2),
      };
    } else if (type === 0x30) {
      warn(offset + at, `entry 0x${entry.toString(16)}: $FILE_NAME attribute too short to read`);
    }
    rec.attrs.push(attr);
    at += size;
  }
  return rec;
}

const inUse = (r: { flags: number }) => (r.flags & 0x1) !== 0;
const isDir = (r: { flags: number }) => (r.flags & 0x2) !== 0;
/** His GetKey: a free record is keyed with its sequence number less one. */
const recKey = (r: Rec) => keyOf(r.entry, inUse(r) ? r.seq : r.seq - 1);
const fileNames = (r: Rec) => r.attrs.filter((a) => a.fn).map((a) => a.fn as FileNameAttr);
const firstLongName = (r: Rec) => fileNames(r).find((f) => f.nameType !== 2) ?? null;

/** Path.GetExtension on Windows. */
function extension(name: string): string {
  for (let i = name.length - 1; i >= 0; i--) {
    const c = name[i];
    if (c === '.') return i === name.length - 1 ? '' : name.slice(i);
    if (c === '\\' || c === '/' || c === ':') break;
  }
  return '';
}

// His StandardInfo.Flag.
const SI_FLAGS: Array<[number, string]> = [
  [0x01, 'ReadOnly'],
  [0x02, 'Hidden'],
  [0x04, 'System'],
  [0x08, 'VolumeLabel'],
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
  [0x40000, 'RecallOnOpen'],
  [0x80000, 'Pinned'],
  [0x100000, 'UnPinned'],
  [0x400000, 'RecallOnDataAccess'],
  [0x10000000, 'IsDirectory'],
  [0x20000000, 'IsIndexView'],
];
const KNOWN_SI = SI_FLAGS.reduce((m, [bit]) => m | bit, 0);

/**
 * .NET's ToString of a [Flags] enum, joined with "|" as his map does: names
 * in ascending value order, and the bare number when any bit has no name.
 */
function siFlags(v: number): string {
  if (v === 0) return 'None';
  if ((v & ~KNOWN_SI) !== 0) return String(v);
  return SI_FLAGS.filter(([bit]) => (v & bit) !== 0)
    .map(([, n]) => n)
    .join('|');
}

const NAME_TYPES = ['Posix', 'Windows', 'Dos', 'DosWindows'];

/** His ReparsePoint.SubstituteName, including the offset rules he applies. */
function substituteName(content: Uint8Array): string {
  if (content.length < 16) return '';
  const dv = new DataView(content.buffer, content.byteOffset, content.byteLength);
  const tag = dv.getUint32(0, true);
  let subOffset = dv.getInt16(8, true);
  const subSize = dv.getInt16(10, true);
  if (subSize <= 0) return '';
  const symlink = tag === 0xa000000c;
  if (!symlink && tag !== 0xa0000003) return '';
  // Symbolic links carry four more bytes of flags before their names.
  if (symlink) subOffset += 4;
  subOffset = subOffset === 0 ? 0x10 : 0x14;
  return utf16(content, subOffset, subSize);
}

const CP1252 = new TextDecoder('windows-1252');

/** One of his CSV rows for a record, a file name, and optionally a stream. */
function csvRow(r: Rec, fn: FileNameAttr, ads: Attr | null, parentPath: (key: number) => string, source: string): Row {
  const dir = isDir(r);
  const datas = r.attrs.filter((a) => a.type === 0x80);

  // GetFileSize: nothing for a directory, else the first $DATA, else the name's size.
  let size = 0n;
  if (!dir) {
    if (datas.length > 0) size = datas[0].resident ? BigInt(datas[0].content?.length ?? 0) : datas[0].actualSize;
    else size = r.attrs.find((a) => a.type === 0x30)?.fn?.logicalSize ?? 0n;
  }

  // GetReferenceCount: distinct name-and-parent pairs, DOS names aside.
  const refs = new Set(
    fileNames(r)
      .filter((f) => f.nameType !== 2)
      .map((f) => `${f.name}-${f.parent}`),
  );

  const si = r.attrs.find((a) => a.type === 0x10);
  const oid = r.attrs.find((a) => a.type === 0x40 && a.content && a.content.length >= 16);
  const lus = r.attrs.find((a) => a.type === 0x100);
  const rp = r.attrs.find((a) => a.type === 0xc0 && a.content);

  const row: Row = {
    EntryNumber: r.entry,
    SequenceNumber: r.seq,
    InUse: inUse(r),
    ParentEntryNumber: fn.parentEntry,
    ParentSequenceNumber: fn.parentSeq,
    ParentPath: parentPath(fn.parent),
    FileName: fn.name,
    Extension: dir ? null : extension(fn.name),
    FileSize: Number(size),
    ReferenceCount: refs.size,
    ReparseTarget: rp?.content ? substituteName(rp.content).replaceAll('\\??\\', '') : null,
    IsDirectory: dir,
    HasAds: false,
    IsAds: ads !== null,
    Timestomped: false,
    uSecZeros: false,
    Copied: false,
    SiFlags: 'None',
    NameType: NAME_TYPES[fn.nameType] ?? String(fn.nameType),
    Created0x10: null,
    Created0x30: null,
    LastModified0x10: null,
    LastModified0x30: null,
    LastRecordChange0x10: null,
    LastRecordChange0x30: null,
    LastAccess0x10: null,
    LastAccess0x30: null,
    UpdateSequenceNumber: 0,
    LogfileSequenceNumber: Number(r.lsn),
    SecurityId: 0,
    ObjectIdFileDroid: oid?.content ? guid(oid.content.subarray(0, 16)) : null,
    LoggedUtilStream: lus ? lus.name : null,
    ZoneIdContents: null,
    SourceFile: source,
    ResidentDataBase64: null,
    ResidentDataHex: null,
    ResidentDataASCII: null,
    Offset: r.offset,
  };

  if (ads) {
    row.FileName = `${fn.name}:${ads.name}`;
    row.FileSize = Number(ads.resident ? BigInt(ads.content?.length ?? 0) : ads.actualSize);
    row.Extension = extension(ads.name);
    if (ads.name === 'Zone.Identifier') {
      row.ZoneIdContents = ads.resident && ads.content ? CP1252.decode(ads.content) : '(Zone.Identifier data is non-resident)';
    }
  }

  if (si && si.raw.length >= 0x48) {
    // His StandardInfo reads the attribute from its start, not from its content.
    const sv = new DataView(si.raw.buffer, si.raw.byteOffset, si.raw.byteLength);
    const created = ticksAt(sv, 0x18);
    const modified = ticksAt(sv, 0x20);
    const record = ticksAt(sv, 0x28);
    const accessed = ticksAt(sv, 0x30);
    row.Created0x10 = toDate(created);
    row.LastModified0x10 = toDate(modified);
    row.LastRecordChange0x10 = toDate(record);
    row.LastAccess0x10 = toDate(accessed);
    row.Copied = modified !== null && created !== null && modified < created;
    // A $FILE_NAME time is shown only when it differs from its SI twin.
    if (fn.created !== created) row.Created0x30 = toDate(fn.created);
    if (fn.modified !== modified) row.LastModified0x30 = toDate(fn.modified);
    if (fn.record !== record) row.LastRecordChange0x30 = toDate(fn.record);
    if (fn.accessed !== accessed) row.LastAccess0x30 = toDate(fn.accessed);
    row.SiFlags = siFlags(sv.getInt32(0x38, true));
    // An NTFS 1.2 record's SI stops at 0x48, before the security id and USN.
    if (si.raw.length >= 0x60) {
      row.SecurityId = sv.getInt32(0x4c, true);
      row.UpdateSequenceNumber = Number(sv.getBigInt64(0x58, true));
    }
    row.Timestomped = row.Created0x30 !== null && created !== null && fn.created !== null && created < fn.created;
    const zeroMs = (t: Ticks) => t !== null && (t / 10000n) % 1000n === 0n;
    row.uSecZeros = zeroMs(created) || zeroMs(modified);
  } else {
    // With no $STANDARD_INFORMATION he fills the SI columns from the name, created aside.
    row.Created0x30 = toDate(fn.created);
    row.LastModified0x10 = toDate(fn.modified);
    row.LastRecordChange0x10 = toDate(fn.record);
    row.LastAccess0x10 = toDate(fn.accessed);
  }
  return row;
}

/** Records in file order, read about a megabyte at a time. */
async function* records(reader: Reader, size: number, ctx: Ctx): AsyncGenerator<{ raw: Uint8Array; offset: number }> {
  const step = size * Math.max(1, Math.floor((1 << 20) / size));
  for (let at = 0; at < reader.size; at += step) {
    if (ctx.signal?.aborted) return;
    const block = await reader.bytes(at, step);
    for (let o = 0; o + size <= block.length; o += size) yield { raw: block.subarray(o, o + size), offset: at + o };
  }
}

const allocatedSize = (head: Uint8Array) =>
  head.length >= 0x20 ? new DataView(head.buffer, head.byteOffset, head.byteLength).getInt32(0x1c, true) : 0;

interface DirName {
  name: string;
  parent: number;
}
interface ExtensionRec {
  offset: number;
  dir: boolean;
  name: DirName | null;
}

export const mft: Parser = {
  id: 'mft',
  name: '$MFT',
  ezTool: 'MFTECmd',
  extensions: [],
  columns,
  sniff(head: Uint8Array): boolean {
    const size = allocatedSize(head);
    return magic(head, 'FILE', 0) && (size === 1024 || size === 4096);
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const size = allocatedSize(await reader.bytes(0, 0x20));
    if (size !== 1024 && size !== 4096) {
      ctx.warn(0, `the first record gives a record size of ${size}; a $MFT uses 1024 or 4096`);
      return;
    }
    if (reader.size % size !== 0) ctx.warn(reader.size, `the file is not a whole number of ${size}-byte records; the tail is ignored`);

    // Pass 1: what his dictionaries would hold, keyed as his are, less the
    // attributes. A record whose key is already taken is skipped, as he skips it.
    // ponytail: a key per record held in Sets (~50 MB per million records); a typed hash if 10M-record volumes show up.
    const usedKeys = new Set<number>();
    const freeKeys = new Set<number>();
    const skipped = new Set<number>();
    const extensions = new Map<number, ExtensionRec[]>();
    const usedDirs = new Map<number, DirName | null>();
    const freeDirs = new Map<number, DirName | null>();

    for await (const { raw, offset } of records(reader, size, ctx)) {
      const r = parseRecord(raw, offset, ctx.warn);
      if (!r) continue;
      const key = recKey(r);
      const keys = inUse(r) ? usedKeys : freeKeys;
      const first = firstLongName(r);
      const name = first ? { name: first.name, parent: first.parent } : null;
      if (keys.has(key)) {
        skipped.add(offset);
        ctx.warn(offset, `a ${inUse(r) ? '' : 'free '}FILE record with key ${keyText(key)} already exists; skipped, as his tool skips it`);
      } else {
        keys.add(key);
        if (r.base === null && isDir(r)) (inUse(r) ? usedDirs : freeDirs).set(key, name);
      }
      // An extension record is filed under its base record even when its own key repeats.
      if (r.base !== null) {
        const list = extensions.get(r.base) ?? [];
        list.push({ offset, dir: isDir(r), name });
        extensions.set(r.base, list);
      }
    }

    // Extension records are merged into the in-use record with their base key,
    // or failing that the free one.
    const mergesInto = (r: Rec) => inUse(r) || !usedKeys.has(recKey(r));
    const extensionName = (key: number) => extensions.get(key)?.find((e) => e.name)?.name ?? null;

    // His BuildMaps: in-use directories, then free ones, then extension
    // records whose base record is missing. The first name for a key wins.
    const dirMap = new Map<number, DirName>();
    for (const [key, name] of usedDirs) {
      const n = name ?? extensionName(key);
      if (n && !dirMap.has(key)) dirMap.set(key, n);
    }
    for (const [key, name] of freeDirs) {
      const n = name ?? (usedKeys.has(key) ? null : extensionName(key));
      if (n && !dirMap.has(key)) dirMap.set(key, n);
    }
    for (const [key, list] of extensions) {
      if (usedKeys.has(key) || freeKeys.has(key)) continue;
      for (const e of list) if (e.dir && e.name && !dirMap.has(key)) dirMap.set(key, e.name);
    }
    usedDirs.clear();
    freeDirs.clear();

    const pathCache = new Map<number, string>();
    const parentPath = (key: number): string => {
      const hit = pathCache.get(key);
      if (hit !== undefined) return hit;
      const parts: string[] = [];
      const seen = new Set<number>();
      let k = key;
      // A directory that is its own ancestor would loop his walk forever; this stops at the repeat.
      for (let d = dirMap.get(k); d && !seen.has(k); d = dirMap.get(k)) {
        seen.add(k);
        parts.push(d.name);
        if (k === ROOT) break;
        k = d.parent;
      }
      if (k !== ROOT) parts.push(`.\\PathUnknown\\Directory with ID 0x${keyText(k)}`);
      const path = parts.reverse().join('\\');
      pathCache.set(key, path);
      return path;
    };

    // His FileRecords, then his FreeFileRecords.
    for (const wanted of [true, false]) {
      for await (const { raw, offset } of records(reader, size, ctx)) {
        // Signature and flags sit before the first fixup, so they can be checked unfixed.
        if (raw[0] !== 0x46 || raw[1] !== 0x49 || raw[2] !== 0x4c || raw[3] !== 0x45) continue;
        if (((raw[0x16] & 1) !== 0) !== wanted || skipped.has(offset)) continue;
        const r = parseRecord(raw, offset, quiet);
        if (!r || r.base !== null) continue;
        if (mergesInto(r)) {
          for (const e of extensions.get(recKey(r)) ?? []) {
            const x = parseRecord(await reader.bytes(e.offset, size), e.offset, quiet);
            if (x) r.attrs.push(...x.attrs);
          }
        }
        // Named $DATA streams, less the later pieces of a non-resident one.
        const ads = r.attrs.filter((a) => a.type === 0x80 && a.name !== '' && (a.resident || a.startVcn === 0n));
        const names = fileNames(r)
          .filter((f) => f.nameType !== 2)
          .sort((x, y) => x.nameType - y.nameType);
        for (const fn of names) {
          const row = csvRow(r, fn, null, parentPath, reader.name);
          row.HasAds = ads.length > 0;
          yield row;
          for (const s of ads) yield csvRow(r, fn, s, parentPath, reader.name);
        }
      }
    }
  },
};
