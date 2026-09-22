/**
 * Windows Registry hive (`regf`) parser.
 * Ported from Eric Zimmerman's Registry Explorer / RECmd — see .refs/
 *   RegistryBase.cs (header), Cells/NKCellRecord.cs (keys),
 *   Cells/VkCellRecord.cs (values incl. big data), Lists/LxListRecord.cs,
 *   Lists/LIListRecord.cs, Lists/RIListRecord.cs, Lists/DBListRecord.cs,
 *   Other/HBinRecord.cs (cell walking), Other/Helpers.cs (signatures),
 *   RegistryHive.cs (the walker), Abstractions/RegistryKey.cs (paths).
 *
 * Scope: full key/value enumeration, transaction log replay (see
 * registry/translog.ts), and recovery of deleted keys and unassociated values
 * from unallocated cells. RECmd plugins are not attempted here.
 */
import type { Column, Parser, Reader, Ctx, Row } from '../core/types';
import { Cursor, filetime, magic } from '../core/binary';
import { MAX_ROWS } from '../core/registry';
import { replayIfDirty } from './registry/translog';

const columns: Column[] = [
  { key: 'keyPath', label: 'Key Path', type: 'str' },
  { key: 'valueName', label: 'Value Name', type: 'str' },
  { key: 'valueType', label: 'Value Type', type: 'str' },
  { key: 'valueData', label: 'Value Data', type: 'str' },
  { key: 'isDeleted', label: 'Deleted', type: 'bool' },
  { key: 'lastWritten', label: 'Last Written', type: 'date' },
  { key: 'valueSlack', label: 'Value Slack', type: 'str', secondary: true },
  { key: 'hiveType', label: 'Hive Type', type: 'str' },
  { key: 'sourceFile', label: 'Source File', type: 'str' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
];

/**
 * His HiveTypeEnum, keyed by the base name the hive records in its own header.
 * The name a hive is saved under tells you nothing; the embedded one does.
 */
const HIVE_TYPES: Record<string, string> = {
  'ntuser.dat': 'NtUser',
  sam: 'Sam',
  security: 'Security',
  software: 'Software',
  system: 'System',
  drivers: 'Drivers',
  'usrclass.dat': 'UsrClass',
  components: 'Components',
  bcd: 'Bcd',
  'amcache.hve': 'Amcache',
  'amcache.hve.tmp': 'Amcache',
  'syscache.hve': 'Syscache',
  elam: 'Elam',
  default: 'Default',
  vsmidk: 'Vsmidk',
  bcdtemplate: 'BcdTemplate',
  bbi: 'Bbi',
  userdiff: 'Userdiff',
};

function hiveTypeFromName(embedded: string): string {
  const base = embedded.split('\\').pop()?.toLowerCase() ?? '';
  return HIVE_TYPES[base] ?? 'Other';
}

// The shared ceiling from src/core/registry.ts. Checked here as well as there
// so the walk stops descending rather than building rows the caller discards.

// 2-char cell signatures as little-endian int16 (Helpers.cs constants).
const NK = 0x6b6e; // "nk"
const VK = 0x6b76; // "vk"
const LF = 0x666c; // "lf"
const LH = 0x686c; // "lh"
const LI = 0x696c; // "li"
const RI = 0x6972; // "ri"
const DB = 0x6264; // "db"
const HBIN = 0x6e696268; // "hbin"

// NK flag: this key is the hive entry root key (NKCellRecord.FlagEnum).
const NK_FLAG_ROOT = 0x0004;
// NK flag: the key name is stored as ASCII (cp1252), not UTF-16LE.
const NK_FLAG_COMPRESSED_NAME = 0x0020;

const REG_TYPE_NAMES: Record<number, string> = {
  0x0000: 'REG_NONE',
  0x0001: 'REG_SZ',
  0x0002: 'REG_EXPAND_SZ',
  0x0003: 'REG_BINARY',
  0x0004: 'REG_DWORD',
  0x0005: 'REG_DWORD_BIG_ENDIAN',
  0x0006: 'REG_LINK',
  0x0007: 'REG_MULTI_SZ',
  0x0008: 'REG_RESOURCE_LIST',
  0x0009: 'REG_FULL_RESOURCE_DESCRIPTOR',
  0x000A: 'REG_RESOURCE_REQUIREMENTS_LIST',
  0x000B: 'REG_QWORD',
  0x0010: 'REG_FILETIME',
  0x0101: 'REG_UWP_BYTE',
  0x0102: 'REG_UWP_INT16',
  0x0103: 'REG_UWP_UINT16',
  0x0104: 'REG_UWP_INT32',
  0x0105: 'REG_UWP_UINT32',
  0x0106: 'REG_UWP_INT64',
  0x0107: 'REG_UWP_UINT64',
  0x0108: 'REG_UWP_SINGLE',
  0x0109: 'REG_UWP_DOUBLE',
  0x010A: 'REG_UWP_CHAR',
  0x010B: 'REG_UWP_BOOLEAN',
  0x010C: 'REG_UWP_STRING',
  0x010D: 'REG_UWP_COMPOSITE_VALUE',
  0x010E: 'REG_UWP_DATETIMEOFFSET',
  0x010F: 'REG_UWP_TIMESPAN',
  0x0110: 'REG_UWP_GUID',
  0x0111: 'REG_UWP_POINT',
  0x0112: 'REG_UWP_SIZE',
  0x0113: 'REG_UWP_RECT',
  0x0114: 'REG_UWP_ARRAY_BYTE',
  0x0115: 'REG_UWP_ARRAY_INT16',
  0x0116: 'REG_UWP_ARRAY_UINT16',
  0x0117: 'REG_UWP_ARRAY_INT32',
  0x0118: 'REG_UWP_ARRAY_UINT32',
  0x0119: 'REG_UWP_ARRAY_INT64',
  0x011A: 'REG_UWP_ARRAY_UINT64',
  0x011B: 'REG_UWP_ARRAY_SINGLE',
  0x011C: 'REG_UWP_ARRAY_DOUBLE',
  0x011D: 'REG_UWP_ARRAY_CHAR',
  0x011E: 'REG_UWP_ARRAY_BOOLEAN',
  0x011F: 'REG_UWP_ARRAY_STRING',
  0x0120: 'REG_UWP_ARRAY_DATETIMEOFFSET',
  0x0121: 'REG_UWP_ARRAY_TIMESPAN',
  0x0122: 'REG_UWP_ARRAY_GUID',
  0x0123: 'REG_UWP_ARRAY_POINT',
  0x0124: 'REG_UWP_ARRAY_SIZE',
  0x0125: 'REG_UWP_ARRAY_RECT',
};

const UWP_MAX = 0x0125;

function regTypeName(raw: number): string {
  if (raw > UWP_MAX) return 'REG_UNKNOWN';
  return REG_TYPE_NAMES[raw] ?? 'REG_UNKNOWN';
}

export interface CellRec {
  sig: string;
  rel: number;
  buf: Uint8Array;
}

function cellSig(buf: Uint8Array): number {
  if (buf.length < 6) return 0;
  return buf[4] | (buf[5] << 8);
}

export function isFree(buf: Uint8Array): boolean {
  if (buf.length < 4) return true;
  return new DataView(buf.buffer, buf.byteOffset, 4).getInt32(0, true) > 0;
}

/**
 * Walk every hbin and collect the allocated nk/vk cells and list records,
 * keyed by their relative (post-4096-header) offset — mirrors EZ's
 * CellRecords / ListRecords dictionaries. Free cells are kept too: a cell the
 * live tree never reaches is what deleted-key recovery works from.
 */
export async function collectCells(
  reader: Reader,
  ctx: Ctx,
  hbinLength: number,
): Promise<{ cells: Map<number, CellRec>; lists: Map<number, CellRec>; rootOffsets: number[] }> {
  const cells = new Map<number, CellRec>();
  const lists = new Map<number, CellRec>();
  const rootOffsets: number[] = [];

  const hbinStart = 4096;
  const end = Math.min(reader.size, hbinStart + hbinLength);
  let pos = hbinStart;

  while (pos < end) {
    if (ctx.signal?.aborted) break;
    const head = await reader.bytes(pos, 0x20);
    if (head.length < 4) break;
    if (new DataView(head.buffer, head.byteOffset, 4).getInt32(0, true) !== HBIN) {
      ctx.warn(pos, `invalid hbin signature at offset 0x${pos.toString(16)} — stopping hbin walk`);
      break;
    }
    if (head.length < 0x20) break;
    const hbinSize = new DataView(head.buffer, head.byteOffset + 8, 4).getUint32(0, true);
    if (hbinSize < 0x20 || pos + hbinSize > reader.size) {
      ctx.warn(pos, `implausible hbin size ${hbinSize} at offset 0x${pos.toString(16)} — stopping hbin walk`);
      break;
    }
    const hbin = await reader.bytes(pos, hbinSize);
    if (hbin.length < hbinSize) {
      ctx.warn(pos, `short read of hbin at offset 0x${pos.toString(16)}`);
      break;
    }
    const hbinRel = pos - 4096;

    let off = 0x20;
    while (off < hbinSize) {
      if (ctx.signal?.aborted) break;
      if (off + 4 > hbinSize) break;
      const recSize = Math.abs(new DataView(hbin.buffer, hbin.byteOffset + off, 4).getInt32(0, true));
      if (recSize < 4 || off + recSize > hbinSize) break;
      const rec = hbin.subarray(off, off + recSize);
      const sig = cellSig(rec);
      const rel = hbinRel + off;
      if (sig === NK && rec.length >= 0x30) {
        const flags = rec[6] | (rec[7] << 8);
        cells.set(rel, { sig: 'nk', rel, buf: rec });
        if ((flags & NK_FLAG_ROOT) !== 0) rootOffsets.push(rel);
      } else if (sig === VK && rec.length >= 0x18) {
        cells.set(rel, { sig: 'vk', rel, buf: rec });
      } else if (sig === LF || sig === LH || sig === LI || sig === RI || sig === DB) {
        lists.set(rel, { sig: '', rel, buf: rec });
      }
      off += recSize;
    }

    pos += hbinSize;
  }

  return { cells, lists, rootOffsets };
}

/** Read a size-prefixed data cell (value list, big-data, class) at relative offset. Returns bytes after the size header. */
export async function readDataCell(reader: Reader, rel: number): Promise<Uint8Array | null> {
  const abs = rel + 4096;
  if (abs < 0 || abs + 4 > reader.size) return null;
  const sizeBuf = await reader.bytes(abs, 4);
  if (sizeBuf.length < 4) return null;
  const size = Math.abs(new DataView(sizeBuf.buffer, sizeBuf.byteOffset, 4).getInt32(0, true));
  if (size <= 4) return null;
  const data = await reader.bytes(abs + 4, size - 4);
  return data;
}

/** Raw bytes of the whole data cell (including its 4-byte size header) at a relative offset. */
export async function readCellRaw(reader: Reader, rel: number): Promise<Uint8Array | null> {
  const abs = rel + 4096;
  if (abs < 0 || abs + 4 > reader.size) return null;
  const sizeBuf = await reader.bytes(abs, 4);
  if (sizeBuf.length < 4) return null;
  const size = Math.abs(new DataView(sizeBuf.buffer, sizeBuf.byteOffset, 4).getInt32(0, true));
  if (size < 4 || abs + size > reader.size) return null;
  return reader.bytes(abs, size);
}

export function utf16Text(buf: Uint8Array): string {
  let s = '';
  for (let i = 0; i + 1 < buf.length; i += 2) {
    const c = buf[i] | (buf[i + 1] << 8);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function hexBytes(buf: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < buf.length; i++) parts.push(buf[i].toString(16).padStart(2, '0').toUpperCase());
  return parts.join(' ');
}

/**
 * Render a VK's value data exactly as Registry Explorer's VkCellRecord.ValueData
 * does, then stringify per our column contract (strings as text, numbers as
 * decimal, binary as uppercase hex).
 */
function renderValueData(buf: Uint8Array, dataLen: number, dataTypeRaw: number, internalDataOffset: number): string {
  const dataType = dataTypeRaw > UWP_MAX ? 999 : dataTypeRaw;
  const start = internalDataOffset;

  switch (dataType) {
    case 0x0001: // REG_SZ
    case 0x0002: // REG_EXPAND_SZ
    case 0x0007: // REG_MULTI_SZ
    case 0x0006: // REG_LINK
    {
      const end = Math.min(start + dataLen, buf.length);
      let s = utf16Text(buf.subarray(start, end));
      // EZ splits on double-NUL and re-joins MULTI_SZ components with spaces.
      const dblNul = s.indexOf('\u0000\u0000');
      if (dblNul > -1) {
        const base = s.slice(0, dblNul);
        s = base.split('\u0000').join(' ');
      } else {
        s = s.split('\u0000').join(' ');
      }
      return s.replace(/\u0000/g, '').trim();
    }
    case 0x0003: // REG_BINARY
    case 0x0000: // REG_NONE
    case 0x0008: // REG_RESOURCE_LIST
    case 0x0009: // REG_FULL_RESOURCE_DESCRIPTOR
    case 0x000A: // REG_RESOURCE_REQUIREMENTS_LIST
    case 999: // REG_UNKNOWN
      return hexBytes(buf.subarray(start, Math.min(start + dataLen, buf.length)));
    case 0x0004: // REG_DWORD
      return dataLen === 4 ? new DataView(buf.buffer, buf.byteOffset + start, 4).getUint32(0, true).toString() : '0';
    case 0x0005: {
      // REG_DWORD_BIG_ENDIAN — EZ reverses the block then reads u32.
      if (buf.length - start < 4) return '0';
      const b = buf.subarray(start, start + 4);
      return (((b[3] | (b[2] << 8) | (b[1] << 16) | (b[0] << 24)) >>> 0).toString());
    }
    case 0x000B: // REG_QWORD
      return dataLen === 8
        ? new DataView(buf.buffer, buf.byteOffset + start, 8).getBigUint64(0, true).toString()
        : '0';
    case 0x0010: {
      // REG_FILETIME
      if (buf.length - start < 8) return '';
      const ticks = new DataView(buf.buffer, buf.byteOffset + start, 8).getBigUint64(0, true);
      const d = filetime(ticks);
      return d ? d.toISOString() : '';
    }
    case 0x0101:
      return `0x${buf[start].toString(16).padStart(2, '0').toUpperCase()}`;
    case 0x0102:
      return new DataView(buf.buffer, buf.byteOffset + start, 2).getInt16(0, true).toString();
    case 0x0103:
      return new DataView(buf.buffer, buf.byteOffset + start, 2).getUint16(0, true).toString();
    case 0x0104:
      return new DataView(buf.buffer, buf.byteOffset + start, 4).getInt32(0, true).toString();
    case 0x0105:
      return new DataView(buf.buffer, buf.byteOffset + start, 4).getUint32(0, true).toString();
    case 0x0106:
      return new DataView(buf.buffer, buf.byteOffset + start, 8).getBigInt64(0, true).toString();
    case 0x0107:
      return new DataView(buf.buffer, buf.byteOffset + start, 8).getBigUint64(0, true).toString();
    case 0x0108:
      return new DataView(buf.buffer, buf.byteOffset + start, 4).getFloat32(0, true).toString();
    case 0x0109:
      return new DataView(buf.buffer, buf.byteOffset + start, 8).getFloat64(0, true).toString();
    case 0x010A:
      return String.fromCharCode(new DataView(buf.buffer, buf.byteOffset + start, 2).getUint16(0, true));
    case 0x010B:
      return new DataView(buf.buffer, buf.byteOffset + start, 1).getUint8(0) !== 0 ? 'True' : 'False';
    case 0x010C: {
      let e = start;
      while (e + 1 < buf.length && !(buf[e] === 0 && buf[e + 1] === 0)) e += 2;
      return utf16Text(buf.subarray(start, e));
    }
    case 0x0110:
      return guidHex(buf, start);
    default:
      return hexBytes(buf.subarray(start, Math.min(start + dataLen, buf.length)));
  }
}

/** A raw value as his KeyValue.ValueData renders it. */
export function valueText(v: RawValue): string {
  return renderValueData(v.bytes, v.bytes.length, v.type, 0);
}

function guidHex(buf: Uint8Array, start: number): string {
  if (start + 16 > buf.length) return '';
  const h = (n: number) => buf[start + n].toString(16).padStart(2, '0');
  return (
    `${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-` +
    `${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`
  );
}

/** The fields of an nk cell, read once so every caller agrees on the layout. */
export interface KeyRecord {
  flags: number;
  lastWrite: Date | null;
  parentRel: number;
  subkeyCount: number;
  subkeyListRel: number;
  valueCount: number;
  valueListRel: number;
  name: string;
}

export function parseKey(buf: Uint8Array): KeyRecord | null {
  if (buf.length < 0x50) return null;
  const c = new Cursor(buf, 6);
  const flags = c.u16();
  const lastWrite = c.filetime();
  c.skip(4); // access
  const parentRel = c.u32();
  const subkeyCount = c.u32();
  c.u32(); // volatile subkey count
  const subkeyListRel = c.u32();
  c.u32(); // volatile subkey list
  const valueCount = c.u32();
  const valueListRel = c.u32();
  c.skip(4 + 4 + 4 + 4 + 8 + 4); // security, class, maxima, workvar
  const nameLen = c.u16();
  if (buf.length < 0x50 + nameLen) return null;
  const name =
    (flags & NK_FLAG_COMPRESSED_NAME) !== 0
      ? asciiBytes(buf.subarray(0x50, 0x50 + nameLen))
      : utf16Text(buf.subarray(0x50, 0x50 + nameLen * 2));
  return {
    flags,
    lastWrite,
    parentRel,
    subkeyCount,
    subkeyListRel,
    valueCount,
    valueListRel,
    name,
  };
}

/**
 * A value's name, type and raw bytes.
 *
 * Artifacts stored inside the registry keep their own binary structures in
 * value data, so they need the bytes rather than the rendered string a grid
 * would show.
 */
export interface RawValue {
  name: string;
  type: number;
  bytes: Uint8Array;
}

export async function readRawValue(
  reader: Reader,
  vk: CellRec,
  minor: number,
): Promise<RawValue | null> {
  const buf = vk.buf;
  if (buf.length < 0x18) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const nameLen = dv.getUint16(6, true);
  const dataLenRaw = dv.getUint32(8, true);
  const offsetToData = dv.getUint32(0x0c, true);
  const type = dv.getUint32(0x10, true) & 0x00000fff;
  const namePresent = dv.getUint16(0x14, true);

  let name = '(default)';
  if (nameLen > 0) {
    name =
      namePresent > 0
        ? asciiBytes(buf.subarray(0x18, 0x18 + nameLen))
        : utf16Text(buf.subarray(0x18, 0x18 + nameLen * 2));
  }

  const resident = (dataLenRaw & 0x80000000) !== 0;
  const dataLen = resident ? dataLenRaw & 0x7fffffff : dataLenRaw;

  if (resident) {
    return { name, type, bytes: buf.subarray(0x0c, Math.min(0x0c + dataLen, buf.length)) };
  }

  const cell = await readCellRaw(reader, offsetToData);
  if (!cell) return null;

  if (dataLen > 16344 && minor > 3) {
    // Big data: the cell is a list of fragments, each holding up to 16344 bytes.
    if (cell.length < 0x0c) return null;
    const cv = new DataView(cell.buffer, cell.byteOffset, cell.byteLength);
    const count = cv.getUint16(6, true);
    const listCell = await readCellRaw(reader, cv.getUint32(8, true));
    if (!listCell) return null;
    const parts: Uint8Array[] = [];
    let total = 0;
    for (let i = 1; i <= count; i++) {
      if (i * 4 + 4 > listCell.length) break;
      const segRel = new DataView(listCell.buffer, listCell.byteOffset + i * 4, 4).getUint32(0, true);
      const seg = await readCellRaw(reader, segRel);
      if (!seg || seg.length <= 4) continue;
      const part = seg.subarray(4, 4 + Math.min(seg.length - 4, 16344));
      parts.push(part);
      total += part.length;
    }
    const out = new Uint8Array(total);
    let at = 0;
    for (const part of parts) {
      out.set(part, at);
      at += part.length;
    }
    return { name, type, bytes: out.subarray(0, Math.min(dataLen, out.length)) };
  }

  return { name, type, bytes: cell.subarray(4, Math.min(4 + dataLen, cell.length)) };
}

export const registry: Parser = {
  id: 'registry',
  name: 'Registry Hive',
  ezTool: 'Registry Explorer',
  extensions: [],
  columns,
  sniff(head: Uint8Array): boolean {
    return magic(head, 'regf', 0);
  },
  async *parse(source: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const reader = await replayIfDirty(source, ctx);

    if (reader.size < 4096) {
      ctx.warn(0, `hive too small to contain a header (${reader.size} bytes)`);
      return;
    }

    const header = await reader.bytes(0, 4096);
    const hc = new Cursor(header);
    const sig = hc.ascii(4);
    if (sig !== 'regf') {
      ctx.warn(0, `not a registry hive (signature '${sig}')`);
      return;
    }
    const primarySeq = hc.u32();
    const secondarySeq = hc.u32();
    hc.skip(8); // last written
    hc.u32(); // major version
    const minor = hc.u32();
    hc.skip(8); // file type, format
    const rootRel = hc.u32();
    const hbinLength = hc.u32();
    hc.skip(32); // clustering factor + reserved
    // The hive records its own path; the base name of it is what identifies
    // the hive, whatever the file has since been renamed to.
    const embeddedName = hc.utf16(64);
    const hiveType = hiveTypeFromName(embeddedName);

    if (primarySeq !== secondarySeq) {
      ctx.warn(
        4,
        `hive is dirty (sequence numbers ${primarySeq} and ${secondarySeq} differ): changes are sitting in its .LOG1 and .LOG2 files. Open those alongside it and they will be replayed, otherwise these rows are the hive as it was last flushed`,
      );
    }

    const { cells, lists, rootOffsets } = await collectCells(reader, ctx, hbinLength);

    // Find root: prefer an nk flagged as the hive entry root key, else the header offset.
    let rootRelFinal = rootRel;
    if (rootOffsets.length > 0) rootRelFinal = rootOffsets[0];
    let rootCell = cells.get(rootRelFinal);
    if (!rootCell || rootCell.sig !== 'nk') {
      // last resort: any nk flagged as root
      rootCell = cells.get(rootRelFinal);
    }
    if (!rootCell) {
      ctx.warn(rootRel, `root key not found (relative offset 0x${rootRel.toString(16)})`);
      return;
    }

    const visited = new Set<number>();
    // Every vk the live tree reaches. What is left over is either a value of a
    // deleted key or an orphan, and either way it is evidence of something
    // that used to be there.
    const referencedValues = new Set<number>();
    // Path of every live key by its cell offset, so a deleted key whose parent
    // survived can be reported under the parent's real path.
    const livePaths = new Map<number, string>();
    let rows = 0;
    const capped = { hit: false };
    const common = { hiveType, sourceFile: reader.name };

    async function* emitKey(cell: CellRec, parentPath: string): AsyncGenerator<Row> {
      if (ctx.signal?.aborted) return;
      if (visited.has(cell.rel)) {
        ctx.warn(cell.rel, `cycle detected at key cell 0x${cell.rel.toString(16)} — stopping descent`);
        return;
      }
      visited.add(cell.rel);

      if (rows >= MAX_ROWS) {
        if (!capped.hit) {
          capped.hit = true;
          ctx.warn(0, `row cap of ${MAX_ROWS.toLocaleString()} reached — results are partial`);
        }
        return;
      }

      const buf = cell.buf;
      const c = new Cursor(buf, 6);
      const flags = c.u16();
      const lastWrite = c.filetime();
      c.skip(4); // access
      c.u32(); // parent
      const subkeyCount = c.u32();
      c.u32(); // volatile subkey count
      const subkeyListRel = c.u32();
      c.u32(); // volatile subkey list
      const valueListCount = c.u32();
      const valueListRel = c.u32();
      c.skip(4); // security
      c.skip(4); // class
      c.skip(4); // max name len + flags
      c.skip(4); // max class len
      c.skip(8); // max value name/data len
      c.skip(4); // workvar
      const nameLen = c.u16();
      c.skip(2); // class length
      let keyName: string;
      if ((flags & NK_FLAG_COMPRESSED_NAME) !== 0) {
        keyName = asciiBytes(buf.subarray(0x50, 0x50 + nameLen));
      } else {
        keyName = utf16Text(buf.subarray(0x50, 0x50 + nameLen * 2));
      }
      const keyPath = parentPath === '' ? keyName : `${parentPath}\\${keyName}`;

      livePaths.set(cell.rel, keyPath);

      const rowOffset = cell.rel + 4096;

      // Values: read the value-list data cell for the count, resolve each vk.
      const values: Row[] = [];
      if (valueListRel > 0 && valueListRel !== 0xffffffff && valueListCount > 0) {
        const list = await readDataCell(reader, valueListRel);
        if (list) {
          const n = Math.min(valueListCount, Math.floor(list.length / 4));
          for (let i = 0; i < n; i++) {
            const vkRel = new DataView(list.buffer, list.byteOffset + i * 4, 4).getUint32(0, true);
            const vk = cells.get(vkRel);
            if (!vk || vk.sig !== 'vk') {
              ctx.warn(vkRel, `expected value cell missing at 0x${vkRel.toString(16)}`);
              continue;
            }
            referencedValues.add(vkRel);
            const val = await decodeValue(reader, vk, minor);
            if (val) values.push(val);
          }
        }
      }

      if (values.length === 0) {
        // Key-only row so the key is visible even without values.
        if (rows >= MAX_ROWS) {
          if (!capped.hit) {
            capped.hit = true;
            ctx.warn(0, `row cap of ${MAX_ROWS.toLocaleString()} reached — results are partial`);
          }
          return;
        }
        rows++;
        yield {
          ...common,
          keyPath,
          valueName: null,
          valueType: null,
          valueData: null,
          valueSlack: null,
          isDeleted: false,
          lastWritten: lastWrite,
          offset: rowOffset,
        };
      } else {
        for (const v of values) {
          if (rows >= MAX_ROWS) {
            if (!capped.hit) {
              capped.hit = true;
              ctx.warn(0, `row cap of ${MAX_ROWS.toLocaleString()} reached — results are partial`);
            }
            return;
          }
          rows++;
          yield { ...common, keyPath, isDeleted: false, lastWritten: lastWrite, offset: rowOffset, ...v };
        }
      }

      // Subkeys: follow the stable subkey list (lf/lh/ri/li).
      if (subkeyCount > 0 && subkeyListRel > 0 && subkeyListRel !== 0xffffffff) {
        const list = lists.get(subkeyListRel);
        if (!list) {
          ctx.warn(subkeyListRel, `subkey list missing at 0x${subkeyListRel.toString(16)}`);
          return;
        }
        yield* walkSubkeyList(list, keyPath);
      }
    }

    async function* walkSubkeyList(list: CellRec, parentPath: string): AsyncGenerator<Row> {
      const sig = cellSig(list.buf);
      const n = new DataView(list.buf.buffer, list.buf.byteOffset + 6, 2).getUint16(0, true);
      if (sig === LF || sig === LH) {
        // entries: [rel:4][hash:4]
        for (let i = 0; i < n; i++) {
          if (i * 8 + 4 > list.buf.length - 8) break;
          const rel = new DataView(list.buf.buffer, list.buf.byteOffset + 8 + i * 8, 4).getUint32(0, true);
          const nk = cells.get(rel);
          if (!nk || nk.sig !== 'nk') {
            ctx.warn(rel, `subkey cell missing at 0x${rel.toString(16)}`);
            continue;
          }
          yield* emitKey(nk, parentPath);
        }
      } else if (sig === LI) {
        for (let i = 0; i < n; i++) {
          if (i * 4 + 4 > list.buf.length - 8) break;
          const rel = new DataView(list.buf.buffer, list.buf.byteOffset + 8 + i * 4, 4).getUint32(0, true);
          if (rel === 0) break;
          const nk = cells.get(rel);
          if (!nk || nk.sig !== 'nk') {
            ctx.warn(rel, `subkey cell missing at 0x${rel.toString(16)}`);
            continue;
          }
          yield* emitKey(nk, parentPath);
        }
      } else if (sig === RI) {
        // entries point to sub-lists (li or lh/lf).
        for (let i = 0; i < n; i++) {
          if (i * 4 + 4 > list.buf.length - 8) break;
          const rel = new DataView(list.buf.buffer, list.buf.byteOffset + 8 + i * 4, 4).getUint32(0, true);
          const sub = lists.get(rel);
          if (!sub) {
            ctx.warn(rel, `ri sub-list missing at 0x${rel.toString(16)}`);
            continue;
          }
          yield* walkSubkeyList(sub, parentPath);
        }
      } else {
        ctx.warn(list.rel, `unknown subkey list type at 0x${list.rel.toString(16)}`);
      }
    }

    yield* emitKey(rootCell, '');

    if (capped.hit) return;

    // Deleted key and value recovery, following BuildDeletedRegistryKeys in
    // his RegistryHive. A cell the live tree never reached is either a key
    // that was deleted or a value belonging to one; the bytes stay until the
    // slot is reused, which is why a deleted Run key can still be read weeks
    // later.
    interface Deleted {
      rel: number;
      name: string;
      parentRel: number;
      lastWrite: Date | null;
      valueRels: number[];
      path: string;
    }

    const deleted = new Map<number, Deleted>();

    for (const [rel, cell] of cells) {
      if (ctx.signal?.aborted) return;
      if (cell.sig !== 'nk' || visited.has(rel)) continue;

      const buf = cell.buf;
      if (buf.length < 0x50) continue;

      const c = new Cursor(buf, 6);
      const flags = c.u16();
      const lastWrite = c.filetime();
      c.skip(4);
      const parentRel = c.u32();
      c.u32(); // subkey count
      c.u32();
      c.u32(); // subkey list
      c.u32();
      const valueListCount = c.u32();
      const valueListRel = c.u32();
      c.skip(4 + 4 + 4 + 4 + 8 + 4);
      const nameLen = c.u16();

      // His sanity check: a record that cannot hold its own name is not one.
      if (buf.length < 0x50 + nameLen) continue;
      // And a value count this large is a reused cell, not a key.
      if (valueListCount > 10000) continue;

      const name =
        (flags & NK_FLAG_COMPRESSED_NAME) !== 0
          ? asciiBytes(buf.subarray(0x50, 0x50 + nameLen))
          : utf16Text(buf.subarray(0x50, 0x50 + nameLen * 2));
      if (name.length === 0) continue;

      const valueRels: number[] = [];
      if (valueListRel > 0 && valueListRel !== 0xffffffff) {
        const list = await readDataCell(reader, valueListRel);
        if (list) {
          for (let i = 0; i < valueListCount && i * 4 + 4 <= list.length; i++) {
            valueRels.push(new DataView(list.buffer, list.byteOffset + i * 4, 4).getUint32(0, true));
          }
          // He also reads past the declared count: a deleted key's list can
          // still hold offsets from when it had more values.
          for (let i = valueListCount; i * 4 + 4 <= list.length; i++) {
            const os = new DataView(list.buffer, list.byteOffset + i * 4, 4).getUint32(0, true);
            if (os < 8 || os % 8 !== 0) break;
            if (!valueRels.includes(os)) valueRels.push(os);
          }
        }
      }

      deleted.set(rel, { rel, name, parentRel, lastWrite, valueRels, path: name });
    }

    // Link deleted keys to deleted parents, then to live parents, so a
    // recovered key is reported where it actually lived rather than by name
    // alone.
    for (const d of deleted.values()) {
      const segments = [d.name];
      let parent = d.parentRel;
      const seen = new Set<number>([d.rel]);
      while (parent !== undefined && !seen.has(parent)) {
        seen.add(parent);
        const dp = deleted.get(parent);
        if (dp) {
          segments.unshift(dp.name);
          parent = dp.parentRel;
          continue;
        }
        const live = livePaths.get(parent);
        if (live !== undefined) {
          segments.unshift(live);
        }
        break;
      }
      d.path = segments.join('\\');
    }

    const associated = new Set<number>();
    let recoveredKeys = 0;

    for (const d of deleted.values()) {
      if (ctx.signal?.aborted) return;
      if (rows >= MAX_ROWS) {
        if (!capped.hit) {
          capped.hit = true;
          ctx.warn(0, `row cap of ${MAX_ROWS.toLocaleString()} reached — results are partial`);
        }
        return;
      }
      recoveredKeys++;

      const emitted: Row[] = [];
      for (const vkRel of d.valueRels) {
        const vk = cells.get(vkRel);
        if (!vk || vk.sig !== 'vk') continue;
        // A vk that is in use and already claimed by a live key is not this
        // key's value; claiming it would attribute live data to a deleted key.
        if (!isFree(vk.buf) && referencedValues.has(vkRel)) continue;
        associated.add(vkRel);
        const val = await decodeValue(reader, vk, minor, true);
        if (val) emitted.push(val);
      }

      if (emitted.length === 0) {
        rows++;
        yield {
          ...common,
          keyPath: d.path,
          valueName: null,
          valueType: null,
          valueData: null,
          valueSlack: null,
          isDeleted: true,
          lastWritten: d.lastWrite,
          offset: d.rel + 4096,
        };
      } else {
        for (const v of emitted) {
          rows++;
          yield {
            ...common,
            keyPath: d.path,
            isDeleted: true,
            lastWritten: d.lastWrite,
            offset: d.rel + 4096,
            ...v,
          };
        }
      }
    }

    // Values whose key is gone entirely. He reports these as unassociated;
    // they have no path, but the name, type and data are still readable.
    let orphanValues = 0;
    for (const [rel, cell] of cells) {
      if (ctx.signal?.aborted) return;
      if (cell.sig !== 'vk') continue;
      if (referencedValues.has(rel) || associated.has(rel)) continue;
      if (rows >= MAX_ROWS) break;

      const val = await decodeValue(reader, cell, minor, true);
      if (!val) continue;
      orphanValues++;
      rows++;
      yield {
        ...common,
        keyPath: '(unassociated)',
        isDeleted: true,
        lastWritten: null,
        offset: rel + 4096,
        ...val,
      };
    }

    if (recoveredKeys > 0 || orphanValues > 0) {
      ctx.warn(
        0,
        `recovered ${recoveredKeys.toLocaleString()} deleted key(s) and ${orphanValues.toLocaleString()} unassociated value(s) from unallocated cells; these are marked Deleted`,
      );
    }
  },
};

export function asciiBytes(buf: Uint8Array): string {
  let s = '';
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0) break;
    s += String.fromCharCode(buf[i]);
  }
  return s;
}

/**
 * Decode a vk cell into a value row. Handles resident data, non-resident data
 * and the big-data (db) case, following VkCellRecord.cs.
 */
async function decodeValue(reader: Reader, vk: CellRec, minor: number, allowFree = false): Promise<Row | null> {
  const buf = vk.buf;
  if (buf.length < 0x18) {
    // not a recoverable vk record
    return null;
  }
  const nameLen = new DataView(buf.buffer, buf.byteOffset + 6, 2).getUint16(0, true);
  const dataLenRaw = new DataView(buf.buffer, buf.byteOffset + 8, 4).getUint32(0, true);
  const offsetToData = new DataView(buf.buffer, buf.byteOffset + 0x0c, 4).getUint32(0, true);
  const dataTypeRaw = new DataView(buf.buffer, buf.byteOffset + 0x10, 4).getUint32(0, true) & 0x00000fff;
  const namePresentFlag = new DataView(buf.buffer, buf.byteOffset + 0x14, 2).getUint16(0, true);

  let valueName = '(default)';
  if (nameLen > 0) {
    if (namePresentFlag > 0) {
      valueName = asciiBytes(buf.subarray(0x18, 0x18 + nameLen));
    } else {
      valueName = utf16Text(buf.subarray(0x18, 0x18 + nameLen * 2));
    }
  }

  const isResident = (dataLenRaw & 0x80000000) !== 0;
  let dataLen = isResident ? dataLenRaw & 0x7fffffff : dataLenRaw;

  let dataBlock: Uint8Array;
  let internalOffset: number;

  if (isResident) {
    // Data lives in the vk's own bytes starting at 0x0C.
    if (dataTypeRaw === 0x0005) dataLen = 4; // REG_DWORD_BIG_ENDIAN resident needs 4
    if (dataTypeRaw > UWP_MAX) dataLen = 4; // REG_UNKNOWN
    const start = 0x0c;
    const end = Math.min(start + dataLen, buf.length);
    dataBlock = buf.subarray(start, end);
    internalOffset = 0;
  } else {
    if (isFree(buf) && !allowFree) {
      return null;
    }
    const cell = await readCellRaw(reader, offsetToData);
    if (!cell) {
      return null;
    }
    if (dataLen > 16344 && minor > 3) {
      // Big data: the cell at offsetToData is a 'db' list of fragmented offsets.
      const db = cell;
      if (db.length < 0x0c) return null;
      const dbEntries = new DataView(db.buffer, db.byteOffset + 6, 2).getUint16(0, true);
      const offsetsRel = new DataView(db.buffer, db.byteOffset + 8, 4).getUint32(0, true);
      const listCell = await readCellRaw(reader, offsetsRel);
      if (!listCell) return null;
      const segments: Uint8Array[] = [];
      let totalBytes = 0;
      for (let i = 1; i <= dbEntries; i++) {
        if (i * 4 + 4 > listCell.length) break;
        const segRel = new DataView(listCell.buffer, listCell.byteOffset + i * 4, 4).getUint32(0, true);
        const segCell = await readCellRaw(reader, segRel);
        if (!segCell || segCell.length <= 4) continue;
        const segLen = Math.min(segCell.length - 4, 16344);
        const segment = segCell.subarray(4, 4 + segLen);
        segments.push(segment);
        totalBytes += segment.length;
      }
      dataBlock = new Uint8Array(totalBytes);
      let offset = 0;
      for (const seg of segments) {
        dataBlock.set(seg, offset);
        offset += seg.length;
      }
      internalOffset = 0;
    } else {
      dataBlock = cell;
      internalOffset = 4;
    }
  }

  const valueData = renderValueData(dataBlock, dataLen, dataTypeRaw, internalOffset);

  // Whatever is left in the record after the value itself. It is the previous
  // occupant of those bytes, so it can hold data from a value that was
  // overwritten by a shorter one.
  const slackStart = internalOffset + dataLen;
  const valueSlack =
    slackStart < dataBlock.length ? hexBytes(dataBlock.subarray(slackStart)) : null;

  return {
    valueName,
    valueType: regTypeName(dataTypeRaw),
    valueData,
    valueSlack,
  };
}
