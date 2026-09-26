/**
 * ESE (Extensible Storage Engine, "JET Blue") databases: SRUDB.dat, the SUM
 * databases, Windows.edb and others.
 *
 * Eric Zimmerman's tools read these through Windows' own esent.dll, so there
 * is no parser of his to port; this is written from Joachim Metz's format
 * specification (https://github.com/libyal/libesedb/blob/main/documentation/
 * Extensible%20Storage%20Engine%20(ESE)%20Database%20File%20(EDB)%20format.asciidoc)
 * and checked against esent itself: each record comes back as the bytes
 * esent's RetrieveColumn returns - long values reassembled, compressed columns
 * expanded - and the decoders turn them into values as ManagedEsent does.
 *
 * Pages are read as they are on disk. A database in a dirty state may have
 * committed changes still only in its transaction logs, which esent would
 * replay first and this does not.
 */
import type { Reader } from './types';
import { xpressDecompress } from './xpress';

export interface EseColumn {
  id: number;
  name: string;
  /** JET_coltyp. */
  type: number;
  flags: number;
  /** Declared size: the width of a fixed Text or Binary column. */
  size: number;
  codepage: number;
}

export interface EseTable {
  name: string;
  objid: number;
  fdp: number;
  lvFdp: number | null;
  columns: EseColumn[];
}

export interface Ese {
  pageSize: number;
  revision: number;
  /** JET_dbstate: 2 dirty, 3 clean. */
  state: number;
  tables: EseTable[];
  /** Every record of a table in primary key order, as column id -> the bytes esent would return; null columns absent. */
  rows(table: EseTable): AsyncGenerator<Map<number, Uint8Array>>;
}

type Warn = (offset: number, message: string) => void;

const FIXED_SIZES: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 4, 7: 8, 8: 8, 14: 4, 15: 8, 16: 16, 17: 2 };

const PAGE_ROOT = 0x1;
const PAGE_LEAF = 0x2;
const PAGE_EMPTY = 0x8;
const PAGE_SPACE_TREE = 0x20;

const TAG_DEFUNCT = 0x2;
const TAG_COMMON_KEY = 0x4;

interface Entry {
  key: Uint8Array;
  data: Uint8Array;
}

const u16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8);
const u32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const concat = (a: Uint8Array, b: Uint8Array) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * ESE column compression: a leading 0x18 means LZXPRESS with a 16-bit
 * uncompressed size, anything else 7-bit packing of the bytes after the
 * leading byte, least significant bits first.
 */
export function eseDecompress(b: Uint8Array): Uint8Array {
  if (b.length === 0) return b;
  if (b[0] === 0x18) return xpressDecompress(b.subarray(3), u16(b, 1));
  const out = new Uint8Array(Math.floor(((b.length - 1) * 8) / 7));
  let n = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 1; i < b.length; i++) {
    acc |= b[i] << bits;
    bits += 8;
    while (bits >= 7 && n < out.length) {
      out[n++] = acc & 0x7f;
      acc >>>= 7;
      bits -= 7;
    }
  }
  return out.subarray(0, n);
}

export async function openEse(reader: Reader, warn: Warn): Promise<Ese | null> {
  const head = await reader.bytes(0, 668);
  if (head.length < 668 || u32(head, 4) !== 0x89abcdef) {
    warn(0, 'not an ESE database: the signature at offset 4 is missing');
    return null;
  }
  const revision = u32(head, 232);
  const pageSize = u32(head, 236);
  const state = u32(head, 52);
  if (![2048, 4096, 8192, 16384, 32768].includes(pageSize)) {
    warn(236, `page size ${pageSize} is not one ESE uses`);
    return null;
  }
  const large = pageSize >= 16384 && revision >= 0x11;
  const headerSize = large ? 80 : 40;
  const tagMask = large ? 0x7fff : 0x1fff;
  const pageCount = Math.floor(reader.size / pageSize) - 1;

  // Pages are read a megabyte at a time; a table's leaves mostly sit together.
  const CHUNK = 1 << 20;
  const chunks = new Map<number, Uint8Array>();
  const readPage = async (pgno: number): Promise<Uint8Array | null> => {
    if (pgno < 1 || pgno > pageCount) return null;
    const at = (pgno + 1) * pageSize;
    const c = Math.floor(at / CHUNK);
    let chunk = chunks.get(c);
    if (!chunk) {
      chunk = await reader.bytes(c * CHUNK, CHUNK);
      chunks.set(c, chunk);
      if (chunks.size > 64) chunks.delete(chunks.keys().next().value as number);
    }
    const p = chunk.subarray(at - c * CHUNK, at - c * CHUNK + pageSize);
    return p.length === pageSize ? p : null;
  };

  /** A page's values: the page tags, read from the end of the page backwards. */
  const pageValues = (p: Uint8Array) => {
    const count = u16(p, 34) & (revision >= 0x122 ? 0x0fff : 0xffff);
    const values: Array<{ value: Uint8Array; flags: number }> = [];
    for (let i = 0; i < count; i++) {
      const t = pageSize - 4 * (i + 1);
      if (t < headerSize) break;
      const size = u16(p, t) & tagMask;
      const rawOffset = u16(p, t + 2);
      const offset = rawOffset & tagMask;
      let flags = large ? 0 : rawOffset >> 13;
      let value = p.subarray(headerSize + offset, headerSize + offset + size);
      // With large pages the flags live in the top three bits of the value's first word.
      if (large && i > 0 && value.length >= 2) {
        flags = value[1] >> 5;
        value = concat(Uint8Array.of(value[0], value[1] & 0x1f), value.subarray(2));
      }
      values.push({ value, flags });
    }
    return values;
  };

  /** Every live leaf entry of the B+-tree rooted at a page, in key order. */
  async function* entries(root: number, seen = new Set<number>()): AsyncGenerator<Entry> {
    if (seen.has(root)) {
      warn((root + 1) * pageSize, `page ${root} is reached twice in one tree; not followed again`);
      return;
    }
    seen.add(root);
    const p = await readPage(root);
    if (!p) {
      warn((root + 1) * pageSize, `page ${root} lies outside the file`);
      return;
    }
    const flags = u32(p, 36);
    if (flags & (PAGE_EMPTY | PAGE_SPACE_TREE)) return;
    const values = pageValues(p);
    // The first value is the page's header: for a non-root page, the key prefix its entries share.
    const common = values.length > 0 && !(flags & PAGE_ROOT) ? values[0].value : new Uint8Array(0);
    for (let i = 1; i < values.length; i++) {
      const { value, flags: tf } = values[i];
      if (tf & TAG_DEFUNCT) continue;
      let at = 0;
      let commonSize = 0;
      if (tf & TAG_COMMON_KEY) {
        commonSize = u16(value, 0);
        at = 2;
      }
      const localSize = u16(value, at);
      at += 2;
      const key = concat(common.subarray(0, commonSize), value.subarray(at, at + localSize));
      const data = value.subarray(at + localSize);
      if (flags & PAGE_LEAF) yield { key, data };
      else if (data.length >= 4) yield* entries(u32(data, data.length - 4), seen);
    }
  }

  // The catalog, MSysObjects, is always rooted at page 4.
  const CATALOG_FIXED = [4, 2, 4, 4, 4, 4, 4, 1, 2, 4, 2, 4];
  const tables = new Map<number, EseTable>();
  const columns: Array<EseColumn & { objid: number }> = [];
  const lvs = new Map<number, number>();
  const templates = new Map<number, string>();
  for await (const e of entries(4)) {
    const d = e.data;
    if (d.length < 4) continue;
    const lastFixed = d[0];
    const lastVar = d[1];
    const varOffset = u16(d, 2);
    const fixed: number[] = [];
    for (let id = 1, at = 4; id <= Math.min(lastFixed, CATALOG_FIXED.length); at += CATALOG_FIXED[id - 1], id++) {
      const size = CATALOG_FIXED[id - 1];
      fixed[id] = size === 1 ? d[at] : size === 2 ? u16(d, at) : u32(d, at);
    }
    const vars: Array<Uint8Array | null> = [];
    const varCount = lastVar >= 128 ? lastVar - 127 : 0;
    const varData = varOffset + 2 * varCount;
    for (let i = 0, prev = 0; i < varCount; i++) {
      const v = u16(d, varOffset + 2 * i);
      const end = v & 0x7fff;
      vars.push(v & 0x8000 ? null : d.subarray(varData + prev, varData + end));
      prev = end;
    }
    const text = (b: Uint8Array | null | undefined) => (b ? new TextDecoder('latin1').decode(b) : '');
    const [objid, type, id, coltypOrFdp, spaceUsage, flags, pagesOrLocale] = [1, 2, 3, 4, 5, 6, 7].map((i) => fixed[i] ?? 0);
    const name = text(vars[0]);
    if (type === 1) {
      tables.set(objid, { name, objid, fdp: coltypOrFdp, lvFdp: null, columns: [] });
      if (vars[2]) templates.set(objid, text(vars[2]));
    } else if (type === 2) columns.push({ objid, id, name, type: coltypOrFdp, flags, size: spaceUsage, codepage: pagesOrLocale });
    else if (type === 4) lvs.set(objid, coltypOrFdp);
  }
  for (const c of columns) {
    const { objid, ...col } = c;
    tables.get(objid)?.columns.push(col);
  }
  for (const [objid, fdp] of lvs) {
    const t = tables.get(objid);
    if (t) t.lvFdp = fdp;
  }
  // A table made from a template has the template's columns before its own.
  const byName = new Map([...tables.values()].map((t) => [t.name, t]));
  for (const [objid, template] of templates) {
    const t = tables.get(objid);
    const base = byName.get(template);
    if (t && base) t.columns = [...base.columns, ...t.columns];
  }
  for (const t of tables.values()) t.columns.sort((a, b) => a.id - b.id);

  /** A table's long values, keyed by their identifier's bytes as the record holds them. */
  const lvCache = new Map<number, Map<string, Array<{ offset: number; data: Uint8Array }>>>();
  const longValues = async (t: EseTable, lidSize: number) => {
    let map = lvCache.get(t.objid);
    if (map) return map;
    map = new Map();
    lvCache.set(t.objid, map);
    if (t.lvFdp === null) return map;
    for await (const e of entries(t.lvFdp)) {
      if (e.key.length !== lidSize + 4) continue; // the root entry (just the id) carries the reference count and size
      // Keys hold the identifier big-endian; records hold it little-endian.
      const lid = hex(e.key.subarray(0, lidSize).slice().reverse());
      const offset = (e.key[lidSize] << 24) | (e.key[lidSize + 1] << 16) | (e.key[lidSize + 2] << 8) | e.key[lidSize + 3];
      const list = map.get(lid) ?? [];
      list.push({ offset: offset >>> 0, data: e.data });
      map.set(lid, list);
    }
    return map;
  };

  async function* rows(t: EseTable): AsyncGenerator<Map<number, Uint8Array>> {
    const cols = new Map(t.columns.map((c) => [c.id, c]));
    const tagMaskRecord = large ? 0x7fff : 0x3fff;
    for await (const e of entries(t.fdp)) {
      const d = e.data;
      if (d.length < 4) continue;
      const out = new Map<number, Uint8Array>();
      const lastFixed = d[0];
      const lastVar = d[1];
      const varOffset = u16(d, 2);

      // Fixed columns, packed in id order, then a bit per column marking it null.
      let at = 4;
      const fixedAt: Array<[number, number, number]> = [];
      for (let id = 1; id <= lastFixed; id++) {
        const c = cols.get(id);
        const size = c ? (FIXED_SIZES[c.type] ?? c.size) : 0;
        if (!c) {
          warn(0, `${t.name}: fixed column ${id} is not in the catalog; the rest of the record's fixed columns cannot be placed`);
          break;
        }
        fixedAt.push([id, at, size]);
        at += size;
      }
      for (const [id, off, size] of fixedAt) {
        const nullBit = d[at + ((id - 1) >> 3)] & (1 << ((id - 1) & 7));
        if (!nullBit) out.set(id, d.subarray(off, off + size));
      }

      // Variable columns: an array of end offsets, the top bit marking null.
      const varCount = lastVar >= 128 ? lastVar - 127 : 0;
      const varData = varOffset + 2 * varCount;
      let prev = 0;
      for (let i = 0; i < varCount; i++) {
        const v = u16(d, varOffset + 2 * i);
        const end = v & 0x7fff;
        if (!(v & 0x8000) && cols.has(128 + i)) out.set(128 + i, d.subarray(varData + prev, varData + end));
        prev = end;
      }

      // Tagged columns: (id, offset) pairs, then their data, each led by a flags byte.
      const tagged = varData + prev;
      if (tagged + 4 <= d.length) {
        const count = (u16(d, tagged + 2) & tagMaskRecord) / 4;
        for (let i = 0; i < count; i++) {
          const id = u16(d, tagged + 4 * i);
          const raw = u16(d, tagged + 4 * i + 2);
          const start = raw & tagMaskRecord;
          const end = i + 1 < count ? u16(d, tagged + 4 * (i + 1) + 2) & tagMaskRecord : d.length - tagged;
          let value = d.subarray(tagged + start, tagged + end);
          let flags = 0;
          if ((large || raw & 0x4000) && value.length > 0) {
            flags = value[0];
            value = value.subarray(1);
          }
          const c = cols.get(id);
          if (!c) continue;
          try {
            if (flags & 0x08) {
              // Several values: RetrieveColumn gives the first, as this does.
              if (flags & 0x10) value = value.subarray(1, 1 + value[0]);
              else if (value.length >= 2) {
                const first = u16(value, 0) & 0x7fff;
                const second = value.length >= 4 && first > 2 ? u16(value, 2) & 0x7fff : value.length;
                value = value.subarray(first, second);
              }
            }
            if (flags & 0x04) {
              const segments = (await longValues(t, value.length)).get(hex(value));
              if (!segments) {
                warn(0, `${t.name}: long value ${hex(value)} for column ${c.name} is missing`);
                continue;
              }
              segments.sort((a, b) => a.offset - b.offset);
              const parts = segments.map((s) => (flags & 0x02 && s.data[0] === 0x18 ? eseDecompress(s.data) : s.data));
              value = parts.reduce((a, b) => concat(a, b), new Uint8Array(0));
            } else if (flags & 0x02) value = eseDecompress(value);
          } catch (err) {
            warn(0, `${t.name}: column ${c.name}: ${(err as Error).message}`);
            continue;
          }
          out.set(id, value);
        }
      }
      yield out;
    }
  }

  return { pageSize, revision, state, tables: [...tables.values()], rows };
}

/** DateTime.FromOADate: days since 1899-12-30, the fraction a time of day even before it. */
export function oaDate(b: Uint8Array): Date | null {
  if (b.length < 8) return null;
  const d = new DataView(b.buffer, b.byteOffset, 8).getFloat64(0, true);
  if (!Number.isFinite(d) || d <= -657435 || d >= 2958466) return null;
  let ms = Math.trunc(d * 86400000 + (d >= 0 ? 0.5 : -0.5));
  if (ms < 0) ms -= (ms % 86400000) * 2;
  return new Date(ms - 2209161600000);
}
