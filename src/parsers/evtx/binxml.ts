/**
 * Windows XML Event Log (EVTX) BinXML decoder.
 *
 * Ported from Eric Zimmerman's evtx project:
 *   - https://github.com/EricZimmerman/evtx (TagBuilder, Template, ChunkInfo, EventRecord)
 * Format references:
 *   - [MS-EVEN6]: Event Log Remoting Protocol (Section 2.2.14 BinXML)
 *   - libevtx documentation: https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
 */
import { Cursor, filetime, guid, utf16, ascii } from '../../core/binary';
import type { EventMap } from './maps';

/**
 * The 468 event maps are three quarters of a megabyte of generated data, and
 * only event logs need them, so they are loaded on demand rather than bundled
 * into every parse. loadEventMaps() must be awaited before decoding a record;
 * without it a record still decodes, just with no map applied.
 */
let maps: typeof import('./maps') | null = null;

export async function loadEventMaps(): Promise<void> {
  maps ??= await import('./maps');
}
import type { XNode } from './xpath';
import { parseXml, selectSingleNode } from './xpath';

// BinXML Token opcodes
export const TOKEN_EOF = 0x00;
export const TOKEN_OPEN_START_ELEMENT = 0x01;
export const TOKEN_CLOSE_START_ELEMENT = 0x02;
export const TOKEN_CLOSE_EMPTY_ELEMENT = 0x03;
export const TOKEN_END_ELEMENT = 0x04;
export const TOKEN_VALUE = 0x05;
export const TOKEN_ATTRIBUTE = 0x06;
export const TOKEN_CDATA = 0x07;
export const TOKEN_CHAR_REF = 0x08;
export const TOKEN_ENTITY_REF = 0x09;
export const TOKEN_PI_TARGET = 0x0a;
export const TOKEN_PI_DATA = 0x0b;
export const TOKEN_TEMPLATE_INSTANCE = 0x0c;
export const TOKEN_NORMAL_SUBSTITUTION = 0x0d;
export const TOKEN_OPTIONAL_SUBSTITUTION = 0x0e;
export const TOKEN_START_STREAM = 0x0f;

// Tokens with more data / attributes flag (bit 6 = 0x40):
export const TOKEN_OPEN_START_ELEMENT_ATTR = 0x41;
export const TOKEN_VALUE_MORE = 0x45;
export const TOKEN_ATTRIBUTE_MORE = 0x46;
export const TOKEN_CDATA_MORE = 0x47;
export const TOKEN_CHAR_REF_MORE = 0x48;
export const TOKEN_ENTITY_REF_MORE = 0x49;

export interface StringTableEntry {
  offset: number;
  hash: number;
  value: string;
  size: number;
}

export interface SubstitutionEntry {
  index: number;
  size: number;
  type: number;
  data: Uint8Array;
}

export type BinXmlNode =
  | {
      type: 'element';
      name: string;
      attributes: {
        name: string;
        value: string | { subId: number; optional: boolean };
      }[];
      children: BinXmlNode[];
      empty: boolean;
    }
  | { type: 'text'; text: string }
  | { type: 'sub'; subId: number; optional: boolean; valType: number }
  | { type: 'cdata'; text: string }
  | { type: 'charRef'; char: string }
  | { type: 'entityRef'; name: string };

export interface TemplateDefinition {
  templateId: number;
  templateOffset: number;
  guid: string;
  size: number;
  nodes: BinXmlNode[];
  nextTemplateOffset: number;
}

/**
 * Caches strings and templates per chunk, guarding lookups and recursion.
 */
export class ChunkCache {
  readonly strings = new Map<number, StringTableEntry>();
  readonly templates = new Map<number, TemplateDefinition>();
  readonly chunkBytes: Uint8Array;
  readonly chunkNumber: number;

  constructor(chunkBytes: Uint8Array, chunkNumber: number) {
    this.chunkBytes = chunkBytes;
    this.chunkNumber = chunkNumber;
    this.initHeaderTables();
  }

  private initHeaderTables(): void {
    const dv = new DataView(
      this.chunkBytes.buffer,
      this.chunkBytes.byteOffset,
      this.chunkBytes.byteLength,
    );

    // String table at chunk offset 128..383 (64 offsets * 4 bytes = 256 bytes)
    for (let i = 128; i < 384; i += 4) {
      if (i + 4 > this.chunkBytes.length) break;
      const off = dv.getUint32(i, true);
      if (off > 0 && off < this.chunkBytes.length) {
        this.getString(off);
      }
    }

    // Template table at chunk offset 384..511 (32 offsets * 4 bytes = 128 bytes)
    for (let i = 384; i < 512; i += 4) {
      if (i + 4 > this.chunkBytes.length) break;
      const off = dv.getUint32(i, true);
      if (off > 0 && off < this.chunkBytes.length) {
        this.getTemplate(off - 10, 0);
      }
    }
  }

  getString(offset: number): StringTableEntry | null {
    if (this.strings.has(offset)) return this.strings.get(offset)!;
    if (offset < 0 || offset + 8 > this.chunkBytes.length) return null;

    const dv = new DataView(
      this.chunkBytes.buffer,
      this.chunkBytes.byteOffset,
      this.chunkBytes.byteLength,
    );
    const hash = dv.getUint16(offset + 4, true);
    const charLen = dv.getUint16(offset + 6, true);
    const byteLen = charLen * 2;
    if (offset + 8 + byteLen > this.chunkBytes.length) return null;

    const strBytes = this.chunkBytes.subarray(offset + 8, offset + 8 + byteLen);
    const value = utf16(strBytes);
    // 4 (next offset) + 2 (hash) + 2 (charLen) + byteLen + 2 (NUL)
    const size = 8 + byteLen + 2;
    const entry: StringTableEntry = { offset, hash, value, size };
    this.strings.set(offset, entry);
    return entry;
  }

  getTemplate(startingOffset: number, depth = 0): TemplateDefinition | null {
    if (depth > 20) return null; // recursion depth limit
    if (this.templates.has(startingOffset)) return this.templates.get(startingOffset)!;

    let index = startingOffset;
    if (index < 0 || index >= this.chunkBytes.length) return null;

    if (this.chunkBytes[index] !== TOKEN_TEMPLATE_INSTANCE) {
      if (index >= 10 && this.chunkBytes[index - 10] === TOKEN_TEMPLATE_INSTANCE) {
        index = index - 10;
      } else {
        return null;
      }
    }

    if (index + 33 > this.chunkBytes.length) return null;
    const dv = new DataView(
      this.chunkBytes.buffer,
      this.chunkBytes.byteOffset,
      this.chunkBytes.byteLength,
    );

    let p = index + 1; // opcode (0x0C)
    p++; // skip version byte
    const templateId = dv.getInt32(p, true);
    p += 4;
    const templateOffset = dv.getInt32(p, true);
    p += 4;
    if (templateOffset === 0) return null;
    const nextTemplateOffset = dv.getInt32(p, true);
    p += 4;
    const templateGuid = guid(this.chunkBytes.subarray(p, p + 16));
    p += 16;
    const length = dv.getInt32(p, true);
    p += 4;

    if (length < 0 || p + length > this.chunkBytes.length) return null;
    const templateBytes = this.chunkBytes.subarray(p, p + length);

    const nodes = parseTemplateBytes(templateBytes, p, this, depth + 1);
    const template: TemplateDefinition = {
      templateId,
      templateOffset,
      guid: templateGuid,
      size: length,
      nodes,
      nextTemplateOffset,
    };

    this.templates.set(startingOffset, template);
    this.templates.set(templateOffset, template);
    this.templates.set(templateOffset - 0x18, template);

    // Follow next template in bucket if present
    if (
      nextTemplateOffset > 0 &&
      nextTemplateOffset < this.chunkBytes.length &&
      !this.templates.has(nextTemplateOffset)
    ) {
      this.getTemplate(nextTemplateOffset - 10, depth + 1);
    }

    return template;
  }
}

function parseTemplateBytes(
  bytes: Uint8Array,
  templateChunkStart: number,
  cache: ChunkCache,
  depth: number,
  /**
   * Whether element starts carry the 2-byte dependency identifier. They do
   * inside a template definition, and per [MS-EVEN6] they do not inside a
   * fragment carried by a Binary XML (0x21) substitution.
   */
  hasDependencyId = true,
): BinXmlNode[] {
  const nodes: BinXmlNode[] = [];
  const cursor = new Cursor(bytes, 0);

  while (cursor.remaining > 0 && !cursor.overran) {
    const op = cursor.u8();
    if (op === TOKEN_EOF) break;
    if (op === TOKEN_START_STREAM) {
      cursor.skip(3); // major, minor, flags
      continue;
    }
    if (op === TOKEN_OPEN_START_ELEMENT || op === TOKEN_OPEN_START_ELEMENT_ATTR) {
      const elem = parseElement(cursor, op, templateChunkStart, cache, depth, hasDependencyId);
      if (elem) nodes.push(elem);
      continue;
    }
    break;
  }
  return nodes;
}

function parseElement(
  cursor: Cursor,
  op: number,
  chunkBase: number,
  cache: ChunkCache,
  depth: number,
  hasDependencyId = true,
): BinXmlNode | null {
  if (depth > 20) return null;
  const hasAttr = op === TOKEN_OPEN_START_ELEMENT_ATTR;
  if (hasDependencyId) cursor.skip(2); // dependency identifier / substitution slot
  const elemSize = cursor.u32();
  const startPos = cursor.pos;

  const nameOffset = cursor.u32();
  const nameEntry = cache.getString(nameOffset);
  const name = nameEntry?.value ?? 'Unknown';

  // If string was stored inline in the stream, advance past it
  const currentChunkPos = chunkBase + cursor.pos;
  if (nameEntry && nameOffset >= currentChunkPos - 4 && nameOffset <= currentChunkPos) {
    cursor.skip(nameEntry.size);
  }

  const attributes: {
    name: string;
    value: string | { subId: number; optional: boolean };
  }[] = [];

  if (hasAttr) {
    const attrSize = cursor.u32();
    const attrStart = cursor.pos;
    while (cursor.pos < attrStart + attrSize && !cursor.overran && cursor.remaining > 0) {
      const attrOp = cursor.u8();
      if (attrOp === TOKEN_ATTRIBUTE || attrOp === TOKEN_ATTRIBUTE_MORE) {
        const attrNameOffset = cursor.u32();
        const attrNameEntry = cache.getString(attrNameOffset);
        const attrName = attrNameEntry?.value ?? 'Unknown';

        const attrChunkPos = chunkBase + cursor.pos;
        if (
          attrNameEntry &&
          attrNameOffset >= attrChunkPos - 4 &&
          attrNameOffset <= attrChunkPos
        ) {
          cursor.skip(attrNameEntry.size);
        }

        const valOp = cursor.u8();
        if (valOp === TOKEN_VALUE || valOp === TOKEN_VALUE_MORE) {
          cursor.skip(1); // skip valType byte
          const valChars = cursor.u16();
          const valStr = cursor.utf16(valChars * 2);
          attributes.push({ name: attrName, value: valStr });
        } else if (valOp === TOKEN_NORMAL_SUBSTITUTION) {
          const subId = cursor.u16();
          cursor.skip(1); // skip valType byte
          attributes.push({ name: attrName, value: { subId, optional: false } });
        } else if (valOp === TOKEN_OPTIONAL_SUBSTITUTION) {
          const subId = cursor.u16();
          cursor.skip(1); // skip valType byte
          attributes.push({ name: attrName, value: { subId, optional: true } });
        } else if (valOp === TOKEN_CHAR_REF || valOp === TOKEN_CHAR_REF_MORE) {
          const code = cursor.u16();
          attributes.push({ name: attrName, value: String.fromCharCode(code) });
        } else if (valOp === TOKEN_ENTITY_REF || valOp === TOKEN_ENTITY_REF_MORE) {
          const entOffset = cursor.u32();
          const ent = cache.getString(entOffset)?.value ?? '';
          attributes.push({ name: attrName, value: `&${ent};` });
        }
      } else {
        break;
      }
    }
  }

  const closeOp = cursor.u8();
  if (closeOp === TOKEN_CLOSE_EMPTY_ELEMENT) {
    return { type: 'element', name, attributes, children: [], empty: true };
  }

  const children: BinXmlNode[] = [];
  const endLimit = startPos + elemSize;

  while (cursor.pos < endLimit && !cursor.overran && cursor.remaining > 0) {
    const childOp = cursor.u8();
    if (childOp === TOKEN_END_ELEMENT) {
      break;
    }
    if (childOp === TOKEN_OPEN_START_ELEMENT || childOp === TOKEN_OPEN_START_ELEMENT_ATTR) {
      const childElem = parseElement(cursor, childOp, chunkBase, cache, depth + 1, hasDependencyId);
      if (childElem) children.push(childElem);
    } else if (childOp === TOKEN_VALUE || childOp === TOKEN_VALUE_MORE) {
      cursor.skip(1); // skip valType byte
      const valChars = cursor.u16();
      const valStr = cursor.utf16(valChars * 2);
      children.push({ type: 'text', text: valStr });
    } else if (childOp === TOKEN_NORMAL_SUBSTITUTION) {
      const subId = cursor.u16();
      const valType = cursor.u8();
      children.push({ type: 'sub', subId, optional: false, valType });
    } else if (childOp === TOKEN_OPTIONAL_SUBSTITUTION) {
      const subId = cursor.u16();
      const valType = cursor.u8();
      children.push({ type: 'sub', subId, optional: true, valType });
    } else if (childOp === TOKEN_CDATA || childOp === TOKEN_CDATA_MORE) {
      const chars = cursor.u16();
      const text = cursor.utf16(chars * 2);
      children.push({ type: 'cdata', text });
    } else if (childOp === TOKEN_CHAR_REF || childOp === TOKEN_CHAR_REF_MORE) {
      const code = cursor.u16();
      children.push({ type: 'charRef', char: String.fromCharCode(code) });
    } else if (childOp === TOKEN_ENTITY_REF || childOp === TOKEN_ENTITY_REF_MORE) {
      const entOffset = cursor.u32();
      const entName = cache.getString(entOffset)?.value ?? '';
      children.push({ type: 'entityRef', name: entName });
    } else if (childOp === TOKEN_EOF) {
      break;
    }
  }

  if (cursor.pos < endLimit) {
    cursor.seek(Math.min(endLimit, cursor.buf.length));
  }

  return { type: 'element', name, attributes, children, empty: false };
}

/**
 * Converts a Windows binary SID to string form (e.g. S-1-5-18).
 */
export function formatSid(b: Uint8Array): string {
  if (b.length < 8) return '';
  const revision = b[0];
  const subAuthCount = b[1];
  let auth = 0n;
  for (let i = 2; i < 8; i++) {
    auth = (auth << 8n) | BigInt(b[i]);
  }
  let sid = `S-${revision}-${auth}`;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  for (let i = 0; i < subAuthCount && 8 + (i + 1) * 4 <= b.length; i++) {
    const subAuth = dv.getUint32(8 + i * 4, true);
    sid += `-${subAuth}`;
  }
  return sid;
}

/**
 * Converts SYSTEMTIME structure (16 bytes) to Date.
 */
function systemTime(b: Uint8Array): Date | null {
  if (b.length < 16) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const year = dv.getUint16(0, true);
  const month = dv.getUint16(2, true);
  const day = dv.getUint16(6, true);
  const hour = dv.getUint16(8, true);
  const min = dv.getUint16(10, true);
  const sec = dv.getUint16(12, true);
  const ms = dv.getUint16(14, true);
  if (year === 0) return null;
  return new Date(Date.UTC(year, month - 1, day, hour, min, sec, ms));
}

/**
 * Formats a single substitution entry into its string representation according
 * to its ValueType.
 */
export function formatSubstitutionValue(
  sub: SubstitutionEntry,
  chunk: Uint8Array,
  cache: ChunkCache,
  depth = 0,
  recordChunkOffset = 0,
): string {
  if (depth > 20) return '';
  const d = sub.data;
  if (!d || d.length === 0) return '';

  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);

  switch (sub.type) {
    case 0x00: // NullType
      return '';
    case 0x01: // StringType (UTF-16LE)
      return utf16(d);
    case 0x02: // AnsiStringType
      return ascii(d);
    case 0x03: // Int8Type
      return d.length >= 1 ? dv.getInt8(0).toString() : '';
    case 0x04: // UInt8Type
      return d.length >= 1 ? d[0].toString() : '';
    case 0x05: // Int16Type
      return d.length >= 2 ? dv.getInt16(0, true).toString() : '';
    case 0x06: // UInt16Type
      return d.length >= 2 ? dv.getUint16(0, true).toString() : '';
    case 0x07: // Int32Type
      return d.length >= 4 ? dv.getInt32(0, true).toString() : '';
    case 0x08: // UInt32Type
      return d.length >= 4 ? dv.getUint32(0, true).toString() : '';
    case 0x09: // Int64Type
      return d.length >= 8 ? dv.getBigInt64(0, true).toString() : '';
    case 0x0a: // UInt64Type
      return d.length >= 8 ? dv.getBigUint64(0, true).toString() : '';
    case 0x0b: // Real32Type
      return d.length >= 4 ? dv.getFloat32(0, true).toString() : '';
    case 0x0c: // Real64Type
      return d.length >= 8 ? dv.getFloat64(0, true).toString() : '';
    case 0x0d: // BoolType (32-bit integer)
      return d.length >= 4 && dv.getInt32(0, true) !== 0 ? 'true' : 'false';
    case 0x0e: // BinaryType
    case 0x10: // SizeTType
      // Continuous upper-case hex, the way Windows renders <Binary>.
      return Array.from(d)
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join('');
    case 0x0f: // GuidType
      // Windows renders a substituted GUID in braces, and analysts match on
      // that form when pivoting between tools.
      return `{${guid(d)}}`;
    case 0x11: {
      // FileTimeType. A FILETIME counts 100-nanosecond intervals, and Windows
      // prints all seven fractional digits. A JavaScript Date only holds
      // milliseconds, so the last four digits come from the remainder --
      // without them an event's ordering within the same millisecond is lost,
      // which is exactly the resolution a timeline needs.
      // Computed here rather than through filetime(), which reports an
      // unset timestamp as null: Windows prints a zero FILETIME literally as
      // 1601-01-01T00:00:00.0000000Z, and an analyst needs to see that the
      // field was present and zero rather than absent.
      if (d.length < 8) return '';
      const ft = dv.getBigUint64(0, true);
      const ms = Number((ft - 116_444_736_000_000_000n) / 10_000n);
      if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return '';
      const iso = new Date(ms).toISOString();
      return `${iso.slice(0, -1)}${String(ft % 10_000n).padStart(4, '0')}Z`;
    }
    case 0x12: {
      // SysTimeType
      const st = systemTime(d);
      return st ? st.toISOString() : '';
    }
    case 0x13: // SidType
      return formatSid(d);
    // Windows renders hex integers in lower case, e.g. 0xd6b0. EvtxECmd
    // upper-cases them; we follow Windows so a value copied out of here
    // matches what Event Viewer shows.
    case 0x14: // HexInt32Type
      return d.length >= 4 ? `0x${dv.getUint32(0, true).toString(16)}` : '';
    case 0x15: // HexInt64Type
      return d.length >= 8 ? `0x${dv.getBigUint64(0, true).toString(16)}` : '';
    case 0x21: {
      // BinXmlType
      return decodeNestedBinXml(d, chunk, cache, depth + 1, recordChunkOffset);
    }
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
    case 0x88:
    case 0x89:
    case 0x8a:
    case 0x8b:
    case 0x8c:
    case 0x8d:
    case 0x8f: {
      const items = arrayItems(sub) ?? [];
      return items.join(sub.type === 0x81 || sub.type === 0x82 ? ', ' : ',');
    }
    case 0x91: {
      // ArrayFileTime
      const arr: string[] = [];
      for (let i = 0; i + 8 <= d.length; i += 8) {
        const dt = filetime(dv.getBigUint64(i, true));
        arr.push(dt ? dt.toISOString() : '');
      }
      return arr.join(',');
    }
    case 0x92: {
      // ArraySystemTime
      const arr: string[] = [];
      for (let i = 0; i + 16 <= d.length; i += 16) {
        const st = systemTime(d.subarray(i, i + 16));
        arr.push(st ? st.toISOString() : '');
      }
      return arr.join(',');
    }
    case 0x93: {
      // ArraySids
      // Each SID can be variable size
      const arr: string[] = [];
      let idx = 0;
      while (idx + 8 <= d.length) {
        const subAuthCount = d[idx + 1];
        const sidLen = 8 + subAuthCount * 4;
        if (idx + sidLen > d.length) break;
        arr.push(formatSid(d.subarray(idx, idx + sidLen)));
        idx += sidLen;
      }
      return arr.join(',');
    }
    case 0x94: {
      // Array32BitHex
      const arr: string[] = [];
      for (let i = 0; i + 4 <= d.length; i += 4)
        arr.push(`0x${dv.getUint32(i, true).toString(16).toUpperCase()}`);
      return arr.join(',');
    }
    case 0x95: {
      // Array64BitHex
      const arr: string[] = [];
      for (let i = 0; i + 8 <= d.length; i += 8)
        arr.push(`0x${dv.getBigUint64(i, true).toString(16).toUpperCase()}`);
      return arr.join(',');
    }
    default:
      return '';
  }
}

function escapeXmlText(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function escapeXmlAttr(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Splits an array-typed substitution into its items, from the bytes rather
 * than from a joined string: "Cisco Systems, Inc." is one item, not two.
 *
 * Windows repeats the element that holds the substitution once per item, so a
 * two-item array renders as <Data>a</Data><Data>b</Data>. An empty item is
 * still an item — it renders as <Data></Data> — so only the empty string left
 * by the final terminator is dropped. Returns null for non-array types.
 */
export function arrayItems(sub: SubstitutionEntry): string[] | null {
  const d = sub.data;
  if ((sub.type & 0x80) === 0 || !d) return null;
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
  const out: string[] = [];

  switch (sub.type) {
    case 0x81:
    case 0x82: {
      const text =
        sub.type === 0x81
          ? new TextDecoder('utf-16le').decode(d)
          : new TextDecoder('windows-1252').decode(d);
      const parts = text.split('\0');
      if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
      return parts;
    }
    case 0x83:
      for (let i = 0; i < d.length; i++) out.push(String(dv.getInt8(i)));
      return out;
    case 0x84:
      for (let i = 0; i < d.length; i++) out.push(String(d[i]));
      return out;
    case 0x85:
      for (let i = 0; i + 2 <= d.length; i += 2) out.push(String(dv.getInt16(i, true)));
      return out;
    case 0x86:
      for (let i = 0; i + 2 <= d.length; i += 2) out.push(String(dv.getUint16(i, true)));
      return out;
    case 0x87:
      for (let i = 0; i + 4 <= d.length; i += 4) out.push(String(dv.getInt32(i, true)));
      return out;
    case 0x88:
      for (let i = 0; i + 4 <= d.length; i += 4) out.push(String(dv.getUint32(i, true)));
      return out;
    case 0x89:
      for (let i = 0; i + 8 <= d.length; i += 8) out.push(dv.getBigInt64(i, true).toString());
      return out;
    case 0x8a:
      for (let i = 0; i + 8 <= d.length; i += 8) out.push(dv.getBigUint64(i, true).toString());
      return out;
    case 0x8b:
      for (let i = 0; i + 4 <= d.length; i += 4) out.push(String(dv.getFloat32(i, true)));
      return out;
    case 0x8c:
      for (let i = 0; i + 8 <= d.length; i += 8) out.push(String(dv.getFloat64(i, true)));
      return out;
    case 0x8d:
      for (let i = 0; i + 4 <= d.length; i += 4) out.push(String(dv.getInt32(i, true) !== 0));
      return out;
    case 0x8f:
      for (let i = 0; i + 16 <= d.length; i += 16) out.push(`{${guid(d.subarray(i, i + 16))}}`);
      return out;
    default:
      return null;
  }
}

/**
 * Decodes nested BinXML from a byte buffer (used for ValueType.BinXmlType).
 */
function decodeNestedBinXml(
  data: Uint8Array,
  chunk: Uint8Array,
  cache: ChunkCache,
  depth: number,
  recordChunkOffset = 0,
): string {
  if (depth > 20 || data.length === 0) return '';
  const cursor = new Cursor(data, 0);
  let out = '';

  // Names inside this fragment can be stored inline, and telling that apart
  // from a reference into the chunk's string table needs the fragment's own
  // position in the chunk. Both are views on the same buffer, so we can
  // recover it.
  const dataChunkOffset =
    data.buffer === chunk.buffer ? data.byteOffset - chunk.byteOffset : 0;

  while (cursor.remaining > 0 && !cursor.overran) {
    const op = cursor.u8();
    if (op === TOKEN_EOF) break;
    if (op === TOKEN_START_STREAM) {
      cursor.skip(3);
      continue;
    }
    if (op === TOKEN_OPEN_START_ELEMENT || op === TOKEN_OPEN_START_ELEMENT_ATTR) {
      // A plain element fragment rather than a template instance: UserData
      // payloads take this shape. EvtxECmd renders only template instances
      // here and drops everything else, which loses the whole <UserData>
      // element; we decode it, because it carries the evidence the record is
      // about and it is what Windows itself renders for the same event.
      const start = cursor.pos - 1;
      const nodes = parseTemplateBytes(
        data.subarray(start),
        dataChunkOffset + start,
        cache,
        depth + 1,
        false,
      );
      out += renderTemplateXml(nodes, [], chunk, cache, depth + 1, recordChunkOffset);
      break;
    }
    if (op === TOKEN_TEMPLATE_INSTANCE) {
      cursor.skip(1); // version
      cursor.skip(4); // templateId
      const tOff = cursor.u32();

      let template = cache.templates.get(tOff);
      if (!template) {
        template = cache.getTemplate(tOff, depth + 1) ?? undefined;
      }

      // Check if template definition is inline or cached:
      // In Eric Zimmerman's evtx (TemplateInstance.cs), if templateOffset < recordPosition,
      // the template is cached and the substitution array follows immediately.
      // Otherwise, the template definition is inline: skip NextTemplateOffset (4) + GUID (16) + length (4),
      // and skip the template definition body bytes (using template.size) to position at the substitution array.
      const isCached =
        recordChunkOffset > 0
          ? tOff < recordChunkOffset
          : template
            ? cursor.remaining < 24 + template.size ||
              new DataView(data.buffer, data.byteOffset + cursor.pos).getInt32(20, true) !== template.size
            : false;

      if (!isCached) {
        const nextTemplateOffset = cursor.i32();
        const templateGuid = cursor.guid();
        const dataSize = cursor.i32();
        if (dataSize < 0 || cursor.remaining < dataSize) {
          throw new Error(`invalid inline template size: ${dataSize}`);
        }
        if (template) {
          cursor.skip(template.size);
        } else {
          const templatePayload = cursor.take(dataSize);
          const nodes = parseTemplateBytes(templatePayload, tOff, cache, depth + 1);
          template = {
            templateId: 0,
            templateOffset: tOff,
            guid: templateGuid,
            size: dataSize,
            nodes,
            nextTemplateOffset,
          };
          cache.templates.set(tOff, template);
        }
      }

      const subCount = cursor.u32();
      if (subCount > 10000 || cursor.remaining < subCount * 4) {
        throw new Error(`implausible substitution count ${subCount} in nested BinXML for template 0x${tOff.toString(16)}`);
      }
      const descriptors: { size: number; type: number }[] = [];
      for (let i = 0; i < subCount; i++) {
        descriptors.push({ size: cursor.u16(), type: cursor.u16() });
      }
      const subs: SubstitutionEntry[] = [];
      for (let i = 0; i < subCount; i++) {
        const d = descriptors[i];
        if (cursor.remaining < d.size) {
          throw new Error('substitution data runs past payload end');
        }
        subs.push({
          index: i,
          size: d.size,
          type: d.type,
          data: cursor.take(d.size),
        });
      }

      if (template) {
        out += renderTemplateXml(template.nodes, subs, chunk, cache, depth + 1, recordChunkOffset);
      }
    }
  }
  return out;
}

export function renderTemplateXml(
  nodes: BinXmlNode[],
  substitutions: SubstitutionEntry[],
  chunk: Uint8Array,
  cache: ChunkCache,
  depth = 0,
  recordChunkOffset = 0,
): string {
  if (depth > 20) return '';
  let sb = '';

  for (const node of nodes) {
    if (node.type === 'element') {
      // An element whose entire content is optional substitutions that all
      // resolve to NullType is not emitted at all. This is why Windows shows
      // <EventData><Data>...</Data></EventData> where a naive render adds an
      // empty <Binary></Binary> after it.
      if (
        !node.empty &&
        node.children.length > 0 &&
        node.children.every(
          (c) =>
            c.type === 'sub' && c.optional && substitutions[c.subId]?.type === 0x00,
        )
      ) {
        continue;
      }

      // An array-valued substitution repeats its enclosing element, once per
      // item, which is how Windows renders a multi-string <Data>.
      const lone =
        node.children.length === 1 && node.children[0].type === 'sub'
          ? node.children[0]
          : null;
      if (lone && !node.empty) {
        const sub = substitutions[lone.subId];
        const items = sub ? arrayItems(sub) : null;
        if (items) {
          for (const item of items) {
            sb += renderTemplateXml(
              [{ ...node, children: [{ type: 'text', text: item }] }],
              substitutions,
              chunk,
              cache,
              depth + 1,
              recordChunkOffset,
            );
          }
          continue;
        }
      }

      sb += `<${node.name}`;
      const attrStrs: string[] = [];

      for (const attr of node.attributes) {
        if (typeof attr.value === 'string') {
          attrStrs.push(`${attr.name}="${escapeXmlAttr(attr.value)}"`);
        } else {
          const sub = substitutions[attr.value.subId];
          if (sub) {
            if (attr.value.optional && sub.type === 0x00) {
              // NullType optional attribute is omitted
              continue;
            }
            const val = formatSubstitutionValue(sub, chunk, cache, depth + 1, recordChunkOffset);
            attrStrs.push(`${attr.name}="${escapeXmlAttr(val)}"`);
          }
        }
      }

      if (attrStrs.length > 0) {
        sb += ' ' + attrStrs.join(' ');
      }

      if (node.empty) {
        sb += '/>';
      } else {
        sb += '>';
        sb += renderTemplateXml(node.children, substitutions, chunk, cache, depth + 1, recordChunkOffset);
        sb += `</${node.name}>`;
      }

    } else if (node.type === 'text') {
      sb += escapeXmlText(node.text);
    } else if (node.type === 'sub') {
      const sub = substitutions[node.subId];
      if (sub) {
        if (node.optional && sub.type === 0x00) {
          // Omit optional null element content
        } else if (sub.type === 0x21) {
          sb += formatSubstitutionValue(sub, chunk, cache, depth + 1, recordChunkOffset);
        } else {
          sb += escapeXmlText(formatSubstitutionValue(sub, chunk, cache, depth + 1, recordChunkOffset));
        }
      }
    } else if (node.type === 'cdata') {
      sb += `<![CDATA[${node.text}]]>`;
    } else if (node.type === 'charRef') {
      sb += node.char;
    } else if (node.type === 'entityRef') {
      sb += `&${node.name};`;
    }
  }

  return sb;
}

/**
 * One decoded event. The field set mirrors EvtxECmd's own output so an analyst
 * moving between the two sees the same columns with the same meanings.
 */
export interface DecodedRecord {
  eventId: number | null;
  level: string | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
  userId: string | null;
  processId: number | null;
  threadId: number | null;
  keywords: string | null;
  /** The record identifier as the XML carries it, which EvtxECmd reports separately from the header's record number. */
  eventRecordId: string | null;
  /** The time in the XML, which is the one EvtxECmd puts in its TimeCreated column. */
  timeCreated: Date | null;
  /**
   * Where the BinXML stream ended inside the record payload. Anything after it
   * is slack, and a second record hidden there is how DanderSpritz conceals an
   * event from every tool that stops at the first one.
   */
  binXmlEnd: number;
  /** Plain-language summary of the event, from his event map. */
  mapDescription: string | null;
  userName: string | null;
  remoteHost: string | null;
  executableInfo: string | null;
  /** The analytically important fields his map lifts out of the payload. */
  payloadData1: string | null;
  payloadData2: string | null;
  payloadData3: string | null;
  payloadData4: string | null;
  payloadData5: string | null;
  payloadData6: string | null;
  payload: string | null;
  xml: string | null;
}

function parseLevel(lvlNum: number): string {
  switch (lvlNum) {
    case 0:
      return 'Information';
    case 1:
      return 'Critical';
    case 2:
      return 'Error';
    case 3:
      return 'Warning';
    case 4:
      return 'Information';
    case 5:
      return 'Verbose';
    default:
      return String(lvlNum);
  }
}

/**
 * The nine properties an event map is allowed to set, in EvtxECmd's own
 * casing. His MapEntryValidator rejects a map that names anything else.
 */
export interface MappedProperties {
  UserName?: string;
  RemoteHost?: string;
  ExecutableInfo?: string;
  PayloadData1?: string;
  PayloadData2?: string;
  PayloadData3?: string;
  PayloadData4?: string;
  PayloadData5?: string;
  PayloadData6?: string;
}

const PROPERTY_NAMES: Record<string, keyof MappedProperties> = {
  USERNAME: 'UserName',
  REMOTEHOST: 'RemoteHost',
  EXECUTABLEINFO: 'ExecutableInfo',
  PAYLOADDATA1: 'PayloadData1',
  PAYLOADDATA2: 'PayloadData2',
  PAYLOADDATA3: 'PayloadData3',
  PAYLOADDATA4: 'PayloadData4',
  PAYLOADDATA5: 'PayloadData5',
  PAYLOADDATA6: 'PayloadData6',
};

/**
 * Applies an event map to a record, following EventRecord.BuildProperties.
 *
 * Three details there are easy to get wrong and all of them change output:
 * a path that resolves to nothing still substitutes as an empty string rather
 * than dropping the property; a Refine regex contributes every match joined
 * with " | ", not just the first capture group; and a value with no entry in
 * its lookup table renders as "Default (original)" rather than being left
 * alone.
 */
export function applyMap(
  root: XNode | null,
  map: EventMap,
): MappedProperties {
  const out: MappedProperties = {};

  for (const entry of map.properties) {
    if (entry.values.length === 0) continue; // his NOMATCH case

    const vars: Array<[string, string]> = [];

    for (const v of entry.values) {
      const selected = selectSingleNode(root, v.path);
      if (selected === null) {
        vars.push([v.name, '']);
        continue;
      }

      let value = selected;

      if (v.refine) {
        try {
          const hits = value.match(new RegExp(v.refine, 'gi'));
          if (hits && hits.length > 0) value = hits.join(' | ');
        } catch {
          // A pattern .NET accepts but JavaScript does not leaves the value as-is.
        }
      }

      const lookup = map.lookups?.find(
        (l) => l.name.toUpperCase() === v.name.toUpperCase(),
      );
      if (lookup) {
        value = lookup.values[value] ?? `${lookup.defaultVal} (${value})`;
      }

      vars.push([v.name, value]);
    }

    let resolved = entry.template;
    for (const [name, value] of vars) resolved = resolved.split(`%${name}%`).join(value);

    const target = PROPERTY_NAMES[entry.property.toUpperCase()];
    if (target) out[target] = resolved;
  }

  return out;
}

/**
 * The record's payload as EvtxECmd reports it: the EventData or UserData
 * element verbatim, including its own tags.
 */
function extractPayloadXml(xml: string): string | null {
  const m = xml.match(/<(EventData|UserData)(?:\s[^>]*)?(?:\/>|>[\s\S]*?<\/\1>)/i);
  return m ? m[0] : null;
}


/**
 * Parses BinXML from an event record payload, resolving templates and substitutions
 * against the chunk's caches.
 */
export function decodeRecordBinXml(
  payloadBytes: Uint8Array,
  recordChunkOffset: number,
  chunk: Uint8Array,
  cache: ChunkCache,
): DecodedRecord {
  const cursor = new Cursor(payloadBytes, 0);
  if (cursor.remaining < 4) {
    throw new Error('payload too short for BinXML header');
  }

  const firstByte = cursor.u8();
  if (firstByte !== TOKEN_START_STREAM) {
    throw new Error(
      `payload does not start with 0x0F (got 0x${firstByte.toString(16)})`,
    );
  }
  cursor.skip(3); // major, minor, flags

  let fullXml = '';

  while (cursor.remaining > 0 && !cursor.overran) {
    const tag = cursor.u8();
    if (tag === TOKEN_EOF) break;

    if (tag === TOKEN_START_STREAM) {
      cursor.skip(3);
      continue;
    }

    if (tag === TOKEN_TEMPLATE_INSTANCE) {
      cursor.skip(1); // version
      cursor.skip(4); // templateId
      const templateOffset = cursor.u32();

      let template: TemplateDefinition | undefined;

      if (templateOffset < recordChunkOffset) {
        // Template was already defined earlier in the chunk
        template = cache.templates.get(templateOffset);
        if (!template) {
          template = cache.getTemplate(templateOffset, 0) ?? undefined;
        }
      } else {
        // Template definition is inline right here
        const nextTemplateOffset = cursor.i32();
        const templateGuid = cursor.guid();
        const dataSize = cursor.i32();
        if (dataSize < 0 || cursor.remaining < dataSize) {
          throw new Error(`invalid inline template size: ${dataSize}`);
        }
        template = cache.templates.get(templateOffset);
        if (!template) {
          template = cache.getTemplate(templateOffset, 0) ?? undefined;
        }
        if (template) {
          cursor.skip(template.size);
        } else {
          const templatePayload = cursor.take(dataSize);
          const templatePosInChunk = recordChunkOffset + cursor.pos - dataSize;
          const nodes = parseTemplateBytes(templatePayload, templatePosInChunk, cache, 0);
          template = {
            templateId: 0,
            templateOffset,
            guid: templateGuid,
            size: dataSize,
            nodes,
            nextTemplateOffset,
          };
          cache.templates.set(templateOffset, template);
        }
      }

      if (!template) {
        throw new Error(`template at offset 0x${templateOffset.toString(16)} not found`);
      }

      const subCount = cursor.u32();
      if (subCount > 10000 || cursor.remaining < subCount * 4) {
        throw new Error(`implausible substitution count ${subCount} for template 0x${templateOffset.toString(16)}`);
      }

      const descriptors: { size: number; type: number }[] = [];
      for (let i = 0; i < subCount; i++) {
        descriptors.push({ size: cursor.u16(), type: cursor.u16() });
      }

      const substitutions: SubstitutionEntry[] = [];
      for (let i = 0; i < subCount; i++) {
        const d = descriptors[i];
        if (cursor.remaining < d.size) {
          throw new Error('substitution data runs past payload end');
        }
        substitutions.push({
          index: i,
          size: d.size,
          type: d.type,
          data: cursor.take(d.size),
        });
      }

      fullXml += renderTemplateXml(template.nodes, substitutions, chunk, cache, 0, recordChunkOffset);
    } else if (tag === TOKEN_OPEN_START_ELEMENT || tag === TOKEN_OPEN_START_ELEMENT_ATTR) {
      const elem = parseElement(cursor, tag, recordChunkOffset, cache, 0);
      if (elem) {
        fullXml += renderTemplateXml([elem], [], chunk, cache, 0, recordChunkOffset);
      }
    } else {
      throw new Error(`unexpected BinXML tag: 0x${tag.toString(16)}`);
    }
  }

  if (!fullXml) {
    throw new Error('BinXML yielded empty document');
  }

  // Extract System fields from the rendered XML
  let eventId: number | null = null;
  const idMatch = fullXml.match(/<EventID[^>]*>(\d+)<\/EventID>/i);
  if (idMatch) eventId = parseInt(idMatch[1], 10);

  let level: string | null = null;
  const lvlMatch = fullXml.match(/<Level[^>]*>(\d+)<\/Level>/i);
  if (lvlMatch) level = parseLevel(parseInt(lvlMatch[1], 10));

  let provider: string | null = null;
  const provMatch = fullXml.match(/<Provider\s+[^>]*Name="([^"]+)"/i);
  if (provMatch) provider = provMatch[1];

  let channel: string | null = null;
  const chMatch = fullXml.match(/<Channel[^>]*>([^<]+)<\/Channel>/i);
  if (chMatch) channel = chMatch[1];

  let computer: string | null = null;
  const compMatch = fullXml.match(/<Computer[^>]*>([^<]+)<\/Computer>/i);
  if (compMatch) computer = compMatch[1];

  let userId: string | null = null;
  const usrMatch = fullXml.match(/<Security\s+[^>]*UserID="([^"]+)"/i);
  if (usrMatch) userId = usrMatch[1];

  let processId: number | null = null;
  let threadId: number | null = null;
  const execMatch = fullXml.match(/<Execution\s+([^>]*)\/>/i);
  if (execMatch) {
    const pidMatch = execMatch[1].match(/ProcessID="(\d+)"/i);
    if (pidMatch) processId = parseInt(pidMatch[1], 10);
    const tidMatch = execMatch[1].match(/ThreadID="(\d+)"/i);
    if (tidMatch) threadId = parseInt(tidMatch[1], 10);
  }

  // EvtxECmd parses the record XML once and resolves every map path against
  // that tree, so we do the same rather than pattern-matching the text.
  const root = parseXml(fullXml);
  const map = eventId === null ? undefined : maps?.findMap(eventId, channel, provider);
  const mapped = map ? applyMap(root, map) : {};

  let eventRecordId: string | null = null;
  const eriMatch = fullXml.match(/<EventRecordID[^>]*>([^<]*)<\/EventRecordID>/i);
  if (eriMatch) eventRecordId = eriMatch[1];

  // TimeCreated comes from the XML rather than the record header: it is what
  // EvtxECmd reports, and on a copied or re-written log the two can differ.
  let timeCreated: Date | null = null;
  const tcMatch = fullXml.match(/<TimeCreated[^>]*SystemTime="([^"]+)"/i);
  if (tcMatch) {
    const t = Date.parse(tcMatch[1].endsWith('Z') ? tcMatch[1] : `${tcMatch[1]}Z`);
    if (Number.isFinite(t)) timeCreated = new Date(t);
  }

  // Keywords is a System field EvtxECmd reports; it is how an analyst spots
  // audit success versus failure without reading the payload.
  const kwMatch = fullXml.match(/<Keywords>([^<]*)<\/Keywords>/i);

  return {
    eventId,
    level,
    provider,
    channel,
    computer,
    userId,
    processId,
    threadId,
    keywords: kwMatch ? kwMatch[1] : null,
    eventRecordId,
    timeCreated,
    mapDescription: map?.description ?? null,
    userName: mapped.UserName ?? null,
    remoteHost: mapped.RemoteHost ?? null,
    executableInfo: mapped.ExecutableInfo ?? null,
    payloadData1: mapped.PayloadData1 ?? null,
    payloadData2: mapped.PayloadData2 ?? null,
    payloadData3: mapped.PayloadData3 ?? null,
    payloadData4: mapped.PayloadData4 ?? null,
    payloadData5: mapped.PayloadData5 ?? null,
    payloadData6: mapped.PayloadData6 ?? null,
    payload: extractPayloadXml(fullXml),
    binXmlEnd: cursor.pos,
    xml: fullXml,
  };
}
