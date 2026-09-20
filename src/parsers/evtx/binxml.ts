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
import { findMap } from './maps';

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
      const elem = parseElement(cursor, op, templateChunkStart, cache, depth);
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
): BinXmlNode | null {
  if (depth > 20) return null;
  const hasAttr = op === TOKEN_OPEN_START_ELEMENT_ATTR;
  cursor.skip(2); // dependency identifier / substitution slot
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
      const childElem = parseElement(cursor, childOp, chunkBase, cache, depth + 1);
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
      return Array.from(d)
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join('-');
    case 0x0f: // GuidType
      return guid(d);
    case 0x11: {
      // FileTimeType
      if (d.length < 8) return '';
      const ft = dv.getBigUint64(0, true);
      const dt = filetime(ft);
      return dt ? dt.toISOString() : '';
    }
    case 0x12: {
      // SysTimeType
      const st = systemTime(d);
      return st ? st.toISOString() : '';
    }
    case 0x13: // SidType
      return formatSid(d);
    case 0x14: // HexInt32Type
      return d.length >= 4
        ? `0x${dv.getUint32(0, true).toString(16).toUpperCase()}`
        : '';
    case 0x15: // HexInt64Type
      return d.length >= 8
        ? `0x${dv.getBigUint64(0, true).toString(16).toUpperCase()}`
        : '';
    case 0x21: {
      // BinXmlType
      return decodeNestedBinXml(d, chunk, cache, depth + 1, recordChunkOffset);
    }
    case 0x81: {
      // ArrayUnicodeString
      const s = new TextDecoder('utf-16le').decode(d);
      return s
        .split('\0')
        .filter((x) => x.length > 0)
        .join(', ');
    }
    case 0x82: {
      // ArrayAsciiString
      const s = new TextDecoder('windows-1252').decode(d);
      return s
        .split('\0')
        .filter((x) => x.length > 0)
        .join(', ');
    }
    case 0x83: {
      // Array8BitIntSigned
      const arr: number[] = [];
      for (let i = 0; i < d.length; i++) arr.push(dv.getInt8(i));
      return arr.join(',');
    }
    case 0x84: {
      // Array8BitIntUnsigned
      return Array.from(d).join(',');
    }
    case 0x85: {
      // Array16BitIntSigned
      const arr: number[] = [];
      for (let i = 0; i + 2 <= d.length; i += 2) arr.push(dv.getInt16(i, true));
      return arr.join(',');
    }
    case 0x86: {
      // Array16BitIntUnsigned
      const arr: number[] = [];
      for (let i = 0; i + 2 <= d.length; i += 2) arr.push(dv.getUint16(i, true));
      return arr.join(',');
    }
    case 0x87: {
      // Array32BitIntSigned
      const arr: number[] = [];
      for (let i = 0; i + 4 <= d.length; i += 4) arr.push(dv.getInt32(i, true));
      return arr.join(',');
    }
    case 0x88: {
      // Array32BitIntUnsigned
      const arr: number[] = [];
      for (let i = 0; i + 4 <= d.length; i += 4) arr.push(dv.getUint32(i, true));
      return arr.join(',');
    }
    case 0x89: {
      // Array64BitIntSigned
      const arr: string[] = [];
      for (let i = 0; i + 8 <= d.length; i += 8)
        arr.push(dv.getBigInt64(i, true).toString());
      return arr.join(',');
    }
    case 0x8a: {
      // Array64BitIntUnsigned
      const arr: string[] = [];
      for (let i = 0; i + 8 <= d.length; i += 8)
        arr.push(dv.getBigUint64(i, true).toString());
      return arr.join(',');
    }
    case 0x8b: {
      // ArrayFloat32Bit
      const arr: number[] = [];
      for (let i = 0; i + 4 <= d.length; i += 4) arr.push(dv.getFloat32(i, true));
      return arr.join(',');
    }
    case 0x8c: {
      // ArrayFloat64Bit
      const arr: number[] = [];
      for (let i = 0; i + 8 <= d.length; i += 8) arr.push(dv.getFloat64(i, true));
      return arr.join(',');
    }
    case 0x8d: {
      // ArrayBool
      const arr: boolean[] = [];
      for (let i = 0; i + 4 <= d.length; i += 4)
        arr.push(dv.getInt32(i, true) !== 0);
      return arr.join(',');
    }
    case 0x8f: {
      // ArrayGuid
      const arr: string[] = [];
      for (let i = 0; i + 16 <= d.length; i += 16)
        arr.push(guid(d.subarray(i, i + 16)));
      return arr.join(',');
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

  while (cursor.remaining > 0 && !cursor.overran) {
    const op = cursor.u8();
    if (op === TOKEN_EOF) break;
    if (op === TOKEN_START_STREAM) {
      cursor.skip(3);
      continue;
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
        throw new Error(`implausible substitution count: ${subCount}`);
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

export interface DecodedRecord {
  eventId: number | null;
  level: string | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
  userId: string | null;
  processId: number | null;
  threadId: number | null;
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
 * Extracts and formats the EventData / UserData payload as compact JSON of
 * name/value pairs, applying any matching EventMap.
 */
function extractPayload(
  xml: string,
  eventId: number | null,
  channel: string | null,
  provider: string | null,
): string | null {
  // Extract EventData or UserData tag
  const eventDataMatch = xml.match(/<EventData[^>]*>([\s\S]*?)<\/EventData>/i);
  const userDataMatch = xml.match(/<UserData[^>]*>([\s\S]*?)<\/UserData>/i);

  const rawSection = eventDataMatch ? eventDataMatch[1] : userDataMatch ? userDataMatch[1] : null;

  const eventDataPairs: Record<string, string> = {};
  const unnamedData: string[] = [];

  if (rawSection) {
    // Extract <Data Name="Key">Value</Data> or <Data>Value</Data>
    const dataRegex = /<Data(?:\s+Name="([^"]*)")?[^>]*>([\s\S]*?)<\/Data>/gi;
    let match: RegExpExecArray | null;
    while ((match = dataRegex.exec(rawSection)) !== null) {
      const name = match[1];
      const val = match[2].trim();
      if (name) {
        eventDataPairs[name] = val;
      } else {
        unnamedData.push(val);
      }
    }

    // If UserData with arbitrary child tags:
    if (Object.keys(eventDataPairs).length === 0 && unnamedData.length === 0) {
      const tagRegex = /<([A-Za-z0-9_]+)[^>]*>([^<]*)<\/\1>/gi;
      let tm: RegExpExecArray | null;
      while ((tm = tagRegex.exec(rawSection)) !== null) {
        eventDataPairs[tm[1]] = tm[2].trim();
      }
    }
  }

  // Look up event map
  let map: EventMap | undefined;
  if (eventId !== null) {
    map = findMap(eventId, channel, provider);
  }

  const payloadObj: Record<string, string> = {};

  if (map) {
    if (map.description) {
      payloadObj['MapDescription'] = map.description;
    }

    for (const prop of map.properties) {
      const varValues: Record<string, string> = {};
      let anyMatched = false;

      for (const valDef of prop.values) {
        let rawVal: string | undefined;
        const nameAttr = valDef.path.match(/@Name="([^"]+)"/);
        if (nameAttr) {
          rawVal = eventDataPairs[nameAttr[1]];
        } else {
          const idxMatch = valDef.path.match(/Data\[(\d+)\]/);
          if (idxMatch) {
            const idx = parseInt(idxMatch[1], 10) - 1;
            rawVal = unnamedData[idx];
          } else if (valDef.path.endsWith('/Data')) {
            rawVal = unnamedData[0] || Object.values(eventDataPairs)[0];
          } else {
            const tagMatch = valDef.path.match(/\/([A-Za-z0-9_]+)$/);
            if (tagMatch) {
              const re = new RegExp(`<${tagMatch[1]}[^>]*>([^<]*)</${tagMatch[1]}>`, 'i');
              const m = xml.match(re);
              if (m) rawVal = m[1];
            }
          }
        }

        if (rawVal !== undefined && rawVal !== '') {
          anyMatched = true;
          let finalVal = rawVal;

          if (valDef.refine) {
            try {
              const re = new RegExp(valDef.refine, 'i');
              const rm = finalVal.match(re);
              if (rm) {
                finalVal = rm[1] !== undefined ? rm[1] : rm[0];
              }
            } catch {
              // ignore regex errors
            }
          }

          if (map.lookups) {
            const lu = map.lookups.find(
              (l) => l.name.toUpperCase() === valDef.name.toUpperCase(),
            );
            if (lu) {
              if (lu.values[finalVal] !== undefined) {
                finalVal = lu.values[finalVal];
              } else if (lu.defaultVal) {
                finalVal = `${lu.defaultVal} (${finalVal})`;
              }
            }
          }

          varValues[valDef.name] = finalVal;
          if (!eventDataPairs[valDef.name] && finalVal) {
            payloadObj[valDef.name] = finalVal;
          }
        }
      }

      if (anyMatched && prop.template) {
        let resolved = prop.template;
        for (const [k, v] of Object.entries(varValues)) {
          resolved = resolved.split(`%${k}%`).join(v);
        }
        resolved = resolved.replace(/%[A-Za-z0-9_]+%/g, '').trim();
        if (resolved) {
          payloadObj[prop.property] = resolved;
        }
      }
    }
  }

  // Merge original named data items
  for (const [k, v] of Object.entries(eventDataPairs)) {
    if (payloadObj[k] === undefined) {
      payloadObj[k] = v;
    }
  }

  // Include unnamed data items if not mapped
  for (let i = 0; i < unnamedData.length; i++) {
    const key = `Data_${i}`;
    if (payloadObj[key] === undefined) {
      payloadObj[key] = unnamedData[i];
    }
  }

  if (Object.keys(payloadObj).length === 0) {
    return null;
  }

  return JSON.stringify(payloadObj);
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
        throw new Error(`implausible substitution count: ${subCount}`);
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

  const payload = extractPayload(fullXml, eventId, channel, provider);

  return {
    eventId,
    level,
    provider,
    channel,
    computer,
    userId,
    processId,
    threadId,
    payload,
    xml: fullXml,
  };
}
