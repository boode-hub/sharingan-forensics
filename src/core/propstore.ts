/**
 * Serialized property stores ([MS-PROPSTORE]): the name/value sheets Windows
 * embeds in shell items, in a shortcut's PropertyStoreDataBlock and in jump
 * list entries. For many modern shell items the name an analyst sees in
 * Explorer lives only here.
 *
 * Ported from Eric Zimmerman's ExtensionBlocks PropertyStore.cs and
 * PropertySheet.cs (https://github.com/EricZimmerman/ExtensionBlocks),
 * including how he renders each value type as text. Where he throws on a
 * sheet that does not parse, or on a key that repeats, this keeps what it
 * read and goes on.
 */
import { guid, iso, preciseDate } from './binary';
import { PROPERTY_KEYS } from './propkeys';

export interface PropertySheet {
  guid: string;
  /** Named sheets key their values by name; numeric ones by property id. */
  named: boolean;
  properties: Array<[string, string]>;
}

const NAMED_SHEET = 'd5cdd505-2e9c-101b-9397-08002b2cf9ae';

// The value types his two switches decode; anything else is printed as
// "Unknown ... property type" with its bytes in hex.
const NAMED_TYPES = new Set([0x0b, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x0a, 0x14, 0x15, 0x16, 0x13, 0x17, 0x1f, 0x40, 0x41, 0x42]);
const NUMERIC_TYPES = new Set([0x1048, 0x1e, 0x1f, 0x0b, 0x03, 0x15, 0x42, 0x13, 0x01, 0x02, 0x101f, 0x48, 0x1011, 0x40, 0x08]);

const utf16 = (b: Uint8Array, at: number, len: number) =>
  new TextDecoder('utf-16le').decode(b.subarray(at, Math.max(at, Math.min(at + Math.max(0, len), b.length))));

/** BitConverter.ToString: upper-case hex, dash separated. */
const dashed = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0').toUpperCase()).join('-');

/** A float32 as .NET prints it: the shortest text that reads back as the same float. */
function single(v: number): string {
  for (let p = 1; p <= 9; p++) {
    const s = Number(v.toPrecision(p));
    if (Math.fround(s) === v) return String(s);
  }
  return String(v);
}

/**
 * DateTime.FromFileTimeUtc, written as every time here is (ISO 8601, UTC, seven
 * digits) rather than his InvariantCulture "MM/dd/yyyy HH:mm:ss", which carries
 * no zone and would read as local time beside the rest.
 */
function filetimeText(ticks: bigint): string {
  if (ticks < 0n) return '';
  return iso(preciseDate(Number(ticks / 10000n) - 11644473600000, Number(ticks % 10000n)));
}

/** Splits a list of size-prefixed records, stopping at a zero or implausible size. */
function records(b: Uint8Array, start: number, strict: boolean): Uint8Array[] {
  const out: Uint8Array[] = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let at = start;
  while (at + 4 <= b.length) {
    const size = dv.getInt32(at, true);
    if (size === 0 || (strict && size >>> 0 >= b.length) || size < 0 || at + size > b.length) break;
    out.push(b.subarray(at, at + size));
    at += size;
  }
  return out;
}

function sheet(contents: Uint8Array, guidNames: Record<string, string>): PropertySheet | null {
  if (contents.length < 24) return null;
  // "1SPS", as he checks it.
  if (contents[4] !== 0x31 || contents[5] !== 0x53 || contents[6] !== 0x50 || contents[7] !== 0x53) return null;
  const formatId = guid(contents.subarray(8, 24));
  const named = formatId === NAMED_SHEET;
  const properties: Array<[string, string]> = [];
  const add = (key: string, value: string) => properties.push([key, value]);

  for (const v of records(contents, 24, !named)) {
    const dv = new DataView(v.buffer, v.byteOffset, v.byteLength);
    try {
      let key: string;
      let at: number;
      if (named) {
        const nameSize = dv.getInt32(4, true);
        key = utf16(v, 9, nameSize - 2);
        at = 9 + nameSize;
      } else {
        key = String(dv.getInt32(4, true));
        at = 9;
      }
      const type = dv.getUint16(at, true);
      at += 4; // type and padding
      const rest = () => dashed(v.subarray(at));

      if (!(named ? NAMED_TYPES : NUMERIC_TYPES).has(type)) {
        add(
          key,
          `Unknown ${named ? 'named' : 'numeric'} property type: ${type.toString(16).toUpperCase()}, Hex data (after property type): ${rest()}`,
        );
        continue;
      }

      switch (type) {
        case 0x000b:
          add(key, dv.getInt32(at, true) > 0 ? 'True' : 'False');
          break;
        case 0x0000:
          add(key, '');
          break;
        case 0x0001:
          add(key, named ? '' : 'Null');
          break;
        case 0x0002:
          // He reads it signed in named sheets and unsigned in numeric ones.
          add(key, String(named ? dv.getInt16(at, true) : dv.getUint16(at, true)));
          break;
        case 0x0003:
        case 0x0016:
          add(key, String(dv.getInt32(at, true)));
          break;
        case 0x0004:
          add(key, single(dv.getFloat32(at, true)));
          break;
        case 0x0005:
          add(key, String(dv.getFloat64(at, true)));
          break;
        case 0x0008: {
          const len = dv.getInt32(at, true);
          add(key, utf16(v, at + 4, len - 2));
          break;
        }
        case 0x000a:
        case 0x0013:
        case 0x0017:
          add(key, String(dv.getUint32(at, true)));
          break;
        case 0x0014:
          add(key, String(dv.getBigInt64(at, true)));
          break;
        case 0x0015:
          add(key, String(dv.getBigUint64(at, true)));
          break;
        case 0x001e: {
          const len = dv.getInt32(at, true);
          add(key, utf16(v, at + 4, len).split('\0')[0]);
          break;
        }
        case 0x001f: {
          const len = dv.getInt32(at, true);
          add(key, len <= 0 ? '' : utf16(v, at + 4, len * 2 - 2));
          break;
        }
        case 0x0040:
          add(key, filetimeText(dv.getBigInt64(at, true)));
          break;
        case 0x0041:
          // A blob can hold a property store of its own; he lists its values
          // after the blob's hex.
          add(key, `BLOB data: ${dashed(v.subarray(at + 4))}`);
          for (const inner of parsePropertyStore(v.subarray(0x69), guidNames)) {
            for (const p of inner.properties) add(p[0], p[1]);
          }
          break;
        case 0x0042:
          add(key, named ? 'VT_STREAM not implemented (yet) See extension block section for contents for now' : 'VT_STREAM not implemented');
          break;
        case 0x0048: {
          const g = guid(v.subarray(at, at + 16));
          add(key, guidNames[g] ?? `Unmapped GUID: ${g}`);
          break;
        }
        case 0x1011:
          add(key, 'VT_VECTOR data not implemented (yet) See extension block section for contents for now');
          break;
        case 0x1048:
          add(key, 'VT_VECTOR data not implemented (yet)');
          break;
        case 0x101f: {
          // A vector of strings: he reads the first.
          let text = '';
          if (v.length > at + 4) {
            const len = dv.getInt32(at + 4, true);
            text = utf16(v, at + 8, len * 2 - 2);
          }
          add(key, text);
          break;
        }
      }
    } catch {
      // A value that runs off the end of its record: keep the others.
    }
  }
  return { guid: formatId, named, properties };
}

/** Every sheet in a serialized property store. */
export function parsePropertyStore(b: Uint8Array, guidNames: Record<string, string>): PropertySheet[] {
  const out: PropertySheet[] = [];
  for (const r of records(b, 0, true)) {
    const s = sheet(r, guidNames);
    if (s) out.push(s);
  }
  return out;
}

/** The key's name, as his GetDescriptionFromGuidAndKey gives it. */
export function propertyName(sheetGuid: string, key: string): string {
  return PROPERTY_KEYS[sheetGuid.toLowerCase()]?.[key] ?? '(Description not available)';
}

/** One line per sheet, as his PropertySheet.ToString writes them. */
export function describeSheets(sheets: PropertySheet[]): string {
  return sheets
    .map((s, i) =>
      `Sheet #${i} => ` +
      s.properties
        .map(([k, v]) => `Guid: ${s.guid}, Key: ${k} ==> ${s.named ? k : propertyName(s.guid, k)}, Value: ${v}`)
        .join('; '),
    )
    .join('\n');
}

/**
 * The name a property view shows, as his shell items choose it: the value of
 * property 10 (System.ItemNameDisplay) if any sheet has one, otherwise every
 * value joined with "::".
 */
export function propertyViewName(sheets: PropertySheet[], empty: string): string {
  for (const s of sheets) for (const [k, v] of s.properties) if (k === '10') return v;
  const all = sheets.flatMap((s) => s.properties.map(([, v]) => v)).join('::');
  return all === '' ? empty : all;
}
