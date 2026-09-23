/**
 * Shell items: the entries of a shortcut's target ID list, of a jump list's
 * shortcuts and of the registry's shell bags.
 *
 * Ported class by class from Eric Zimmerman's Lnk library (Lnk/ShellItems:
 * ShellBag0X00, 0X01, 0X1F, 0X23, 0X2E, 0X2F, 0X31, 0X32, 0X40, 0X4C, 0X61,
 * 0X71, 0X74, 0Xc3, ShellBagZipContents, ShellBagCDBurn), the type dispatch in
 * LnkFile.cs, and his ExtensionBlocks library (Beef0004, Beef0026,
 * MFTInformation, Utils.GetStringsFromMultistring), which is where a file or
 * directory entry keeps its long name, MFT reference and timestamps. Values,
 * friendly names and the order he tries each layout in are his.
 *
 * Where his code throws - an unknown item type, a signature he did not
 * expect - the item is kept with what could be read, because one strange
 * entry must not cost the analyst the rest of the path.
 *
 * https://github.com/EricZimmerman/Lnk
 * https://github.com/EricZimmerman/ExtensionBlocks
 */
import { filetime, guid, utf16Raw } from './binary';
import { describeSheets, parsePropertyStore, propertyViewName, type PropertySheet } from './propstore';
import { invariantDate } from './textdate';

export interface ShellItem {
  /** His FriendlyName: what kind of thing this entry names. */
  friendlyName: string;
  /** His Value: the name that goes into the absolute path. */
  value: string;
  /** 8.3 name, where the entry carries one. */
  shortName: string | null;
  fileSize: number | null;
  modified: Date | null;
  created: Date | null;
  accessed: Date | null;
  mftEntry: number | null;
  mftSequence: number | null;
  /** His MFTInformation.Note: NTFS, FAT, or Network/special item. */
  fileSystemHint: string | null;
  /** Raw item type byte, so an unexpected one is still visible. */
  itemType: number;
  /** Offset of this item within the file. */
  offset: number;
}

type Names = Record<string, string>;

const CP1252 = new TextDecoder('windows-1252');
const cp1252 = (b: Uint8Array) => CP1252.decode(b);

/** Encoding.Unicode.GetString over [at, at+len), clamped to the buffer. */
const unicode = (b: Uint8Array, at: number, len: number) =>
  utf16Raw(b.subarray(at, Math.max(at, Math.min(at + Math.max(0, len), b.length))));

/** Text up to the first NUL pair, UTF-16LE. */
function wstr(b: Uint8Array, start: number, max = b.length): string {
  let i = start;
  while (i + 1 < max && !(b[i] === 0 && b[i + 1] === 0)) i += 2;
  return utf16Raw(b.subarray(start, i));
}

const view = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength);
const u16 = (b: Uint8Array, at: number) => (at + 2 <= b.length ? view(b).getUint16(at, true) : 0);
const i16 = (b: Uint8Array, at: number) => (at + 2 <= b.length ? view(b).getInt16(at, true) : 0);
const u32 = (b: Uint8Array, at: number) => (at + 4 <= b.length ? view(b).getUint32(at, true) : 0);
const i32 = (b: Uint8Array, at: number) => (at + 4 <= b.length ? view(b).getInt32(at, true) : 0);

/** GuidMapping.GetDescriptionFromGuid. */
const folder = (g: string, names: Names) => names[g.toLowerCase().replace(/[{}]/g, '')] ?? `Unmapped GUID: ${g}`;
const guidAt = (b: Uint8Array, at: number) => (at + 16 <= b.length ? guid(b.subarray(at, at + 16)) : '');

/**
 * The DOS date and time a shell item stores, as his
 * Utils.ExtractDateTimeOffsetFromBytes reads it: taken as UTC.
 */
export function dosDate(b: Uint8Array, at: number): Date | null {
  if (at + 4 > b.length) return null;
  const d = u16(b, at);
  const t = u16(b, at + 2);
  const day = d & 0x1f;
  const month = (d & 0x1e0) >> 5;
  const year = ((d & 0xfe00) >> 9) + 1980;
  const hour = (t & 0xf800) >> 11;
  const minute = (t & 0x07e0) >> 5;
  const second = (t & 0x001f) * 2;
  if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) return null;
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  // new DateTime rejects 31 February rather than rolling it into March.
  return date.getUTCDate() === day ? date : null;
}

/**
 * Utils.GetStringsFromMultistring, as he wrote it: the pieces are found by
 * searching the bytes' hex text for "00-00-", which is what decides where a
 * long name ends and a localised name begins. Everything is read as UTF-16,
 * so the ANSI localised name of a Windows XP (version 3) Beef0004 comes out
 * as mojibake here exactly as it does in his tools.
 */
function multiString(raw: Uint8Array): string[] {
  const b = raw.subarray(0, Math.max(0, raw.length - 2)); // the last two are the version offset
  let hex = Array.from(b, (x) => x.toString(16).padStart(2, '0').toUpperCase()).join('-');
  if (hex.startsWith('00-00-00-')) return [''];
  if (!hex.endsWith('-00-00-00')) hex += '-00';
  const out: string[] = [];
  let index = 0;
  const re = /00-00-/gi;
  for (let m = re.exec(hex); m; m = re.exec(hex)) {
    const position = Math.floor((m.index + 3) / 3);
    if (position + 2 < b.length) {
      out.push(unicode(b, index, position - index).replace(/\0/g, ''));
      index += position + 2;
    }
  }
  if (index + 4 <= b.length) out.push(unicode(b, index, b.length - index).replace(/\0/g, ''));
  return out;
}

interface Beef0004 {
  created: Date | null;
  accessed: Date | null;
  longName: string;
  localisedName: string;
  mftEntry: number | null;
  mftSequence: number | null;
  note: string | null;
}

/** His Beef0004: the long name, the MFT reference and the created/accessed times. */
function beef0004(b: Uint8Array): Beef0004 | null {
  if (b.length < 20 || u32(b, 4) !== 0xbeef0004) return null;
  const version = u16(b, 2);
  let index = 18;
  let mftEntry: number | null = null;
  let mftSequence: number | null = null;
  let note: string | null = null;
  if (version >= 7) {
    index += 2;
    if (index + 8 <= b.length) {
      // MFTInformation: a 48-bit entry number and a 16-bit sequence number.
      const low = u32(b, index);
      const high = u16(b, index + 4);
      const seq = u16(b, index + 6);
      mftEntry = high === 0 ? low : low + high * 16_777_216;
      mftSequence = seq === 0 ? null : seq;
      note = mftEntry > 0 && seq > 0 ? 'NTFS' : mftEntry > 0 ? 'FAT' : seq === 0 ? 'Network/special item' : '';
    }
    index += 16;
  }
  if (version >= 3) index += 2;
  if (version >= 9) index += 4;
  if (version >= 8) index += 4;
  const pieces = index < b.length ? multiString(b.subarray(index)) : [];
  return {
    created: dosDate(b, 8),
    accessed: dosDate(b, 12),
    // Only a single string is a long name; with two, the second is the
    // localised name and he leaves the long name empty.
    longName: pieces.length === 1 ? pieces[0] : '',
    localisedName: pieces.length > 1 ? pieces[1] : '',
    mftEntry,
    mftSequence,
    note,
  };
}

/** The size-prefixed extension blocks from `at`, as his shell items cut them up. */
function extensionBlocks(b: Uint8Array, at: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  let index = at;
  while (index + 2 <= b.length) {
    const size = i16(b, index);
    if (size <= 0) break;
    if (size === 1) {
      index += 2;
      continue;
    }
    out.push(b.subarray(index, Math.min(index + size, b.length)));
    index += size;
  }
  return out;
}

/** Where the Beef0004 block starts: four bytes before its "04 00 EF BE" signature. */
function beefPosition(b: Uint8Array): number {
  for (let i = 0; i + 4 <= b.length; i++) {
    if (b[i] === 0x04 && b[i + 1] === 0x00 && b[i + 2] === 0xef && b[i + 3] === 0xbe) return i - 4;
  }
  return -1;
}

function item(type: number, offset: number, friendlyName: string, value = ''): ShellItem {
  return {
    friendlyName,
    value,
    shortName: null,
    fileSize: null,
    modified: null,
    created: null,
    accessed: null,
    mftEntry: null,
    mftSequence: null,
    fileSystemHint: null,
    itemType: type,
    offset,
  };
}

function applyBeef(it: ShellItem, beef: Beef0004) {
  it.created = beef.created;
  it.accessed = beef.accessed;
  it.mftEntry = beef.mftEntry;
  it.mftSequence = beef.mftSequence;
  it.fileSystemHint = beef.note;
}

/** A date his zip folder items store as text, as DateTimeOffset.TryParse reads it. */
function zipDate(b: Uint8Array, at: number): Date | null {
  const text = unicode(b, at, 40).split('\0')[0];
  return text ? invariantDate(text) : null;
}

/** ShellBagZipContents: an entry inside a zip file Explorer browsed into. */
function zipContents(b: Uint8Array, type: number, offset: number): ShellItem {
  const it = item(type, offset, 'Zip file contents');
  it.accessed = zipDate(b, 0x24) ?? zipDate(b, 0x18);
  const read = (start: number): string | null => {
    const size1 = u16(b, start);
    const at = start + 8;
    if (start + 8 > b.length || at + size1 * 2 > b.length) return null;
    return size1 > 0 ? unicode(b, at, size1 * 2) : '!!!Unable to determine value!!!';
  };
  // Windows XP puts the names earlier.
  it.value = read(b[0x14] === 0x10 ? 60 : 84) ?? read(60) ?? '!!!Unable to determine value!!!';
  return it;
}

/** His test for a zip folder date at the usual places: a "/" in "01/20/2016", or "N/A". */
const zipDated = (b: Uint8Array) =>
  b[0x28] === 0x2f || (b[0x24] === 0x4e && b[0x26] === 0x2f && b[0x28] === 0x41);

/** Beef0026.ToString, which is what a control panel category item shows as its value. */
function beef0026Text(b: Uint8Array, names: Names): string {
  const lines = [
    `Signature: 0x${u32(b, 4).toString(16).padStart(8, '0')}`,
    `Size: ${u16(b, 0).toLocaleString('en-US')}`,
    `Version: ${u16(b, 2).toLocaleString('en-US')}`,
  ];
  let sheets: PropertySheet[] = [];
  let versionOffset = 0;
  // "yyyy-MM-dd HH:mm:ss.fffffff", every 100ns tick of the FILETIME.
  const stamp = (at: number) => {
    const ticks = view(b).getBigUint64(at, true);
    const d = new Date(Number(ticks / 10000n) - 11644473600000);
    const frac = String(ticks % 10000000n).padStart(7, '0');
    return `${d.toISOString().slice(0, 19).replace('T', ' ')}.${frac}`;
  };
  const times: string[] = [];
  if ([0x11, 0x10, 0x12, 0x34, 0x31].includes(b[8]) && b.length >= 36) {
    times.push(`Created: ${stamp(12)}`, `Last modified: ${stamp(20)}`, `Last accessed: ${stamp(28)}`);
  } else {
    const size = u16(b, 8);
    if (size <= b.length - 8) {
      sheets = parsePropertyStore(b.subarray(8, 8 + size), names);
      versionOffset = i16(b, b.length - 4);
    }
  }
  lines.push(`Version Offset: 0x${(versionOffset & 0xffff).toString(16).toUpperCase().padStart(2, '0')}`);
  const out = [...lines, '', '', ...times];
  if (sheets.length > 0) out.push('Property Sheets', describeSheets(sheets));
  return out.join('\n');
}

/**
 * The "users property view" shape ShellBag0X00, 0X1F and 0X71 share: a
 * property store, then two GUIDs, then extension blocks. The value is the
 * item's display name from the property store.
 */
function propertyView(
  b: Uint8Array,
  type: number,
  offset: number,
  names: Names,
  empty: string,
  noSheets?: () => ShellItem | null,
): ShellItem {
  const it = item(type, offset, 'Variable: Users property view');
  const listSize = i16(b, 10);
  const identifierSize = i16(b, 12);
  const index = 14 + Math.max(0, identifierSize);
  let sheets: PropertySheet[] = [];
  if (listSize > 0) {
    sheets = parsePropertyStore(b.subarray(index, index + listSize), names);
  } else if (noSheets) {
    const alt = noSheets();
    if (alt) return alt;
  }
  // He names the item from the GUID after the store, then replaces that
  // with the store's display name, which is what he prints.
  it.value = propertyViewName(sheets, empty);
  return it;
}

/** ShellBag0X31 and 0X32: a directory or a file, with its Beef0004. */
function fileEntry(b: Uint8Array, type: number, offset: number, isDirectory: boolean): ShellItem {
  // Browsed zip contents reuse these types; his date test decides.
  if (b.length > (isDirectory ? 0x29 : 0x28)) {
    const zipShape = isDirectory
      ? (b[0x27] === 0x00 && b[0x28] === 0x2f && b[0x29] === 0x00) || (b[0x24] === 0x4e && b[0x26] === 0x2f && b[0x28] === 0x41)
      : zipDated(b);
    if (zipShape && (b[0x28] === 0x2f || b[0x26] === 0x2f || b[0x1a] === 0x2f || b[0x1c] === 0x2f)) {
      const zip = zipContents(b, type, offset);
      if (!zip.value.includes('Unable to determine value')) return zip;
    }
  }

  const it = item(type, offset, isDirectory ? 'Directory' : 'File');
  if (!isDirectory) it.fileSize = u32(b, 4);
  it.modified = dosDate(b, 8);
  let index = 14;
  const wide = type === 0x35 || type === 0x36;
  const beefAt = beefPosition(b);

  if (!isDirectory && beefAt < 0) {
    // No Beef0004 at all: he takes every string that follows, joined by "|".
    const parts = cp1252(b.subarray(index)).split('\0').filter((s) => s.length > 0);
    it.shortName = parts.join('|') || null;
    it.value = parts.join('|');
    return it;
  }

  let len = 0;
  const strLen = beefAt - index;
  if (isDirectory && strLen < 0) {
    // His directory walk without a Beef0004: two bytes at a time to a NUL.
    len = 2;
    while (index + len < b.length && b[index + len] !== 0) len += 2;
  } else if ((isDirectory && (type === 0x35 || type === 0x36)) || (!isDirectory && type === 0x36)) {
    len = strLen;
  } else {
    while (index + len < b.length && b[index + len] !== 0) len += 1;
  }
  const raw = b.subarray(index, Math.min(index + len, b.length));
  const shortName = (wide ? utf16Raw(raw) : cp1252(raw)).replace(/\0+$/, '').replace(/^\0+/, '');
  it.shortName = shortName || null;
  it.value = shortName;
  index += len;

  let blocksAt: number;
  if (isDirectory) {
    while (index < b.length && b[index] === 0) index += 1;
    blocksAt = index;
  } else {
    blocksAt = beefAt;
  }
  for (const block of extensionBlocks(b, blocksAt)) {
    if (block.length < 8) break;
    const beef = beef0004(block);
    if (!beef) continue;
    if (isDirectory) {
      it.value = beef.longName.length === 0 ? beef.localisedName : beef.longName;
    } else if (beef.longName.trim().length > 0) {
      it.value = beef.longName;
    }
    applyBeef(it, beef);
  }
  return it;
}

/** ShellBag0X1F: a root folder, most often a GUID, sometimes a property view or backup. */
function rootFolder(b: Uint8Array, offset: number, names: Names): ShellItem {
  const type = 0x1f;
  const byGuid = () => item(type, offset, 'Root folder: GUID', folder(guidAt(b, 4), names));
  if (b[0] === 0x14) return byGuid();
  if (b[4] === 0x2f) {
    return item(type, offset, 'Users property view: Drive letter', cp1252(b.subarray(13, 16)));
  }
  const mask = b[3] & 0x70;
  if (mask !== 0x00 && mask !== 0x60) return byGuid();

  const sig = u32(b, 6);
  if (sig === 0xbeebee00) return propertyView(b, type, offset, names, 'No Property sheets found');
  if (sig === 0x4c644970) {
    const it = item(type, offset, 'Windows Backup');
    const ft = (at: number) => (at + 8 <= b.length ? filetime(view(b).getBigUint64(at, true)) : null);
    it.modified = ft(0x14);
    it.created = ft(0x1c);
    const nameLen = i16(b, 0x38);
    it.value = unicode(b, 0x3a, nameLen * 2);
    return it;
  }
  if (b[0] === 50 || b[0] === 58) return byGuid();

  // A users property view with a GUID behind its property store.
  const it = item(type, offset, 'Users property view');
  const storeSize = u16(b, 10);
  const identifierSize = u16(b, 12);
  const pos = 14 + identifierSize + storeSize + 2;
  it.value = pos === b.length ? folder(guidAt(b, 4), names) : folder(guidAt(b, pos + 16), names);
  return it;
}

/** ShellBag0X2E: a GUID folder, a user profile, a control panel category, or a property view. */
function shellFolder(b: Uint8Array, offset: number, names: Names): ShellItem {
  const type = 0x2e;
  if (b[3] === 0x80 || b.length === 0x16) {
    return item(type, offset, 'Root folder: GUID', folder(guidAt(b, 4), names));
  }
  const tail = b.length >= 8 ? view(b).getBigUint64(b.length - 8, true) : 0n;
  if (tail === 0x0000ee306bfe9555n || tail === 0xee306bfe9555c589n) {
    const it = item(type, offset, 'User profile');
    it.accessed = dosDate(b, b.length - 14);
    it.value = unicode(b, 10, b.length - 10).split('\0')[0] || '(None)';
    return it;
  }
  if (i32(b, 5) >= 0x15032601) {
    const it = item(type, offset, 'Control panel category');
    if (b.length < 0x48) {
      it.value = beef0026Text(b.subarray(20), names);
      return it;
    }
    it.value = unicode(b, 0x116, b.length - 0x22 - 0x116).replace(/^\0+|\0+$/g, '');
    return it;
  }
  // His property view for this type does not step over the property store
  // before reading the GUIDs, so it names whatever sits 18 bytes past the
  // identifier. Kept as he has it: this is the value his tools print.
  const it = item(type, offset, 'Users property view');
  const listSize = i16(b, 10);
  const identifierSize = i16(b, 12);
  if (listSize <= 0 || identifierSize <= 0) return it;
  const index = 14 + identifierSize + 2;
  it.value = folder(guidAt(b, index + 16), names);
  return it;
}

/** Uri.UnescapeDataString: %XX sequences decoded, anything malformed left alone. */
const unescape = (s: string) =>
  s.replace(/(?:%[0-9a-f]{2})+/gi, (m) => {
    try {
      return decodeURIComponent(m);
    } catch {
      return m;
    }
  });

/** ShellBag0X00: a "variable" item, whose shape is chosen by its signatures. */
function variable(b: Uint8Array, offset: number, names: Names): ShellItem {
  const type = 0x00;
  const special = u32(b, 4);
  if (special === 0xc001b000) {
    const it = item(type, offset, 'Variable: HTTP URI');
    const size = u32(b, 0x14);
    it.value = unescape(unicode(b, 0x18, size).replace(/\0/g, ''));
    return it;
  }
  if (special === 0x49534647) return item(type, offset, 'Variable: Game folder');
  if (special === 0xffffff38) return item(type, offset, 'Variable: Control panel CPL file');

  const dataSig = u32(b, 6);
  switch (dataSig) {
    case 0x00030005:
    case 0x00000005: {
      const it = item(type, offset, 'Variable: FTP URI');
      let index = 0x16;
      it.modified = index + 8 <= b.length ? filetime(view(b).getBigUint64(index, true)) : null;
      index += 16;
      let len = 0;
      while (index + len < b.length && b[index + len] !== 0) len += 1;
      it.shortName = cp1252(b.subarray(index, index + len)) || null;
      index += len;
      while (index < b.length && b[index] === 0) index += 1;
      len = 0;
      while (index + len + 1 < b.length && (b[index + len] !== 0 || b[index + len + 1] !== 0)) len += 1;
      it.value = unicode(b, index, len + 1);
      return it;
    }
    case 0x23febbee: {
      // A property view that is only a GUID.
      const it = item(type, offset, 'Variable');
      if (u16(b, 12) > 0) it.value = folder(guidAt(b, 14), names);
      return it;
    }
    case 0x10312005: {
      const it = item(type, offset, 'Variable: MTP type 2');
      let index = 4 + 2 + 4 + 4 + 2 + 2 + 4 + 12 + 4;
      const storageLen = i32(b, index);
      it.value = unicode(b, index + 16, storageLen * 2 - 2);
      return it;
    }
    case 0x00: {
      const it = item(type, offset, 'Variable: Zip file contents');
      const shaped =
        b[0x28] === 0x2f ||
        (b[0x24] === 0x4e && b[0x26] === 0x2f && b[0x28] === 0x41) ||
        b[0x1c] === 0x2f ||
        (b[0x18] === 0x4e && b[0x1a] === 0x2f && b[0x1c] === 0x41);
      if (!shaped) {
        it.value = '!!! Unable to determine Value !!!';
        return it;
      }
      const zip = zipContents(b, type, offset);
      return zip;
    }
    case 0x07192006: {
      const it = item(type, offset, 'Variable: MTP type 1');
      it.modified = 0x1a + 8 <= b.length ? filetime(view(b).getBigUint64(0x1a, true)) : null;
      it.created = 0x22 + 8 <= b.length ? filetime(view(b).getBigUint64(0x22, true)) : null;
      const storageLen = i32(b, 0x3e);
      const idLen = i32(b, 0x42);
      let index = 0x4a;
      const storage = unicode(b, index, storageLen * 2 - 2);
      index += storageLen * 2;
      const storageId = unicode(b, index, idLen * 2 - 2);
      it.value = storage.length > 0 ? (storage === storageId ? storage : `${storage} (${storageId})`) : storageId;
      return it;
    }
    default: {
      if (b.length <= 0x60) {
        return item(type, offset, 'Server name', unicode(b, 6, b.length - 6).replace(/\0/g, ''));
      }
      if (i16(b, 12) > b.length) {
        const strs = cp1252(b.subarray(0x0c)).split('\0');
        return item(type, offset, 'Variable: Users property view', `${strs[0]} (${strs.slice(1).join(',')})`);
      }
      return propertyView(b, type, offset, names, 'No Property sheet value found', () => {
        if (zipDated(b)) return zipContents(b, type, offset);
        if (b[4] === 0x41 && b[5] === 0x75 && b[6] === 0x67 && b[7] === 0x4d) return cdBurn(b, offset);
        return null;
      });
    }
  }
}

/** ShellBagCDBurn ("AugM"): a file staged for burning, which wraps a file entry. */
function cdBurn(b: Uint8Array, offset: number): ShellItem {
  const it = item(0x00, offset, 'CDBurn');
  let index = 8 + 12;
  while (index + 2 <= b.length) {
    const size = i16(b, index);
    index += 2;
    if (size <= 0) break;
    if (size === 1) {
      index += 2;
      continue;
    }
    const inner = b.subarray(index, Math.min(index + size, b.length));
    index += size;
    // The chunk is a file entry without its size field.
    const wide = inner[0] === 0x35;
    it.modified = dosDate(inner, 6);
    const beefAt = beefPosition(inner);
    let at = 12;
    if (wide) {
      it.shortName = unicode(inner, at, beefAt - at - 2) || null;
      at = beefAt;
    } else {
      let len = 0;
      while (at + len < inner.length && inner[at + len] !== 0) len += 1;
      it.shortName = String.fromCharCode(...inner.subarray(at, at + len)) || null;
      at += len;
    }
    while (at < inner.length && inner[at] === 0) at += 1;
    const beef = beef0004(inner.subarray(at));
    if (beef) {
      applyBeef(it, beef);
      if (beef.longName.trim().length > 0) it.value = beef.longName;
    } else {
      it.value = '!!! Unable to determine Value !!!';
    }
  }
  return it;
}

/** ShellBag0X74: a "users files folder" (CFSF) wrapping a file entry. */
function usersFilesFolder(b: Uint8Array, offset: number): ShellItem {
  const type = b[2];
  const sig = cp1252(b.subarray(6, 10));
  if (sig === 'CF\0\0' && zipDated(b)) return zipContents(b, type, offset);
  const it = item(type, offset, 'Users Files Folder');
  if (sig !== 'CFSF') return it;
  it.fileSize = u32(b, 14);
  it.modified = dosDate(b, 18);
  let index = 24;
  let len = 0;
  while (index + len < b.length && b[index + len] !== 0) len += 1;
  it.shortName = cp1252(b.subarray(index, index + len)) || null;
  index += len;
  while (index < b.length && b[index] === 0) index += 1;
  index += 32; // the delegate GUID and the item's own GUID
  // He sets the value only from the long name; the primary name is the short one.
  for (const block of extensionBlocks(b, index)) {
    const beef = beef0004(block);
    if (!beef) continue;
    if (beef.longName.trim().length > 0) it.value = beef.longName;
    applyBeef(it, beef);
  }
  return it;
}

/** Control panel categories, as ShellBag0X01 numbers them. */
const CONTROL_PANEL_CATEGORIES: Record<number, string> = {
  0x00: 'All Control Panel Items',
  0x01: 'Appearance and Personalization',
  0x02: 'Hardware and Sound',
  0x03: 'Network and Internet',
  0x04: 'Sound, Speech and Audio Devices',
  0x05: 'System and Security',
  0x06: 'Clock, Language, and Region',
  0x07: 'Ease of Access',
  0x08: 'Programs',
  0x09: 'User Accounts',
  0x10: 'Security Center',
  0x11: 'Mobile PC',
};

const NETWORK_NAMES: Record<number, string> = {
  0x47: 'Entire Network',
  0x46: 'Microsoft Windows Network',
  0x41: 'Domain/Workgroup name',
  0x42: 'Server UNC path',
  0x43: 'Share UNC path',
};

/**
 * Parses one shell item. Never throws: an item his library would reject still
 * yields a row naming its type, because dropping the rest of the path would
 * lose more than an unnamed entry does.
 */
export function parseShellItem(b: Uint8Array, offset: number, guidNames: Names): ShellItem {
  const type = b.length > 2 ? b[2] : 0;
  try {
    // LnkFile checks for browsed zip contents before it looks at the type.
    if (b.length > 0x28 && view(b).getBigInt64(0x8, true) === 0n && view(b).getBigInt64(0x18, true) === 0n) {
      if (b[0x28] === 0x2f || b[0x26] === 0x2f || b[0x1a] === 0x2f || b[0x1c] === 0x2f) {
        return zipContents(b, type, offset);
      }
    }

    switch (type) {
      case 0x1f:
        return rootFolder(b, offset, guidNames);
      case 0x22:
      case 0x23:
      case 0x2a:
      case 0x2f:
        return item(type, offset, 'Drive letter', cp1252(b.subarray(3, 5)));
      case 0x2e:
        return shellFolder(b, offset, guidNames);
      case 0x31:
      case 0x35:
      case 0x39:
      case 0x3a:
      case 0xb1:
        return fileEntry(b, type, offset, true);
      case 0x32:
      case 0x36:
        return fileEntry(b, type, offset, false);
      case 0x00:
        return variable(b, offset, guidNames);
      case 0x01: {
        if (b[8] === 0x3a && b[9] === 0x00) {
          return item(type, offset, 'Hyper-V storage volume', unicode(b, 0x32, b.length - 0x32).replace(/\0/g, ''));
        }
        if (u32(b, 4) !== 0x39de2184) {
          return item(type, offset, 'Control Panel Category', unicode(b, 14, b.length - 14).replace(/\0/g, ''));
        }
        return item(
          type,
          offset,
          'Control Panel Category',
          CONTROL_PANEL_CATEGORIES[b[8]] ?? `Unknown category! Category ID: ${b[8]}`,
        );
      }
      case 0x71: {
        if (u32(b, 6) === 0xbeebee00) {
          return propertyView(b, type, offset, guidNames, 'No Property sheet value found', () =>
            zipDated(b) ? zipContents(b, type, offset) : null,
          );
        }
        const at = b.length === 0x16 ? 4 : 14;
        return item(type, offset, 'GUID: Control panel', folder(guidAt(b, at), guidNames));
      }
      case 0x61: {
        const it = item(type, offset, 'URI');
        const dataSize = u16(b, 4);
        if (dataSize === 0) {
          it.value = wstr(b, 8);
        } else {
          it.modified = 14 + 8 <= b.length ? filetime(view(b).getBigUint64(14, true)) : null;
          const size = u32(b, 42);
          it.value = cp1252(b.subarray(46, Math.min(46 + size, b.length))).replace(/\0/g, '');
        }
        return it;
      }
      case 0xc3: {
        let len = 0;
        while (5 + len < b.length && b[5 + len] !== 0) len += 1;
        return item(type, offset, 'Network location', cp1252(b.subarray(5, 5 + len)));
      }
      case 0x74:
      case 0x77:
        return usersFilesFolder(b, offset);
      case 0xae:
      case 0xaa:
      case 0x79:
        return zipContents(b, type, offset);
      case 0x41:
      case 0x42:
      case 0x43:
      case 0x46:
      case 0x47:
        return item(type, offset, NETWORK_NAMES[type], cp1252(b.subarray(5)).split('\0')[0]);
      case 0x4c: {
        let index = 0x1c;
        let len = i16(b, index);
        index += 2;
        const name = unicode(b, index, len * 2).replace(/^\0+|\0+$/g, '');
        index += len * 2 + 2;
        len = i16(b, index);
        index += 2;
        const url = unicode(b, index, len * 2).replace(/^\0+|\0+$/g, '') || 'URL not specified';
        return item(type, offset, 'Sharepoint directory', `${name} (${url})`);
      }
      default:
        return item(type, offset, `Unknown shell item ID: 0x${type.toString(16).toUpperCase()}`);
    }
  } catch {
    // A malformed item must not take the rest of the list with it.
    return item(type, offset, `Unreadable shell item type 0x${type.toString(16)}`);
  }
}

/**
 * The absolute path as LECmd builds it: every shell item's value, trimmed of
 * separators and joined with a backslash.
 */
export function absolutePath(items: ShellItem[]): string {
  return items.map((i) => i.value.replace(/^\\+|\\+$/g, '')).join('\\');
}
