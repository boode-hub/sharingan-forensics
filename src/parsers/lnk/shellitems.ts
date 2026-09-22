/**
 * Shell item (ShellBag) parsing for the LNK target ID list.
 *
 * Ported from Eric Zimmerman's Lnk library (Lnk/ShellItems/*) and his
 * ExtensionBlocks library (Beef0004), which is where a shell item keeps the
 * long file name, the MFT reference and the DOS timestamps.
 *
 * The target ID list is the part of a shortcut that survives when the link
 * info does not: it records the path as the shell resolved it, and each file
 * or directory entry carries the MFT entry and sequence number of the object
 * it pointed at.
 *
 * https://github.com/EricZimmerman/Lnk
 * https://github.com/EricZimmerman/ExtensionBlocks
 */
import { guid, utf16Raw } from '../../core/binary';

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
  /** NTFS, FAT or exFAT, inferred as his Beef0004 infers it. */
  fileSystemHint: string | null;
  /** Raw item type byte, so an unexpected one is still visible. */
  itemType: number;
  /** Offset of this item within the file. */
  offset: number;
}

const ASCII = new TextDecoder('windows-1252');

function cp1252(b: Uint8Array): string {
  return ASCII.decode(b);
}

/** Text up to the first NUL, cp1252. */
function cstr(b: Uint8Array, start: number, max = b.length): string {
  let i = start;
  while (i < max && b[i] !== 0) i++;
  return cp1252(b.subarray(start, i));
}

/** Text up to the first NUL pair, UTF-16LE. */
function wstr(b: Uint8Array, start: number, max = b.length): string {
  let i = start;
  while (i + 1 < max && !(b[i] === 0 && b[i + 1] === 0)) i += 2;
  return utf16Raw(b.subarray(start, i));
}

/**
 * The DOS date and time a shell item stores, as his
 * Utils.ExtractDateTimeOffsetFromBytes reads it. Two-second resolution, and
 * the value is already UTC-ish: he treats it as UTC and so do we, because
 * changing that would silently shift every shell item timestamp.
 */
export function dosDate(b: Uint8Array, at: number): Date | null {
  if (at + 4 > b.length) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const d = dv.getUint16(at, true);
  const t = dv.getUint16(at + 2, true);
  if (d === 0 && t === 0) return null;

  const day = d & 0x1f;
  const month = (d & 0x1e0) >> 5;
  const year = ((d & 0xfe00) >> 9) + 1980;
  const hour = (t & 0xf800) >> 11;
  const minute = (t & 0x07e0) >> 5;
  const second = (t & 0x001f) * 2;

  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  return Number.isFinite(ms) ? new Date(ms) : null;
}

/** The 8-byte file reference a Beef0004 carries, packed as in $MFT. */
function mftReference(b: Uint8Array, at: number): { entry: number | null; sequence: number | null } {
  if (at + 8 > b.length) return { entry: null, sequence: null };
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const low = dv.getUint32(at, true);
  const high = dv.getUint16(at + 4, true);
  const sequence = dv.getUint16(at + 6, true);
  return {
    entry: high === 0 ? low : low + high * 16_777_216,
    sequence: sequence === 0 ? null : sequence,
  };
}

/**
 * Splits the trailing multi-string of a Beef0004 into its pieces: the long
 * name first, then the localised name when one is present.
 */
function multiString(b: Uint8Array): string[] {
  const text = utf16Raw(b);
  return text.split('\0').filter((s) => s.length > 0);
}

interface Beef0004 {
  created: Date | null;
  accessed: Date | null;
  longName: string;
  localisedName: string;
  mftEntry: number | null;
  mftSequence: number | null;
}

/**
 * Reads the 0xbeef0004 extension block, which is where the useful part of a
 * file or directory shell item lives.
 */
function readBeef0004(b: Uint8Array): Beef0004 | null {
  if (b.length < 20) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const version = dv.getUint16(2, true);

  const created = dosDate(b, 8);
  const accessed = dosDate(b, 12);

  let index = 18;
  let mftEntry: number | null = null;
  let mftSequence: number | null = null;

  if (version >= 7) {
    index += 2; // two empty bytes
    const ref = mftReference(b, index);
    mftEntry = ref.entry;
    mftSequence = ref.sequence;
    index += 8;
    index += 8; // eight unknown
  }
  if (version >= 3) index += 2;
  if (version >= 9) index += 4;
  if (version >= 8) index += 4;

  if (index >= b.length) return { created, accessed, longName: '', localisedName: '', mftEntry, mftSequence };

  // The last two bytes are the version offset, not string data.
  const strings = multiString(b.subarray(index, Math.max(index, b.length - 2)));
  return {
    created,
    accessed,
    longName: strings.length === 1 ? strings[0] : strings.length > 1 ? strings[0] : '',
    localisedName: strings.length > 1 ? strings[1] : '',
    mftEntry,
    mftSequence,
  };
}

/** Walks the extension blocks that follow a file or directory entry. */
function findBeef0004(b: Uint8Array, from: number): Beef0004 | null {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let index = from;
  while (index + 8 <= b.length) {
    const size = dv.getUint16(index, true);
    if (size <= 0) break;
    if (size === 1) {
      index += 2; // a separator
      continue;
    }
    if (index + size > b.length) break;
    const signature = dv.getUint32(index + 4, true);
    if (signature === 0xbeef0004) {
      return readBeef0004(b.subarray(index, index + size));
    }
    index += size;
  }
  return null;
}

/**
 * Locates the 0xbeef0004 block by its signature, as he does: the name that
 * precedes it has no length field, so its end is found by looking for where
 * the block starts.
 */
function beefPosition(b: Uint8Array): number {
  for (let i = 0; i + 4 <= b.length; i++) {
    if (b[i] === 0x04 && b[i + 1] === 0x00 && b[i + 2] === 0xef && b[i + 3] === 0xbe) {
      return i - 4; // back up over size and version
    }
  }
  return -1;
}

/** Control panel categories, keyed by the byte at offset 8 as he reads it. */
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
  0x0a: 'Security Center',
  0x0b: 'Mobile PC',
};

function emptyItem(type: number, offset: number): ShellItem {
  return {
    friendlyName: 'Unknown',
    value: '',
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

/** His Beef0004 infers the file system from what the reference does or does not carry. */
function fileSystemHint(b: Beef0004): string | null {
  if (b.mftEntry !== null && b.mftSequence !== null && b.mftEntry > 0 && b.mftSequence > 0) {
    return 'NTFS';
  }
  if (b.mftEntry !== null && b.mftSequence === null && b.accessed) {
    // A FAT access time has no time component at all; exFAT keeps one.
    return b.accessed.getUTCMinutes() === 0 &&
      b.accessed.getUTCSeconds() === 0 &&
      b.accessed.getUTCMilliseconds() === 0
      ? 'FAT'
      : 'exFAT';
  }
  return null;
}

/**
 * A file (0x32, 0x36) or directory (0x31 and friends) entry. Both have the
 * same shape; only the friendly name and whether the size field means anything
 * differ.
 */
function fileEntry(b: Uint8Array, type: number, offset: number, isDirectory: boolean): ShellItem {
  const item = emptyItem(type, offset);
  item.friendlyName = isDirectory ? 'Directory' : 'File';

  if (b.length < 14) return item;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);

  const size = dv.getUint32(4, true);
  item.fileSize = isDirectory ? null : size;
  item.modified = dosDate(b, 8);

  // 2 size + 1 type + 1 unknown + 4 size + 4 date + 2 attributes
  const nameAt = 14;
  const wide = type === 0x35 || type === 0x36;
  const beefAt = beefPosition(b);

  let nameEnd: number;
  if (beefAt < 0) {
    // No extension block: the name runs to its own terminator.
    nameEnd = nameAt;
    if (wide) {
      while (nameEnd + 1 < b.length && !(b[nameEnd] === 0 && b[nameEnd + 1] === 0)) nameEnd += 2;
    } else {
      while (nameEnd < b.length && b[nameEnd] !== 0) nameEnd += 1;
    }
  } else if (wide) {
    nameEnd = beefAt;
  } else {
    nameEnd = nameAt;
    while (nameEnd < b.length && b[nameEnd] !== 0) nameEnd += 1;
  }

  const raw = b.subarray(nameAt, Math.max(nameAt, Math.min(nameEnd, b.length)));
  const shortName = (wide ? utf16Raw(raw) : cp1252(raw)).replace(/\0+$/, '');
  item.shortName = shortName || null;
  item.value = shortName;

  if (beefAt >= 0) {
    const beef = findBeef0004(b, beefAt);
    if (beef) {
      if (beef.longName) item.value = beef.longName;
      else if (beef.localisedName) item.value = beef.localisedName;
      item.created = beef.created;
      item.accessed = beef.accessed;
      item.mftEntry = beef.mftEntry;
      item.mftSequence = beef.mftSequence;
      item.fileSystemHint = fileSystemHint(beef);
    }
  }

  return item;
}

/** A GUID-named folder: "Root folder: GUID" in his output. */
function guidEntry(
  b: Uint8Array,
  type: number,
  offset: number,
  names: Record<string, string>,
  friendly: string,
): ShellItem {
  const item = emptyItem(type, offset);
  item.friendlyName = friendly;
  if (b.length < 20) return item;
  const g = guid(b.subarray(4, 20));
  item.value = names[g] ?? `Unmapped GUID: ${g}`;
  return item;
}

/**
 * Parses one shell item. Never throws: an item type we do not model yet still
 * yields a row naming its type, because dropping the rest of the path would
 * lose more than an unnamed entry does.
 */
export function parseShellItem(
  b: Uint8Array,
  offset: number,
  guidNames: Record<string, string>,
): ShellItem {
  const type = b.length > 2 ? b[2] : 0;

  try {
    switch (type) {
      case 0x1f: {
        // Root folder. A drive-letter variant exists; everything else is a GUID.
        if (b.length > 6 && b[4] === 0x2f) {
          const item = emptyItem(type, offset);
          item.friendlyName = 'Users property view: Drive letter';
          item.value = cp1252(b.subarray(13, Math.min(16, b.length)));
          return item;
        }
        return guidEntry(b, type, offset, guidNames, 'Root folder: GUID');
      }

      case 0x2e:
        return guidEntry(b, type, offset, guidNames, 'Device');

      case 0x71: {
        // His ShellBag0X71: the GUID sits at 14, not 4, except for two shapes
        // where it is back at 4.
        const item = emptyItem(type, offset);
        item.friendlyName = 'GUID: Control panel';
        let at = 14;
        if (b[2] === 0x4d || b.length === 0x16) at = 4;
        if (at + 16 > b.length) return item;
        const g = guid(b.subarray(at, at + 16));
        item.value = guidNames[g] ?? `Unmapped GUID: ${g}`;
        return item;
      }

      case 0x2a:
      case 0x2f: {
        const item = emptyItem(type, offset);
        item.friendlyName = 'Drive letter';
        item.value = cp1252(b.subarray(3, Math.min(5, b.length)));
        return item;
      }

      case 0x31:
      case 0x35:
      case 0x39:
      case 0x3a:
      case 0xb1:
        return fileEntry(b, type, offset, true);

      case 0x32:
      case 0x36:
        return fileEntry(b, type, offset, false);

      case 0x61: {
        // URI. The interesting part is the URI itself, at the end.
        const item = emptyItem(type, offset);
        item.friendlyName = 'URI';
        const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
        const dataSize = b.length >= 6 ? dv.getUint16(4, true) : 0;
        if (dataSize === 0) {
          item.value = wstr(b, 8);
        } else if (b.length > 46) {
          const strSize = dv.getUint32(42, true);
          if (strSize > 0 && 46 + strSize <= b.length) {
            item.value = cp1252(b.subarray(46, 46 + strSize)).replace(/\0/g, '');
          }
        }
        return item;
      }

      case 0x74:
      case 0x77: {
        // "Users Files Folder": a CFSF wrapper around an ordinary file entry,
        // then a delegate GUID and the item's own GUID. The embedded entry is
        // laid out like a 0x32 file entry, six bytes further in.
        const item = emptyItem(type, offset);
        item.friendlyName = 'Users Files Folder';
        if (b.length < 26 || cp1252(b.subarray(6, 10)) !== 'CFSF') {
          item.value = cstr(b, 6);
          return item;
        }
        const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
        item.fileSize = dv.getUint32(14, true);
        item.modified = dosDate(b, 18);

        let end = 24;
        while (end < b.length && b[end] !== 0) end += 1;
        const primary = cp1252(b.subarray(24, end));
        item.shortName = primary || null;
        item.value = primary;

        const beefAt = beefPosition(b);
        if (beefAt >= 0) {
          const beef = findBeef0004(b, beefAt);
          if (beef) {
            if (beef.longName) item.value = beef.longName;
            else if (beef.localisedName) item.value = beef.localisedName;
            item.created = beef.created;
            item.accessed = beef.accessed;
            item.mftEntry = beef.mftEntry;
            item.mftSequence = beef.mftSequence;
            item.fileSystemHint = fileSystemHint(beef);
          }
        }
        return item;
      }

      case 0x01: {
        const item = emptyItem(type, offset);
        item.friendlyName = 'Control Panel Category';
        if (b.length < 10) return item;
        const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);

        // Hyper-V browsing puts a drive letter here instead.
        if (b[8] === 0x3a && b[9] === 0x00) {
          item.friendlyName = 'Hyper-V storage volume';
          item.value = b.length > 0x32 ? utf16Raw(b.subarray(0x32)).replace(/\0/g, '') : '';
          return item;
        }

        if (dv.getUint32(4, true) !== 0x39de2184) {
          item.value = b.length > 14 ? utf16Raw(b.subarray(14)).replace(/\0/g, '') : '';
          return item;
        }

        item.value = CONTROL_PANEL_CATEGORIES[b[8]] ?? `Category ${b[8]}`;
        return item;
      }

      case 0x00: {
        const item = emptyItem(type, offset);
        item.friendlyName = 'Variable';
        if (b.length < 8) return item;
        const signature = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(4, true);
        if (signature === 0xc001b000) {
          // A URL container: the address is a NUL-terminated string near the end.
          item.friendlyName = 'Variable: URI';
          item.value = wstr(b, 0x28).replace(/\0/g, '');
          return item;
        }
        if (signature === 0x49534647) {
          item.friendlyName = 'Variable: Game folder';
          return item;
        }
        // Anything else is a users property view, whose name lives in a
        // property store we do not decode. Reporting it unnamed is honest;
        // scraping the nearest run of bytes would put invented text into a
        // path an analyst may rely on.
        item.friendlyName = 'Variable: Users property view';
        return item;
      }

      default: {
        const item = emptyItem(type, offset);
        item.friendlyName = `Unmodelled shell item type 0x${type.toString(16)}`;
        return item;
      }
    }
  } catch {
    // A malformed item must not take the rest of the list with it.
    const item = emptyItem(type, offset);
    item.friendlyName = `Unreadable shell item type 0x${type.toString(16)}`;
    return item;
  }
}

/**
 * The absolute path as LECmd builds it: every shell item's value, trimmed of
 * separators and joined with a backslash.
 */
export function absolutePath(items: ShellItem[]): string {
  return items
    .map((i) => i.value.replace(/^\\+|\\+$/g, ''))
    .join('\\');
}
