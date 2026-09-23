/**
 * Windows Shortcut (.lnk) parser.
 *
 * Ported from Eric Zimmerman's Lnk library and LECmd's output. The column set
 * is his CSV's, and the target ID list, which he decodes into shell items, is
 * decoded here too: it is the part of a shortcut that records the path as the
 * shell resolved it, along with the MFT entry and sequence number of the
 * object each step pointed at. A shortcut whose link info is missing or
 * stripped often still has it.
 *
 * Rows are one per entry. The first is the shortcut itself and carries every
 * field LECmd's CSV has; after it comes one row per shell item and one per
 * extra data block, so nothing in the file is summarised into a count.
 *
 * Format references:
 *   - [MS-SHLLINK]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/
 *   - https://github.com/EricZimmerman/Lnk
 */
import type { Column, Parser, Reader, Ctx, Row } from '../core/types';
import { Cursor, guid } from '../core/binary';
import { absolutePath, parseShellItem, type ShellItem } from '../core/shellitem';
import { parsePropertyStore, propertyName } from '../core/propstore';

const LinkCLSID = '00021401-0000-0000-c000-000000000046';
const HEADER_SIZE = 76;

const columns: Column[] = [
  { key: 'entryType', label: 'Entry Type', type: 'str' },
  { key: 'path', label: 'Path', type: 'str' },
  { key: 'itemKind', label: 'Kind', type: 'str' },
  { key: 'shortName', label: 'Short Name', type: 'str' },
  { key: 'targetCreated', label: 'Target Created', type: 'date' },
  { key: 'targetModified', label: 'Target Modified', type: 'date' },
  { key: 'targetAccessed', label: 'Target Accessed', type: 'date' },
  { key: 'fileSize', label: 'File Size', type: 'num' },
  { key: 'mftEntry', label: 'MFT Entry', type: 'num' },
  { key: 'mftSequence', label: 'MFT Sequence', type: 'num' },
  { key: 'fileSystemHint', label: 'File System Hint', type: 'str' },
  { key: 'relativePath', label: 'Relative Path', type: 'str' },
  { key: 'workingDirectory', label: 'Working Directory', type: 'str' },
  { key: 'arguments', label: 'Arguments', type: 'str' },
  { key: 'iconLocation', label: 'Icon Location', type: 'str' },
  { key: 'description', label: 'Description', type: 'str' },
  { key: 'fileAttributes', label: 'File Attributes', type: 'str' },
  { key: 'headerFlags', label: 'Header Flags', type: 'str' },
  { key: 'driveType', label: 'Drive Type', type: 'str' },
  { key: 'volumeSerialNumber', label: 'Volume Serial Number', type: 'str' },
  { key: 'volumeLabel', label: 'Volume Label', type: 'str' },
  { key: 'localPath', label: 'Local Path', type: 'str' },
  { key: 'networkPath', label: 'Network Path', type: 'str' },
  { key: 'commonPath', label: 'Common Path', type: 'str' },
  { key: 'targetIdAbsolutePath', label: 'Target ID Absolute Path', type: 'str' },
  { key: 'machineId', label: 'Machine ID', type: 'str' },
  { key: 'machineMacAddress', label: 'Machine MAC Address', type: 'str' },
  { key: 'machineMacVendor', label: 'MAC Vendor', type: 'str' },
  { key: 'trackerCreatedOn', label: 'Tracker Created On', type: 'date' },
  { key: 'extraBlocksPresent', label: 'Extra Blocks Present', type: 'str' },
  { key: 'sourceFile', label: 'Source File', type: 'str' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
];

/** His DriveTypes descriptions, which is what LECmd and JLECmd print. */
const DRIVE_TYPES = [
  'Unknown',
  'No root directory',
  'Removable storage media (Floppy, USB)',
  'Fixed storage media (Hard drive)',
  'Remote storage',
  'Optical disc (CD-ROM, DVD, BD)',
  'RAM drive',
];

/** His DataFlag names, so the header flags read the same in both tools. */
const DATA_FLAGS: Array<[number, string]> = [
  [0x00000001, 'HasTargetIdList'],
  [0x00000002, 'HasLinkInfo'],
  [0x00000004, 'HasName'],
  [0x00000008, 'HasRelativePath'],
  [0x00000010, 'HasWorkingDir'],
  [0x00000020, 'HasArguments'],
  [0x00000040, 'HasIconLocation'],
  [0x00000080, 'IsUnicode'],
  [0x00000100, 'ForceNoLinkInfo'],
  [0x00000200, 'HasExpString'],
  [0x00000400, 'RunInSeparateProcess'],
  [0x00000800, 'Reserved0'],
  [0x00001000, 'HasDarwinId'],
  [0x00002000, 'RunAsUser'],
  [0x00004000, 'HasExpIcon'],
  [0x00008000, 'NoPidlAlias'],
  [0x00010000, 'Reserved1'],
  [0x00020000, 'RunWithShimLayer'],
  [0x00040000, 'ForceNoLinkTrack'],
  [0x00080000, 'EnableTargetMetadata'],
  [0x00100000, 'DisableLinkPathTracking'],
  [0x00200000, 'DisableKnownFolderTracking'],
  [0x00400000, 'DisableKnownFolderAlias'],
  [0x00800000, 'AllowLinkToLink'],
  [0x01000000, 'UnaliasOnSave'],
  [0x02000000, 'PreferEnvironmentPath'],
  [0x04000000, 'KeepLocalIdListForUncTarget'],
];

/** His FileAttribute names. */
const FILE_ATTRIBUTES: Array<[number, string]> = [
  [0x00000001, 'FileAttributeReadonly'],
  [0x00000002, 'FileAttributeHidden'],
  [0x00000004, 'FileAttributeSystem'],
  [0x00000008, 'ResVolumeLabel'],
  [0x00000010, 'FileAttributeDirectory'],
  [0x00000020, 'FileAttributeArchive'],
  [0x00000040, 'FileAttributeDevice'],
  [0x00000080, 'FileAttributeNormal'],
  [0x00000100, 'FileAttributeTemporary'],
  [0x00000200, 'FileAttributeSparseFile'],
  [0x00000400, 'FileAttributeReparsePoint'],
  [0x00000800, 'FileAttributeCompressed'],
  [0x00001000, 'FileAttributeOffline'],
  [0x00002000, 'FileAttributeNotContentIndexed'],
  [0x00004000, 'FileAttributeEncrypted'],
  [0x00008000, 'UnkWin95Fat'],
  [0x00010000, 'FileAttributeVirtual'],
];

const EXTRA_BLOCK_NAMES: Record<number, string> = {
  0xa0000001: 'EnvironmentVariableDataBlock',
  0xa0000002: 'ConsoleDataBlock',
  0xa0000003: 'TrackerDataBaseBlock',
  0xa0000004: 'ConsoleFEDataBlock',
  0xa0000005: 'SpecialFolderDataBlock',
  0xa0000006: 'DarwinDataBlock',
  0xa0000007: 'IconEnvironmentDataBlock',
  0xa0000008: 'ShimDataBlock',
  0xa0000009: 'PropertyStoreDataBlock',
  0xa000000b: 'KnownFolderDataBlock',
  0xa000000c: 'VistaAndAboveIDListDataBlock',
};

function flagNames(value: number, table: Array<[number, string]>): string {
  const names = table.filter(([bit]) => (value & bit) !== 0).map(([, name]) => name);
  return names.length > 0 ? names.join(', ') : '0';
}

const CP1252 = new TextDecoder('windows-1252');

function cstr(b: Uint8Array, start = 0, max = b.length): string {
  let i = start;
  while (i < max && b[i] !== 0) i++;
  return CP1252.decode(b.subarray(start, i));
}

function wstr(b: Uint8Array, start = 0, max = b.length): string {
  let i = start;
  while (i + 1 < max && !(b[i] === 0 && b[i + 1] === 0)) i += 2;
  let s = '';
  for (let k = start; k < i; k += 2) s += String.fromCharCode(b[k] | (b[k + 1] << 8));
  return s;
}

/**
 * The creation time embedded in a version 1 UUID, which is how the tracker
 * block's file droid records when the target was first seen. 100-nanosecond
 * intervals since the Gregorian reform.
 */
export function uuidV1Time(b: Uint8Array): Date | null {
  if (b.length < 16) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const low = BigInt(dv.getUint32(0, true));
  const mid = BigInt(dv.getUint16(4, true));
  const hiAndVersion = dv.getUint16(6, true);
  const hi = BigInt(hiAndVersion & 0x0fff);
  const ticks = (hi << 48n) | (mid << 32n) | low;
  if (ticks === 0n) return null;
  // 1582-10-15 to 1970-01-01 in 100ns units.
  const ms = Number((ticks - 122_192_928_000_000_000n) / 10_000n);
  if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return null;
  return new Date(ms);
}

/**
 * LECmd's MACVendor: the vendor for the first three octets, from his table,
 * or "(Unknown vendor)". Nothing when there is no tracker block.
 */
export async function macVendor(mac: string | null): Promise<string | null> {
  if (!mac) return null;
  const { MAC_VENDORS } = await import('./lnk/macs');
  return MAC_VENDORS[mac.split(':').slice(0, 3).join('').toUpperCase()] ?? '(Unknown vendor)';
}

/** The MAC address the tracker block leaves in the last node of the file droid. */
export function macFromDroid(g: string): string | null {
  const node = g.split('-').pop();
  if (!node || node.length !== 12) return null;
  return (node.match(/.{2}/g) ?? []).join(':');
}

export interface LnkBlock {
  name: string;
  signature: number;
  size: number;
  offset: number;
  detail: string | null;
}

/** A decoded shortcut: his LnkFile, as LECmd and JLECmd read it. */
export interface LnkFile {
  linkFlags: number;
  fileAttributes: number;
  targetCreated: Date | null;
  targetAccessed: Date | null;
  targetModified: Date | null;
  fileSize: number;
  items: ShellItem[];
  /** His DriveType description, or "(None)" when there is no volume info. */
  driveType: string;
  volumeSerialNumber: string | null;
  volumeLabel: string | null;
  localPath: string | null;
  /** The network share name from the link info. */
  networkPath: string | null;
  commonPath: string | null;
  description: string | null;
  relativePath: string | null;
  workingDirectory: string | null;
  arguments: string | null;
  iconLocation: string | null;
  blocks: LnkBlock[];
  machineId: string | null;
  machineMacAddress: string | null;
  trackerCreatedOn: Date | null;
}

export const fileAttributeNames = (f: LnkFile) => flagNames(f.fileAttributes, FILE_ATTRIBUTES);
export const headerFlagNames = (f: LnkFile) => flagNames(f.linkFlags, DATA_FLAGS);
export const hasArguments = (f: LnkFile) => (f.linkFlags & 0x20) !== 0;

/**
 * The target's MFT reference as LECmd and JLECmd take it: from the Beef0004
 * block of the last shell item, and nowhere else.
 */
export function targetMft(f: LnkFile): { entry: number | null; sequence: number | null } {
  const last = f.items[f.items.length - 1];
  return { entry: last?.mftEntry ?? null, sequence: last?.mftSequence ?? null };
}

/**
 * Decodes a shortcut held in memory: a .lnk file, or one embedded in a jump
 * list. Returns null, having warned, only when the header itself is unusable;
 * everything after it is read as far as it goes.
 */
export function parseLnk(
  buf: Uint8Array,
  guidNames: Record<string, string>,
  warn: (offset: number, message: string) => void,
): LnkFile | null {
  if (buf.length < HEADER_SIZE) {
    warn(0, `truncated header (${buf.length}/${HEADER_SIZE} bytes)`);
    return null;
  }

  const c = new Cursor(buf, 0);
  if (c.u32() !== 0x4c) {
    warn(0, 'invalid HeaderSize, expected 0x4C');
    return null;
  }
  const linkCLSID = c.guid();
  if (linkCLSID.toLowerCase() !== LinkCLSID) {
    warn(4, `invalid LinkCLSID ${linkCLSID}`);
    return null;
  }

  const linkFlags = c.u32();
  const fileAttributes = c.u32();
  const targetCreated = c.filetime();
  const targetAccessed = c.filetime();
  const targetModified = c.filetime();
  const fileSize = c.u32();
  c.i32(); // icon index
  c.u32(); // show command
  c.u16(); // hotkey
  c.skip(10); // reserved

  const has = (bit: number) => (linkFlags & bit) !== 0;
  const isUnicode = has(0x80);

  let pos = HEADER_SIZE;

  // Target ID list.
  const items: ShellItem[] = [];
  if (has(0x01)) {
    if (pos + 2 > buf.length) {
      warn(pos, 'truncated target ID list size');
    } else {
      const listSize = new DataView(buf.buffer, buf.byteOffset + pos, 2).getUint16(0, true);
      const listStart = pos + 2;
      const listEnd = Math.min(listStart + listSize, buf.length);
      if (listStart + listSize > buf.length) {
        warn(pos, 'target ID list runs past the end of the file; reading what is there');
      }

      let p = listStart;
      while (p + 2 <= listEnd) {
        const size = new DataView(buf.buffer, buf.byteOffset + p, 2).getUint16(0, true);
        if (size === 0) break; // terminator
        if (size < 3 || p + size > listEnd) {
          warn(p, `shell item size ${size} does not fit the list; stopping here`);
          break;
        }
        items.push(parseShellItem(buf.subarray(p, p + size), p, guidNames));
        p += size;
      }

      pos = listStart + listSize;
    }
  }

  // Link info.
  let driveType = '(None)';
  let volumeSerialNumber: string | null = null;
  let volumeLabel: string | null = null;
  let localPath: string | null = null;
  let networkPath: string | null = null;
  let commonPath: string | null = null;

  if (has(0x02)) {
    if (pos + 4 > buf.length) {
      warn(pos, 'truncated link info');
    } else {
      const li = new DataView(buf.buffer, buf.byteOffset + pos, Math.min(buf.length - pos, 4));
      const linkInfoSize = li.getUint32(0, true);
      const end = pos + linkInfoSize;

      if (linkInfoSize < 28 || end > buf.length) {
        warn(pos, `link info size ${linkInfoSize} does not fit the file`);
      } else {
        const lv = new DataView(buf.buffer, buf.byteOffset + pos, linkInfoSize);
        const headerSize = lv.getUint32(4, true);
        const flags = lv.getUint32(8, true);
        const volumeIdOffset = lv.getUint32(12, true);
        const localBasePathOffset = lv.getUint32(16, true);
        const networkRelativeLinkOffset = lv.getUint32(20, true);
        const commonPathSuffixOffset = lv.getUint32(24, true);

        // The unicode offsets only exist in the larger header.
        const hasUnicode = headerSize >= 0x24;
        const localBasePathUnicodeOffset = hasUnicode ? lv.getUint32(28, true) : 0;
        const commonPathSuffixUnicodeOffset = hasUnicode ? lv.getUint32(32, true) : 0;

        if ((flags & 0x01) !== 0 && volumeIdOffset > 0 && pos + volumeIdOffset + 16 <= end) {
          const v = pos + volumeIdOffset;
          const vv = new DataView(buf.buffer, buf.byteOffset + v, Math.min(end - v, 64));
          const volumeIdSize = vv.getUint32(0, true);
          const dt = vv.getUint32(4, true);
          driveType = DRIVE_TYPES[dt] ?? String(dt);
          // His ToString("X8") of the serial as a signed int: always 8 digits.
          volumeSerialNumber = (vv.getUint32(8, true) >>> 0).toString(16).toUpperCase().padStart(8, '0');

          const labelOffset = vv.getUint32(12, true);
          if (labelOffset === 0x14 && volumeIdSize >= 20) {
            // The 0x14 sentinel means the real label is unicode.
            const unicodeOffset = vv.getUint32(16, true);
            volumeLabel = wstr(buf, v + unicodeOffset, Math.min(v + volumeIdSize, buf.length));
          } else {
            volumeLabel = cstr(buf, v + labelOffset, Math.min(v + volumeIdSize, buf.length));
          }
        }

        if (localBasePathUnicodeOffset > 0) {
          localPath = wstr(buf, pos + localBasePathUnicodeOffset, end);
        } else if (localBasePathOffset > 0) {
          localPath = cstr(buf, pos + localBasePathOffset, end);
        }

        if (commonPathSuffixUnicodeOffset > 0) {
          commonPath = wstr(buf, pos + commonPathSuffixUnicodeOffset, end);
        } else if (commonPathSuffixOffset > 0) {
          commonPath = cstr(buf, pos + commonPathSuffixOffset, end);
        }

        if ((flags & 0x02) !== 0 && networkRelativeLinkOffset > 0) {
          const n = pos + networkRelativeLinkOffset;
          if (n + 20 <= end) {
            const nv = new DataView(buf.buffer, buf.byteOffset + n, Math.min(end - n, 64));
            const netNameOffset = nv.getUint32(8, true);
            if (netNameOffset > 0) networkPath = cstr(buf, n + netNameOffset, end);
          }
        }

        pos = end;
      }
    }
  }

  // String data, in the order the format fixes.
  let description: string | null = null;
  let relativePath: string | null = null;
  let workingDirectory: string | null = null;
  let args: string | null = null;
  let iconLocation: string | null = null;

  const readString = (): string | null => {
    if (pos + 2 > buf.length) return null;
    const charCount = new DataView(buf.buffer, buf.byteOffset + pos, 2).getUint16(0, true);
    pos += 2;
    const byteCount = isUnicode ? charCount * 2 : charCount;
    if (pos + byteCount > buf.length) {
      warn(pos, `truncated string data (need ${byteCount}, have ${buf.length - pos})`);
      pos = buf.length;
      return null;
    }
    const slice = buf.subarray(pos, pos + byteCount);
    pos += byteCount;
    // The count is characters, not bytes, and the string is not terminated.
    return isUnicode ? wstr(slice, 0, slice.length) : CP1252.decode(slice);
  };

  if (has(0x04)) description = readString();
  if (has(0x08)) relativePath = readString();
  if (has(0x10)) workingDirectory = readString();
  if (has(0x20)) args = readString();
  if (has(0x40)) iconLocation = readString();

  // Extra data blocks.
  const blocks: LnkBlock[] = [];
  let machineId: string | null = null;
  let machineMacAddress: string | null = null;
  let trackerCreatedOn: Date | null = null;

  while (pos + 8 <= buf.length) {
    const bv = new DataView(buf.buffer, buf.byteOffset + pos, 8);
    const blockSize = bv.getUint32(0, true);
    if (blockSize < 4) break; // terminal block
    if (pos + blockSize > buf.length) {
      warn(pos, `extra data block of ${blockSize} bytes runs past the end of the file`);
      break;
    }
    const signature = bv.getUint32(4, true);
    const name = EXTRA_BLOCK_NAMES[signature] ?? `Unknown block 0x${signature.toString(16)}`;
    const block = buf.subarray(pos, pos + blockSize);
    let detail: string | null = null;

    switch (signature) {
      case 0xa0000003: {
        // Tracker block: machine name, and the droid GUIDs that carry the
        // MAC address of the machine and when the target was first seen.
        if (blockSize >= 0x60) {
          machineId = cstr(block, 16, 32);
          const fileDroid = guid(block.subarray(0x30, 0x40));
          machineMacAddress = macFromDroid(fileDroid);
          trackerCreatedOn = uuidV1Time(block.subarray(0x30, 0x40));
          detail = `Machine ID: ${machineId}; File droid: ${fileDroid}`;
        }
        break;
      }
      case 0xa0000001: // EnvironmentVariableDataBlock
      case 0xa0000006: // DarwinDataBlock
      case 0xa0000007: // IconEnvironmentDataBlock
      case 0xa0000008: {
        // ShimDataBlock. All of these are an ANSI string followed by its
        // unicode twin; the unicode one is authoritative when present.
        const ansi = cstr(block, 8, Math.min(8 + 260, blockSize));
        const uni = blockSize > 268 ? wstr(block, 268, blockSize) : '';
        detail = uni || ansi || null;
        break;
      }
      case 0xa0000005: {
        // SpecialFolderDataBlock: a CSIDL and the offset into the ID list.
        if (blockSize >= 16) {
          const sv = new DataView(buf.buffer, buf.byteOffset + pos, 16);
          detail = `Folder ID: ${sv.getUint32(8, true)}; Offset: ${sv.getUint32(12, true)}`;
        }
        break;
      }
      case 0xa000000b: {
        // KnownFolderDataBlock: a folder GUID and the offset into the ID list.
        if (blockSize >= 28) {
          const g = guid(block.subarray(8, 24));
          detail = `${guidNames[g] ?? `Unmapped GUID: ${g}`} (${g})`;
        }
        break;
      }
      case 0xa0000009: {
        // PropertyStoreDataBlock, written out as his ToString lays it out:
        // GUID\id, the property's name, then its value.
        const sheets = parsePropertyStore(block.subarray(8), guidNames);
        const lines = sheets.flatMap((s) =>
          s.properties.map(
            ([k, v]) => `${`${s.guid}\\${k}`.padEnd(43)} ${propertyName(s.guid, k).padEnd(35)} ==> ${v}`,
          ),
        );
        detail =
          sheets.length === 0
            ? null
            : ['Property store data block (Format: GUID\\ID Description ==> Value)', ...(lines.length ? lines : ['(Property store is empty)'])].join('\n');
        break;
      }
      case 0xa0000002: {
        // ConsoleDataBlock: the window's colours and font.
        if (blockSize >= 12) {
          const cv = new DataView(buf.buffer, buf.byteOffset + pos, 12);
          detail = `Fill attributes: 0x${cv.getUint16(8, true).toString(16)}`;
        }
        break;
      }
      case 0xa0000004: {
        // ConsoleFEDataBlock: the console code page.
        if (blockSize >= 12) {
          detail = `Code page: ${new DataView(buf.buffer, buf.byteOffset + pos, 12).getUint32(8, true)}`;
        }
        break;
      }
      default:
        break;
    }

    blocks.push({ name, signature, size: blockSize, offset: pos, detail });
    pos += blockSize;
  }

  return {
    linkFlags,
    fileAttributes,
    targetCreated,
    targetAccessed,
    targetModified,
    fileSize,
    items,
    driveType,
    volumeSerialNumber,
    volumeLabel,
    localPath,
    networkPath,
    commonPath,
    description,
    relativePath,
    workingDirectory,
    arguments: args,
    iconLocation,
    blocks,
    machineId,
    machineMacAddress,
    trackerCreatedOn,
  };
}

export const lnk: Parser = {
  id: 'lnk',
  name: 'Shortcut',
  ezTool: 'LECmd',
  extensions: ['.lnk'],
  columns,
  sniff(head: Uint8Array, _filename: string): boolean {
    if (head.length < 20) return false;
    if (head[0] !== 0x4c || head[1] !== 0x00 || head[2] !== 0x00 || head[3] !== 0x00) return false;
    return guid(head.subarray(4, 20)).toLowerCase() === LinkCLSID;
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    // A shortcut is small; reading it whole keeps the shell item walk simple.
    const buf = await reader.bytes(0, reader.size);
    const { GUID_NAMES } = await import('./lnk/guids');
    const f = parseLnk(buf, GUID_NAMES, ctx.warn);
    if (!f) return;

    const mft = targetMft(f);
    const last = f.items[f.items.length - 1];

    const common = {
      relativePath: f.relativePath,
      workingDirectory: f.workingDirectory,
      arguments: f.arguments,
      iconLocation: f.iconLocation,
      description: f.description,
      fileAttributes: fileAttributeNames(f),
      headerFlags: headerFlagNames(f),
      driveType: f.driveType,
      volumeSerialNumber: f.volumeSerialNumber,
      volumeLabel: f.volumeLabel,
      localPath: f.localPath,
      networkPath: f.networkPath,
      commonPath: f.commonPath,
      targetIdAbsolutePath: f.items.length > 0 ? absolutePath(f.items) : null,
      machineId: f.machineId,
      machineMacAddress: f.machineMacAddress,
      machineMacVendor: await macVendor(f.machineMacAddress),
      trackerCreatedOn: f.trackerCreatedOn,
      extraBlocksPresent: f.blocks.length > 0 ? f.blocks.map((b) => b.name).join(', ') : null,
      sourceFile: reader.name,
    };

    yield {
      ...common,
      entryType: 'Target',
      path:
        (f.localPath ?? '') + (f.commonPath ?? '') ||
        f.networkPath ||
        (f.items.length > 0 ? absolutePath(f.items) : null),
      itemKind: 'Shortcut',
      shortName: null,
      targetCreated: f.targetCreated,
      targetModified: f.targetModified,
      targetAccessed: f.targetAccessed,
      fileSize: f.fileSize,
      mftEntry: mft.entry,
      mftSequence: mft.sequence,
      fileSystemHint: mft.entry !== null ? (last?.fileSystemHint ?? null) : null,
      offset: 0,
    };

    for (const item of f.items) {
      yield {
        ...common,
        entryType: 'Shell Item',
        path: item.value,
        itemKind: item.friendlyName,
        shortName: item.shortName,
        targetCreated: item.created,
        targetModified: item.modified,
        targetAccessed: item.accessed,
        fileSize: item.fileSize,
        mftEntry: item.mftEntry,
        mftSequence: item.mftSequence,
        fileSystemHint: item.fileSystemHint,
        offset: item.offset,
      };
    }

    for (const block of f.blocks) {
      yield {
        ...common,
        entryType: 'Extra Block',
        path: block.detail,
        itemKind: block.name,
        shortName: null,
        targetCreated: block.signature === 0xa0000003 ? f.trackerCreatedOn : null,
        targetModified: null,
        targetAccessed: null,
        fileSize: block.size,
        mftEntry: null,
        mftSequence: null,
        fileSystemHint: null,
        offset: block.offset,
      };
    }
  },
};
