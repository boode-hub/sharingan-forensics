/**
 * Jump lists: the recent and pinned items Windows keeps per application.
 *
 * Ported from Eric Zimmerman's JumpList library
 * (https://github.com/EricZimmerman/JumpList: AutomaticDestination.cs,
 * DestList.cs, DestListHeader.cs, DestListEntry.cs, CustomDestination.cs,
 * Entry.cs) and JLECmd's CSV output (https://github.com/EricZimmerman/JLECmd,
 * GetAutoCsvFormat, GetCustomCsvFormat, AutoCsvOut, CustomCsvOut).
 *
 * An automaticDestinations-ms file is a compound file holding a DestList
 * stream (which item, when, how often, on which machine) and one shortcut per
 * item in a stream named by its entry number in hex. A customDestinations-ms
 * file is shortcuts laid end to end, grouped into categories, each group
 * closed by a footer. Both are read with the same shortcut decoder as .lnk
 * files, so every column JLECmd takes from the shortcut means the same here.
 *
 * Shortcut streams the DestList does not mention are reported too, as JLECmd
 * does with --withDir, marked in Notes. The Source Created/Modified/Accessed
 * columns are the file's own timestamps on disk, which a browser is not
 * given; they are kept, empty, so exports line up with his.
 */
import type { Column, ColType, Ctx, Parser, Reader, Row, Table } from '../core/types';
import { filetime, guid } from '../core/binary';
import { isCfb, openCfb, type CfbEntry } from '../core/cfb';
import type { ShellItem } from '../core/shellitem';
import {
  fileAttributeNames,
  hasArguments,
  headerFlagNames,
  macFromDroid,
  parseLnk,
  targetMft,
  uuidV1Time,
  type LnkFile,
} from './lnk';

const spaced = (name: string) =>
  name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');

/** His CSV class's properties, in declaration order, which is his column order. */
function cols(spec: string, secondary: string[] = []): Column[] {
  return spec
    .trim()
    .split(/\s+/)
    .map((s) => {
      const [key, type = 'str'] = s.split(':');
      return { key, label: spaced(key), type: type as ColType, secondary: secondary.includes(key) || undefined };
    });
}

const SOURCE = 'SourceFile SourceCreated:date SourceModified:date SourceAccessed:date AppId AppIdDescription';
const LNK = `TargetCreated:date TargetModified:date TargetAccessed:date FileSize:num RelativePath
  WorkingDirectory FileAttributes HeaderFlags DriveType VolumeSerialNumber VolumeLabel LocalPath CommonPath
  TargetIDAbsolutePath TargetMFTEntryNumber TargetMFTSequenceNumber MachineID MachineMACAddress
  TrackerCreatedOn:date ExtraBlocksPresent Arguments`;
const UNKNOWABLE = ['SourceCreated', 'SourceModified', 'SourceAccessed'];

export const tables: Table[] = [
  {
    id: 'automatic',
    label: 'AutomaticDestinations',
    columns: cols(
      `${SOURCE} HasSps:bool DestListVersion:num LastUsedEntryNumber:num MRU:num EntryNumber
       CreationTime:date LastModified:date Hostname MacAddress Path InteractionCount:num PinStatus:bool
       FileBirthDroid FileDroid VolumeBirthDroid VolumeDroid ${LNK} Notes`,
      UNKNOWABLE,
    ),
  },
  {
    id: 'custom',
    label: 'CustomDestinations',
    columns: cols(`${SOURCE} EntryName ${LNK}`, UNKNOWABLE),
  },
];

type Warn = (offset: number, message: string) => void;
type GuidNames = Record<string, string>;

/** GuidMapping.GetDescriptionFromGuid. */
function folderName(g: string, names: GuidNames): string {
  const key = g.toLowerCase().replace(/[{}]/g, '');
  return names[key] ?? `Unmapped GUID: ${g}`;
}

interface DestListEntry {
  entryNumber: number;
  mruPosition: number;
  hostname: string;
  path: string;
  pinned: boolean;
  interactionCount: number;
  lastModified: Date | null;
  created: Date | null;
  macAddress: string;
  volumeDroid: string;
  fileDroid: string;
  volumeBirthDroid: string;
  fileBirthDroid: string;
  hasSps: boolean;
}

const ZERO_GUID = '00000000-0000-0000-0000-000000000000';

function destListEntry(
  b: Uint8Array,
  version: number,
  mruPosition: number,
  spsSize: number,
  names: GuidNames,
): DestListEntry {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const droid = (at: number) => guid(b.subarray(at, at + 16));
  const fileDroid = droid(24);

  // A hostname is ASCII, but some builds wrote it as UTF-16; a zero second
  // byte is how he tells them apart.
  const hostBytes = b.subarray(72, 88);
  const hostname = (
    b[73] === 0 ? new TextDecoder('utf-16le').decode(hostBytes) : String.fromCharCode(...hostBytes)
  ).split('\0')[0];

  const pathAt = version > 1 ? 128 : 112;
  const pathLen = Math.max(0, dv.getInt16(pathAt, true)) * 2;
  let path = new TextDecoder('utf-16le').decode(b.subarray(pathAt + 2, pathAt + 2 + pathLen));

  if (path.startsWith('knownfolder')) {
    const id = path.split('{').pop() as string;
    path = `${path} ==> ${folderName(id.slice(0, -1), names)}`;
  }
  if (path.startsWith('::')) {
    // Shell namespace paths: each {GUID} segment is named. His substring
    // drops the first and last character of the match, which are the braces
    // when there are braces.
    const re =
      /\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b|\(\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b\)|\{\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b\}/i;
    const segs = path.split('\\').map((seg) => {
      const m = re.exec(seg);
      return m ? folderName(m[0].slice(1, -1), names) : seg;
    });
    path = `${path} ==> ${segs.join('\\')}`;
  }

  // The file droid is a version 1 UUID: its node is the MAC address of the
  // machine that made it, and its time is when the target was first seen.
  const mac = macFromDroid(fileDroid) ?? '';
  const created = uuidV1Time(b.subarray(24, 40));
  const ft = dv.getBigUint64(100, true);

  return {
    entryNumber: dv.getInt32(88, true),
    mruPosition,
    hostname,
    path,
    pinned: dv.getInt32(108, true) !== -1,
    interactionCount: version > 1 ? dv.getInt32(116, true) : 0,
    lastModified: filetime(ft),
    created: created && created.getUTCFullYear() !== 1582 ? created : null,
    macAddress: mac === '00:00:00:00:00:00' ? '' : mac,
    volumeDroid: droid(8),
    fileDroid,
    volumeBirthDroid: droid(40),
    fileBirthDroid: droid(56),
    hasSps: spsSize > 0,
  };
}

/** DestList.cs: a 32-byte header, then entries until the stream ends. */
function destList(b: Uint8Array, names: GuidNames, warn: Warn) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const version = dv.getInt32(0, true);
  const count = dv.getInt32(4, true);
  const lastEntryNumber = dv.getInt32(16, true);
  const entries: DestListEntry[] = [];
  let at = 32;
  let mru = 0;
  while (at < b.length) {
    if (version === 1) {
      // Windows 7 and 8 declare how many entries there are.
      if (entries.length >= count) break;
      if (at + 114 > b.length) break;
      const size = 114 + dv.getInt16(at + 112, true) * 2;
      if (size < 114 || at + size > b.length) {
        warn(at, `DestList entry ${entries.length} runs past the end of the stream`);
        break;
      }
      entries.push(destListEntry(b.subarray(at, at + size), version, mru++, 0, names));
      at += size;
    } else {
      // Windows 10 entries carry a property store after the path, sized by
      // the four bytes that follow it.
      if (at + 130 > b.length) break;
      const size = 130 + dv.getInt16(at + 128, true) * 2;
      if (size < 130 || at + size + 4 > b.length) {
        warn(at, `DestList entry ${entries.length} runs past the end of the stream`);
        break;
      }
      const sps = dv.getInt32(at + size, true);
      if (sps < 0 || at + size + 4 + sps > b.length) {
        warn(at, `DestList entry ${entries.length} has a property store that runs past the end of the stream`);
        break;
      }
      entries.push(destListEntry(b.subarray(at, at + size + sps), version, mru++, sps, names));
      at += size + sps + 4;
    }
  }
  if (version === 1 && entries.length !== count) {
    warn(4, `DestList header says ${count} entries; ${entries.length} could be read`);
  }
  return { version, lastEntryNumber, entries };
}

/**
 * JLECmd's GetAbsolutePathFromTargetIDs: the values joined with a backslash,
 * untrimmed (LECmd's own version trims each value; this one does not).
 */
const targetPath = (items: ShellItem[]) => items.map((i) => i.value).join('\\');

/** The columns JLECmd takes from an entry's shortcut. */
function lnkFields(f: LnkFile | null) {
  if (!f) {
    return { DriveType: '(None)', FileSize: 0 };
  }
  const mft = targetMft(f);
  const tracker = f.blocks.some((b) => b.name === 'TrackerDataBaseBlock');
  return {
    TargetCreated: f.targetCreated,
    TargetModified: f.targetModified,
    TargetAccessed: f.targetAccessed,
    FileSize: f.fileSize,
    RelativePath: f.relativePath,
    WorkingDirectory: f.workingDirectory,
    FileAttributes: fileAttributeNames(f),
    HeaderFlags: headerFlagNames(f),
    DriveType: f.driveType,
    VolumeSerialNumber: f.volumeSerialNumber,
    VolumeLabel: f.volumeLabel,
    LocalPath: f.localPath,
    CommonPath: f.commonPath,
    TargetMFTEntryNumber: mft.entry === null ? null : `0x${mft.entry.toString(16).toUpperCase()}`,
    TargetMFTSequenceNumber: mft.sequence === null ? null : `0x${mft.sequence.toString(16).toUpperCase()}`,
    MachineID: tracker ? f.machineId : null,
    MachineMACAddress: tracker ? f.machineMacAddress : null,
    TrackerCreatedOn: tracker ? f.trackerCreatedOn : null,
    ExtraBlocksPresent: f.blocks.map((b) => b.name).join(', '),
    Arguments: hasArguments(f) ? (f.arguments ?? '') : '',
  };
}

function appIdOf(name: string, ids: Record<string, string>) {
  const appId = name.split(/[\\/]/).pop()?.split('.')[0] ?? '';
  return { AppId: appId, AppIdDescription: ids[appId.toLowerCase()] ?? null };
}

async function* automatic(buf: Uint8Array, reader: Reader, ctx: Ctx, names: GuidNames): AsyncGenerator<Row> {
  const cfb = openCfb(buf, ctx.warn);
  if (!cfb) return;
  const { APP_IDS } = await import('./jumplist/appids');
  const source = { SourceFile: reader.name, ...appIdOf(reader.name, APP_IDS) };
  const byName = (n: string): CfbEntry | undefined =>
    cfb.entries.find((e) => e.name.toLowerCase() === n.toLowerCase());

  const readLnk = (entry: CfbEntry): LnkFile | null => {
    const bytes = cfb.read(entry);
    if (!bytes) return null;
    return parseLnk(bytes, names, (off, msg) => ctx.warn(off, `stream ${entry.name}: ${msg}`));
  };

  const destEntry = byName('DestList');
  const bytes = destEntry && destEntry.size > 0 ? cfb.read(destEntry) : null;
  const list = bytes && bytes.length >= 32 ? destList(bytes, names, ctx.warn) : null;
  if (!destEntry) ctx.warn(0, 'this jump list has no DestList stream, so only its shortcut streams can be read');
  else if (!list) ctx.warn(0, 'the DestList is empty: the application has no recent or pinned items in this jump list');

  const hasSps = list?.entries.some((e) => e.hasSps) ?? false;
  const header = {
    ...source,
    HasSps: hasSps,
    DestListVersion: list?.version ?? 0,
    LastUsedEntryNumber: list?.lastEntryNumber ?? 0,
  };

  const listed = new Set<string>();
  for (const e of list?.entries ?? []) {
    const name = e.entryNumber.toString(16);
    listed.add(name);
    const stream = byName(name);
    const f = stream ? readLnk(stream) : null;
    let target: string | null = null;
    if (f) {
      target = f.items.length > 0 ? targetPath(f.items) : '';
      if (target.length === 0) {
        target = f.networkPath !== null ? `${f.networkPath}\\${f.commonPath ?? ''}` : `${f.localPath ?? ''}\\${f.commonPath ?? ''}`;
      }
    }
    yield {
      table: 'automatic',
      ...header,
      MRU: e.mruPosition,
      EntryNumber: e.entryNumber.toString(16).toUpperCase(),
      CreationTime: e.created,
      LastModified: e.lastModified,
      Hostname: e.hostname,
      MacAddress: e.macAddress,
      Path: e.path,
      InteractionCount: e.interactionCount,
      PinStatus: e.pinned,
      FileBirthDroid: e.fileBirthDroid === ZERO_GUID ? '' : e.fileBirthDroid,
      FileDroid: e.fileDroid === ZERO_GUID ? '' : e.fileDroid,
      VolumeBirthDroid: e.volumeBirthDroid === ZERO_GUID ? '' : e.volumeBirthDroid,
      VolumeDroid: e.volumeDroid === ZERO_GUID ? '' : e.volumeDroid,
      ...lnkFields(f),
      TargetIDAbsolutePath: target,
      Notes: '',
    };
  }

  // Shortcut streams with no DestList entry: left behind when an item was
  // removed from the list but not from the file. His comparison of names is
  // case-sensitive against upper-case hex, which would also flag listed
  // entries from "a" upwards; this compares them as the numbers they are.
  for (const entry of cfb.entries) {
    if (entry.type !== 2 || /^(root entry|destlist|destlistpropertystore)$/i.test(entry.name)) continue;
    if (listed.has(entry.name.toLowerCase())) continue;
    const f = readLnk(entry);
    if (!f) continue;
    const target = f.items.length > 0 ? targetPath(f.items) : `${f.networkPath ?? ''}\\\\${f.commonPath ?? ''}`;
    yield {
      table: 'automatic',
      ...header,
      MRU: null,
      EntryNumber: entry.name,
      CreationTime: entry.created,
      LastModified: entry.modified,
      Hostname: '',
      MacAddress: '',
      Path: '',
      PinStatus: null,
      FileBirthDroid: '',
      FileDroid: '',
      VolumeBirthDroid: '',
      VolumeDroid: '',
      ...lnkFields(f),
      TargetIDAbsolutePath: target,
      Notes: 'Found in Directory, not DestList',
    };
  }
}

const FOOTER = [0xab, 0xfb, 0xbf, 0xba];
const LNK_HEADER = [
  0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x46,
];

function find(b: Uint8Array, needle: number[], from: number): number {
  outer: for (let i = from; i <= b.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (b[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

async function* custom(buf: Uint8Array, reader: Reader, ctx: Ctx, names: GuidNames): AsyncGenerator<Row> {
  if (buf.length <= 24) {
    ctx.warn(0, 'empty custom destinations jump list');
    return;
  }
  if (!FOOTER.every((b, i) => buf[buf.length - 4 + i] === b)) {
    ctx.warn(buf.length - 4, 'the file does not end with the custom destinations footer; reading what is there');
  }
  const { APP_IDS } = await import('./jumplist/appids');
  const source = { SourceFile: reader.name, ...appIdOf(reader.name, APP_IDS) };

  // Each category ends with the footer bytes; the file is cut at every one.
  let chunkStart = 0;
  for (let footer = find(buf, FOOTER, 0); footer !== -1; footer = find(buf, FOOTER, footer + 4)) {
    const chunk = buf.subarray(chunkStart, footer + 4);
    const base = chunkStart;
    chunkStart = footer + 4;
    if (chunk.length <= 30) continue;

    const dv = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    // A header type of 0 is a named category, such as "Frequent" or "Tasks".
    let entryName = '';
    if (dv.getInt32(12, true) === 0) {
      const len = dv.getInt16(16, true);
      entryName = new TextDecoder('utf-16le')
        .decode(chunk.subarray(18, Math.min(18 + len * 2, chunk.length)))
        .split('\0')[0];
    }

    const footerAt = find(chunk, FOOTER, 0);
    const offsets: number[] = [];
    for (let at = find(chunk, LNK_HEADER, 0); at !== -1; at = find(chunk, LNK_HEADER, at + 1)) offsets.push(at);
    for (let i = 0; i < offsets.length; i++) {
      const start = offsets[i];
      const end = i + 1 < offsets.length ? offsets[i + 1] : footerAt;
      if (end <= start) continue;
      const f = parseLnk(chunk.subarray(start, end), names, (off, msg) =>
        ctx.warn(base + start + off, `shortcut at 0x${(base + start).toString(16)}: ${msg}`),
      );
      if (!f) continue;
      yield {
        table: 'custom',
        ...source,
        EntryName: entryName,
        ...lnkFields(f),
        TargetIDAbsolutePath: f.items.length > 0 ? targetPath(f.items) : null,
      };
    }
  }
}

export const jumplist: Parser = {
  id: 'jumplist',
  name: 'Jump List',
  ezTool: 'JLECmd',
  extensions: ['.automaticdestinations-ms', '.customdestinations-ms'],
  columns: tables[0].columns,
  tables,
  // A compound file could be many things; one named as a jump list is one.
  sniff(head: Uint8Array, filename: string): boolean {
    return isCfb(head) && /automaticdestinations/i.test(filename);
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    // Jump lists are small; they are read whole.
    const buf = await reader.bytes(0, reader.size);
    const { GUID_NAMES } = await import('./lnk/guids');
    if (isCfb(buf)) yield* automatic(buf, reader, ctx, GUID_NAMES);
    else yield* custom(buf, reader, ctx, GUID_NAMES);
  },
};
