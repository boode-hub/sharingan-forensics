/**
 * Amcache.hve: what Windows recorded about programs and files it saw.
 *
 * Ported from Eric Zimmerman's AmcacheParser
 * (https://github.com/EricZimmerman/AmcacheParser): AmcacheNew.cs for the
 * Windows 10 and later layout (Root\InventoryApplicationFile and siblings),
 * AmcacheOld.cs for the Windows 8 layout (Root\File and Root\Programs), and
 * the column maps in Program.cs.
 *
 * He writes one CSV per kind of record, so this produces one table per CSV,
 * named as his files are. Column order is his: the explicit Index() calls in
 * Program.cs, with the properties he did not index placed where CsvHelper's
 * AutoMap puts them. That placement reproduces real AmcacheParser headers
 * (Usn falls between BinProductVersion and Language; InstallDateArpLastModified
 * between Publisher and InstallDate), which is what confirms it.
 *
 * Where his code would drop a whole entry because one value would not parse
 * (an int.Parse that throws inside the per-key try), the entry is kept with
 * that field empty and a warning, because a partly readable entry is still
 * evidence. Deleted keys that his Registry library attaches to their live
 * parent are reported too, as his are, and marked in a Deleted column he does
 * not have.
 */
import type { Column, ColType, Ctx, Parser, Reader, Row, Table } from '../core/types';
import { filetime, magic, unixtime } from '../core/binary';
import { openHive, type Hive, type HiveKey } from './registry/hive';

const spaced = (name: string) =>
  name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');

/** "Name Size:num" - his header names in his order, with a type where not a string. */
function cols(spec: string): Column[] {
  return [
    ...spec
      .trim()
      .split(/\s+/)
      .map((s) => {
        const [key, type = 'str'] = s.split(':');
        return { key, label: spaced(key), type: type as ColType };
      }),
    { key: 'Deleted', label: 'Deleted', type: 'bool' },
  ];
}

const FILE_NEW = cols(`ApplicationName ProgramId FileKeyLastWriteTimestamp:date SHA1 IsOsComponent:bool
  FullPath Name FileExtension LinkDate:date ProductName Size:num Version ProductVersion LongPathHash
  BinaryType IsPeFile:bool BinFileVersion BinProductVersion Usn:num Language:num Description OriginalFileName`);

// FileEntryOld: he indexes every column for unassociated entries but stops at
// LanguageID for associated ones, so ProductName, CompanyName and
// SwitchBackContext fall back to their declaration positions there.
const FILE_OLD_TAIL = `SizeOfImage:num PEHeaderHash PEHeaderChecksum:num BinProductVersion BinFileVersion
  LinkerVersion:num BinaryType:num IsLocal:num GuessProgramID:num Created:date LastModified:date
  LastModifiedStore:date LinkDate:date LanguageID:num`;

export const tables: Table[] = [
  { id: 'unassociated', label: 'UnassociatedFileEntries', columns: FILE_NEW },
  { id: 'associated', label: 'AssociatedFileEntries', columns: FILE_NEW },
  {
    id: 'programs',
    label: 'ProgramEntries',
    columns: cols(`ProgramId KeyLastWriteTimestamp:date Name Version Publisher InstallDateArpLastModified
      InstallDate:date InstallDateMsi:date InstallDateFromLinkFile OSVersionAtInstallTime BundleManifestPath
      HiddenArp:bool InboxModernApp:bool Language:num ManifestPath MsiPackageCode MsiProductCode
      PackageFullName ProgramInstanceId RegistryKeyPath RootDirPath Type Source StoreAppType
      UninstallString Manufacturer FileEntries:num`),
  },
  { id: 'shortcuts', label: 'ShortCuts', columns: cols('KeyName LnkName KeyLastWriteTimestamp:date') },
  {
    id: 'driverBinaries',
    label: 'DriverBinaries',
    columns: cols(`KeyName KeyLastWriteTimestamp:date DriverTimeStamp:date DriverLastWriteTime:date
      DriverName DriverInBox:bool DriverIsKernelMode:bool DriverSigned:bool DriverCheckSum:num
      DriverCompany DriverId DriverPackageStrongName DriverType DriverVersion ImageSize:num Inf Product
      ProductVersion Service WdfVersion`),
  },
  {
    id: 'deviceContainers',
    label: 'DeviceContainers',
    columns: cols(`KeyName KeyLastWriteTimestamp:date Categories DiscoveryMethod FriendlyName Icon
      IsActive:bool IsConnected:bool IsMachineContainer:bool IsNetworked:bool IsPaired:bool Manufacturer
      ModelId ModelName ModelNumber PrimaryCategory State`),
  },
  {
    id: 'driverPackages',
    label: 'DriverPackages',
    columns: cols(`KeyName KeyLastWriteTimestamp:date Date:date Class Directory DriverInBox:bool Hwids Inf
      Provider SubmissionId SYSFILE Version`),
  },
  {
    id: 'devicePnps',
    label: 'DevicePnps',
    columns: cols(`KeyName KeyLastWriteTimestamp:date BusReportedDescription Class ClassGuid Compid
      ContainerId Description DriverId DriverPackageStrongName DriverName DriverVerDate DriverVerVersion
      Enumerator HWID Inf InstallState Manufacturer MatchingId Model ParentId ProblemCode Provider Service
      Stackid`),
  },
  {
    id: 'oldUnassociated',
    label: 'UnassociatedFileEntries (Windows 8)',
    columns: cols(`ProgramName ProgramID VolumeID VolumeIDLastWriteTimestamp:date FileID
      FileIDLastWriteTimestamp:date SHA1 FullPath FileExtension MFTEntryNumber:num MFTSequenceNumber:num
      FileSize:num FileVersionString FileVersionNumber FileDescription ${FILE_OLD_TAIL} ProductName
      CompanyName SwitchBackContext`),
  },
  {
    id: 'oldAssociated',
    label: 'AssociatedFileEntries (Windows 8)',
    columns: cols(`ProgramName ProgramID ProductName VolumeID CompanyName VolumeIDLastWriteTimestamp:date
      FileID FileIDLastWriteTimestamp:date SHA1 FullPath FileExtension MFTEntryNumber:num
      MFTSequenceNumber:num FileSize:num FileVersionString FileVersionNumber FileDescription
      SwitchBackContext ${FILE_OLD_TAIL}`),
  },
  {
    id: 'oldPrograms',
    label: 'ProgramEntries (Windows 8)',
    columns: cols(`ProgramID LastWriteTimestamp:date ProgramName_0 ProgramVersion_1 VendorName_2
      InstallDateEpoch_a:date UnknownGuid_10 InstallDateEpoch_b:date LanguageCode_3 UnknownGuid_12
      InstallSource_6 UninstallGuid_11 UninstallRegistryKey_7 UnknownDword_5:num UnknownDword_13:num
      PathsList_d UnknownDword_14:num UnknownDword_15:num UnknownBytes_16 UnknownQWord_17:num
      UnknownDword_18:num UninstallGuid_f FilesLinks FileEntries:num`),
  },
];

/**
 * DateTime.Parse with the invariant culture, which is how he reads the dates
 * Windows stores as text ("07/13/2009 23:32:37", month first). He then takes
 * the result as UTC without converting it.
 */
export function invariantDate(s: string): Date | null {
  let m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?\s*(AM|PM)?)?$/i.exec(
    s.trim(),
  );
  let y: number, mo: number, d: number, h: number, mi: number, sec: number, frac: string;
  if (m) {
    [mo, d, y, h, mi, sec] = [m[1], m[2], m[3], m[4] ?? '0', m[5] ?? '0', m[6] ?? '0'].map(Number);
    frac = m[7] ?? '';
    const ampm = m[8]?.toUpperCase();
    if (ampm && (h < 1 || h > 12)) return null;
    if (ampm === 'PM' && h < 12) h += 12;
    if (ampm === 'AM' && h === 12) h = 0;
  } else {
    m = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?)?(Z|[+-]\d{2}:?\d{2})?$/.exec(
      s.trim(),
    );
    if (!m) return null;
    [y, mo, d, h, mi, sec] = [m[1], m[2], m[3], m[4] ?? '0', m[5] ?? '0', m[6] ?? '0'].map(Number);
    frac = m[7] ?? '';
  }
  const ms = Number(frac.padEnd(3, '0').slice(0, 3));
  const t = Date.UTC(y, mo - 1, d, h, mi, sec, ms);
  const date = new Date(t);
  // Date.UTC rolls 02/30 into March; DateTime.Parse rejects it.
  if (date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d || h > 23 || mi > 59 || sec > 59) return null;
  if (y < 1) return null;
  return date;
}

/** Path.GetExtension on Windows: from the last dot after the last separator. */
function extension(path: string): string {
  for (let i = path.length - 1; i >= 0; i--) {
    const c = path[i];
    if (c === '.') return i === path.length - 1 ? '' : path.slice(i);
    if (c === '\\' || c === '/') break;
  }
  return '';
}

/** FileId and SHA1 values carry four leading zeros before the hash. */
const sha1 = (v: string) => (v.length > 4 ? v.slice(4).toLowerCase() : '');

type Warn = (key: HiveKey, message: string) => void;

/** Parses a decimal the way int.Parse would, or warns and gives the fallback. */
function int(v: string, key: HiveKey, field: string, warn: Warn, fallback: number | null = 0): number | null {
  if (/^\s*[-+]?\d+\s*$/.test(v)) return Number(v);
  warn(key, `${field} is not a number ("${v}"); left empty`);
  return fallback;
}

function date(v: string, key: HiveKey, field: string, warn: Warn): Date | null {
  if (v.length === 0) return null;
  const d = invariantDate(v);
  if (!d) warn(key, `${field} is not a date ("${v}"); left empty`);
  return d;
}

/** Warns once per value name he does not know, as he logs them, without flooding. */
function unknownValues(ctx: Ctx) {
  const seen = new Set<string>();
  return (where: string, key: HiveKey, name: string) => {
    if (seen.has(`${where}\0${name}`)) return;
    seen.add(`${where}\0${name}`);
    ctx.warn(key.rel + 4096, `unknown value name in ${where}: ${name} (first seen at key ${key.name}); it is not in any column`);
  };
}

async function* parseNew(hive: Hive, fileKey: HiveKey, ctx: Ctx): AsyncGenerator<Row> {
  const warn: Warn = (key, message) => ctx.warn(key.rel + 4096, `${key.name}: ${message}`);
  const unknown = unknownValues(ctx);
  const root = hive.key(hive.root, 'Root');

  // Programs first: a file entry is associated with a program by ProgramId.
  const programs: Row[] = [];
  const programFiles = new Map<string, Row[]>();
  const programsKey = root && hive.key(root, 'InventoryApplication');
  if (!programsKey) ctx.warn(0, 'Hive does not contain a Root\\InventoryApplication key');
  for (const key of programsKey ? hive.subkeys(programsKey) : []) {
    if (ctx.signal?.aborted) return;
    const r: Row = {
      table: 'programs',
      ProgramId: '',
      KeyLastWriteTimestamp: key.lastWrite,
      Name: '',
      Version: '',
      Publisher: '',
      InstallDateArpLastModified: '',
      InstallDate: null,
      InstallDateMsi: null,
      InstallDateFromLinkFile: '',
      OSVersionAtInstallTime: '',
      BundleManifestPath: '',
      HiddenArp: false,
      InboxModernApp: false,
      Language: 0,
      ManifestPath: '',
      MsiPackageCode: '',
      MsiProductCode: '',
      PackageFullName: '',
      ProgramInstanceId: '',
      RegistryKeyPath: '',
      RootDirPath: '',
      Type: '',
      Source: '',
      StoreAppType: '',
      UninstallString: '',
      Manufacturer: '',
      FileEntries: 0,
      Deleted: key.deleted,
    };
    for (const v of await hive.values(key)) {
      const d = v.data;
      switch (v.name) {
        case 'BundleManifestPath':
        case 'ManifestPath':
        case 'MsiPackageCode':
        case 'MsiProductCode':
        case 'Name':
        case 'OSVersionAtInstallTime':
        case 'PackageFullName':
        case 'ProgramId':
        case 'ProgramInstanceId':
        case 'Publisher':
        case 'RegistryKeyPath':
        case 'RootDirPath':
        case 'Source':
        case 'StoreAppType':
        case 'Type':
        case 'UninstallString':
        case 'Version':
        case 'InstallDateArpLastModified':
        case 'InstallDateFromLinkFile':
        case 'Manufacturer':
          r[v.name] = d;
          break;
        case 'HiddenArp':
        case 'InboxModernApp':
          r[v.name] = d === '1';
          break;
        case 'InstallDate':
        case 'InstallDateMsi':
          r[v.name] = date(d, key, v.name, warn);
          break;
        case 'Language':
          r.Language = d.length === 0 ? 0 : int(d, key, v.name, warn);
          break;
        // Values he knows and deliberately leaves out of the CSV.
        case 'DriverVerVersion':
        case 'BusReportedDescription':
        case 'HWID':
        case 'COMPID':
        case 'STACKID':
        case 'UpperClassFilters':
        case 'UpperFilters':
        case 'LowerFilters':
        case 'BinFileVersion':
        case 'SentDetailedInv':
        case 'ProductName':
        case 'Provider':
        case 'Inf':
        case '(default)':
        case 'MsiInstallDate':
        case 'UserSid':
          break;
        default:
          unknown('InventoryApplication', key, v.name);
      }
    }
    programs.push(r);
    // His FirstOrDefault: the first program with an id wins.
    if (!programFiles.has(r.ProgramId as string)) programFiles.set(r.ProgramId as string, []);
  }

  const firstProgram = new Map<string, Row>();
  for (const p of programs) if (!firstProgram.has(p.ProgramId as string)) firstProgram.set(p.ProgramId as string, p);

  for (const key of hive.subkeys(fileKey)) {
    if (ctx.signal?.aborted) return;
    const r: Row = {
      table: 'unassociated',
      ApplicationName: 'Unassociated',
      ProgramId: '',
      FileKeyLastWriteTimestamp: key.lastWrite,
      SHA1: '',
      IsOsComponent: false,
      FullPath: '',
      Name: '',
      FileExtension: '',
      LinkDate: null,
      ProductName: '',
      Size: 0,
      Version: '',
      ProductVersion: '',
      LongPathHash: '',
      BinaryType: '',
      IsPeFile: false,
      BinFileVersion: '',
      BinProductVersion: '',
      Usn: 0,
      Language: 0,
      Description: '',
      OriginalFileName: '',
      Deleted: key.deleted,
    };
    let linked = false;
    for (const v of await hive.values(key)) {
      const d = v.data;
      switch (v.name) {
        case 'BinaryType':
        case 'BinFileVersion':
        case 'BinProductVersion':
        case 'LongPathHash':
        case 'Name':
        case 'ProductName':
        case 'ProductVersion':
        case 'Version':
        case 'Description':
        case 'OriginalFileName':
          r[v.name] = d;
          break;
        case 'LowerCaseLongPath':
          r.FullPath = d;
          break;
        case 'FileId':
          r.SHA1 = sha1(d);
          break;
        case 'IsOsComponent':
        case 'IsPeFile':
          r[v.name] = d === '1';
          break;
        case 'Language':
          r.Language = int(d, key, v.name, warn);
          break;
        case 'LinkDate':
          r.LinkDate = date(d, key, v.name, warn);
          break;
        case 'ProgramId':
          r.ProgramId = d;
          linked = firstProgram.has(d);
          break;
        case 'Size': {
          // Older builds wrote it as a hex string, newer ones as a QWORD.
          const n = d.startsWith('0x') ? parseInt(d.slice(2), 16) : Number(d);
          r.Size = Number.isFinite(n) && d.length > 0 ? n : 0;
          break;
        }
        case 'Usn':
          r.Usn = int(d, key, v.name, warn);
          break;
        case 'Publisher':
          // He reads it, then leaves it out of the CSV map.
          break;
        case 'BusReportedDescription':
        case 'FileSize':
        case 'Model':
        case 'Manufacturer':
        case 'ParentId':
        case 'MatchingID':
        case 'ClassGuid':
        case 'DriverName':
        case 'Enumerator':
        case 'Service':
        case 'DeviceState':
        case 'InstallState':
        case 'DriverVerVersion':
        case 'DriverPackageStrongName':
        case 'DriverVerDate':
        case 'AppxPackageRelativeId':
        case 'AppxPackageFullName':
        case 'ContainerId':
        case 'HiddenArp':
        case 'Inf':
        case 'LowerFilters':
        case 'ProblemCode':
        case 'LocationPaths':
        case 'Provider':
        case 'Class':
          break;
        default:
          if (!v.deleted) unknown('InventoryApplicationFile', key, v.name);
      }
    }
    r.FileExtension = extension(r.FullPath as string);
    if (linked) {
      const program = firstProgram.get(r.ProgramId as string) as Row;
      r.table = 'associated';
      r.ApplicationName = program.Name;
      (programFiles.get(r.ProgramId as string) as Row[]).push(r);
      program.FileEntries = (program.FileEntries as number) + 1;
    } else {
      yield r;
    }
  }

  // His associated CSV walks the programs and writes each one's files.
  for (const p of programs) {
    if (firstProgram.get(p.ProgramId as string) !== p) continue;
    yield* programFiles.get(p.ProgramId as string) ?? [];
  }
  yield* programs;

  if (!root) return;

  const shortcuts = hive.key(root, 'InventoryApplicationShortcut');
  for (const key of shortcuts ? hive.subkeys(shortcuts) : []) {
    const values = await hive.values(key);
    yield {
      table: 'shortcuts',
      KeyName: key.name,
      LnkName: values[0]?.data ?? '',
      KeyLastWriteTimestamp: key.lastWrite,
      Deleted: key.deleted,
    };
  }

  yield* simple(hive, root, 'InventoryDeviceContainer', 'deviceContainers', ctx, {
    strings: 'Categories DiscoveryMethod FriendlyName Icon Manufacturer ModelId ModelName ModelNumber PrimaryCategory State',
    flags: 'IsActive IsConnected IsMachineContainer IsNetworked IsPaired',
    ignored: '(default) Model BusReportedDescription Version LowerClassFilters ManifestPath UpperClassFilters',
  });

  yield* simple(hive, root, 'InventoryDevicePnp', 'devicePnps', ctx, {
    strings: `BusReportedDescription Class ClassGuid COMPID=Compid ContainerId Description DriverId
      DriverName DriverPackageStrongName DriverVerDate DriverVerVersion Enumerator HWID Inf InstallState
      Manufacturer MatchingID=MatchingId Model ParentId ProblemCode Provider Service STACKID=Stackid`,
    // DeviceState he reads and then leaves out of the CSV.
    ignored: `DeviceState LowerClassFilters LowerFilters UpperClassFilters UpperFilters ExtendedInfs DeviceInterfaceClasses
      (default) DeviceExtDriversFlightIds InstallDate FirstInstallDate DeviceDriverFlightId LocationPaths`,
  });

  yield* simple(hive, root, 'InventoryDriverBinary', 'driverBinaries', ctx, {
    strings: 'DriverCompany DriverName DriverPackageStrongName DriverType DriverVersion Inf Product ProductVersion Service WdfVersion',
    flags: 'DriverInBox DriverIsKernelMode DriverSigned',
    numbers: 'DriverCheckSum ImageSize',
    dates: 'DriverLastWriteTime',
    ignored: '(default) COMPID HWID',
    special(r, name, d, key) {
      if (name === 'DriverId') {
        r.DriverId = d.slice(4); // the same four-zero prefix as FileId
        return true;
      }
      if (name === 'DriverTimeStamp') {
        // Seconds since 1970, and 0 when the image has none.
        const s = int(d, key, name, warn);
        r.DriverTimeStamp = s && s > 0 ? unixtime(s) : null;
        return true;
      }
      return false;
    },
  });

  yield* simple(hive, root, 'InventoryDriverPackage', 'driverPackages', ctx, {
    strings: 'Class Directory Hwids Inf Provider SubmissionId SYSFILE Version',
    flags: 'DriverInBox',
    dates: 'Date',
    // ClassGuid he reads and then leaves out of the CSV.
    ignored: 'ClassGuid LowerFilters FlightIds RecoveryIds IsActive Language',
  });
}

interface SimpleSpec {
  /** Value names copied as text; "Value=Column" where his property is named differently. */
  strings: string;
  /** Values that are true when they read "1". */
  flags?: string;
  numbers?: string;
  dates?: string;
  /** Values he knows about and does not report. */
  ignored: string;
  special?: (r: Row, name: string, data: string, key: HiveKey) => boolean;
}

/**
 * The device and driver keys: one row per subkey, every value either copied,
 * read as a flag, a number or a date, or deliberately skipped.
 */
async function* simple(
  hive: Hive,
  root: HiveKey,
  keyName: string,
  table: string,
  ctx: Ctx,
  spec: SimpleSpec,
): AsyncGenerator<Row> {
  const parent = hive.key(root, keyName);
  if (!parent) return;
  const warn: Warn = (key, message) => ctx.warn(key.rel + 4096, `${key.name}: ${message}`);
  const unknown = unknownValues(ctx);
  const words = (s = '') => s.trim().split(/\s+/).filter(Boolean);
  const strings = new Map(words(spec.strings).map((w) => [w.split('=')[0], w.split('=')[1] ?? w]));
  const flags = new Set(words(spec.flags));
  const numbers = new Set(words(spec.numbers));
  const dates = new Set(words(spec.dates));
  const ignored = new Set(words(spec.ignored));
  const columns = (tables.find((t) => t.id === table) as Table).columns;

  for (const key of hive.subkeys(parent)) {
    if (ctx.signal?.aborted) return;
    const r: Row = { table };
    for (const c of columns) {
      r[c.key] = c.type === 'bool' ? false : c.type === 'num' ? 0 : c.type === 'date' ? null : '';
    }
    r.KeyName = key.name;
    r.KeyLastWriteTimestamp = key.lastWrite;
    r.Deleted = key.deleted;
    for (const v of await hive.values(key)) {
      const d = v.data;
      if (spec.special?.(r, v.name, d, key)) continue;
      if (strings.has(v.name)) r[strings.get(v.name) as string] = d;
      else if (flags.has(v.name)) r[v.name] = d === '1';
      else if (numbers.has(v.name)) r[v.name] = int(d, key, v.name, warn);
      else if (dates.has(v.name)) r[v.name] = date(d, key, v.name, warn);
      else if (!ignored.has(v.name)) unknown(keyName, key, v.name);
    }
    yield r;
  }
}

/** Value names in the Windows 8 File key are hex numbers. */
const OLD_FILE_VALUES: Record<number, string> = {
  0x0: 'ProductName',
  0x1: 'CompanyName',
  0x2: 'FileVersionNumber',
  0x3: 'LanguageID',
  0x4: 'SwitchBackContext',
  0x5: 'FileVersionString',
  0x6: 'FileSize',
  0x7: 'SizeOfImage',
  0x8: 'PEHeaderHash',
  0x9: 'PEHeaderChecksum',
  0xa: 'BinProductVersion',
  0xb: 'BinFileVersion',
  0xc: 'FileDescription',
  0xd: 'LinkerVersion',
  0xf: 'LinkDate',
  0x10: 'BinaryType',
  0x11: 'LastModified',
  0x12: 'Created',
  0x15: 'FullPath',
  0x16: 'IsLocal',
  0x17: 'LastModifiedStore',
  0x100: 'ProgramID',
  0x101: 'SHA1',
  0x106: 'GuessProgramID',
};

/**
 * His MFT numbers from a File subkey name, quirks included: the name is padded
 * to eight hex digits, the first four are the sequence number with trailing
 * zeros trimmed, and the rest is the entry number.
 */
function mftFromKey(name: string): { entry: number; sequence: number } {
  const temp = name.padStart(8, '0');
  const seq = temp.slice(0, 4).replace(/0+$/, '') || '0';
  return { sequence: parseInt(seq, 16) || 0, entry: parseInt(temp.slice(4), 16) || 0 };
}

const fileTimeOf = (d: string): Date | null => (/^\d+$/.test(d) ? filetime(BigInt(d)) : null);

async function* parseOld(hive: Hive, ctx: Ctx): AsyncGenerator<Row> {
  const warn: Warn = (key, message) => ctx.warn(key.rel + 4096, `${key.name}: ${message}`);
  const unknown = unknownValues(ctx);
  const fileKey = hive.key(hive.root, 'Root\\File');
  const programsKey = hive.key(hive.root, 'Root\\Programs');
  if (!fileKey || !programsKey) {
    ctx.warn(
      0,
      'Hive does not contain a File and/or Programs key (nor Root\\InventoryApplicationFile), so it is not an Amcache hive this can read',
    );
    return;
  }

  const programs: Row[] = [];
  for (const key of hive.subkeys(programsKey)) {
    if (ctx.signal?.aborted) return;
    const r: Row = {
      table: 'oldPrograms',
      ProgramID: key.name,
      LastWriteTimestamp: key.lastWrite,
      ProgramName_0: '',
      ProgramVersion_1: '',
      VendorName_2: '',
      InstallDateEpoch_a: null,
      UnknownGuid_10: '',
      InstallDateEpoch_b: null,
      LanguageCode_3: '',
      UnknownGuid_12: '',
      InstallSource_6: '',
      UninstallGuid_11: '',
      UninstallRegistryKey_7: '',
      UnknownDword_5: 0,
      UnknownDword_13: 0,
      PathsList_d: '',
      UnknownDword_14: 0,
      UnknownDword_15: 0,
      UnknownBytes_16: '',
      UnknownQWord_17: 0,
      UnknownDword_18: 0,
      UninstallGuid_f: '',
      FilesLinks: '',
      FileEntries: 0,
      Deleted: key.deleted,
    };
    for (const v of await hive.values(key)) {
      const d = v.data;
      switch (v.name) {
        case '0': r.ProgramName_0 = d; break;
        case '1': r.ProgramVersion_1 = d; break;
        case '2': r.VendorName_2 = d; break;
        case '3': r.LanguageCode_3 = d; break;
        case '5': r.UnknownDword_5 = int(d, key, v.name, warn); break;
        case '6': r.InstallSource_6 = d; break;
        case '7': r.UninstallRegistryKey_7 = d; break;
        case 'a':
        case 'b': {
          const s = int(d, key, v.name, warn);
          r[v.name === 'a' ? 'InstallDateEpoch_a' : 'InstallDateEpoch_b'] = s && s > 0 ? unixtime(s) : null;
          break;
        }
        case 'd': r.PathsList_d = d; break;
        case 'f': r.UninstallGuid_f = d; break;
        case '10': r.UnknownGuid_10 = d; break;
        case '11': r.UninstallGuid_11 = d; break;
        case '12': r.UnknownGuid_12 = d; break;
        // His switch stores 13, 14 and 15 all in UnknownDword_13, so the last
        // of them present wins and 14 and 15 always read 0. Kept as he has it.
        case '13':
        case '14':
        case '15':
          r.UnknownDword_13 = int(d, key, v.name, warn);
          break;
        case '16':
          r.UnknownBytes_16 = Array.from(v.bytes, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
          break;
        case '17': r.UnknownQWord_17 = int(d, key, v.name, warn); break;
        case '18': r.UnknownDword_18 = int(d, key, v.name, warn); break;
        // "volumeGuid@fileId" pairs. His CSV prints the parsed list as the
        // type name once per pair; the pairs themselves are what it held.
        case 'Files': r.FilesLinks = d; break;
        default:
          unknown('Programs', key, v.name);
      }
    }
    programs.push(r);
  }
  const byId = new Map<string, Row>();
  for (const p of programs) if (!byId.has(p.ProgramID as string)) byId.set(p.ProgramID as string, p);
  const programFiles = new Map<Row, Row[]>();

  for (const volume of hive.subkeys(fileKey)) {
    for (const key of hive.subkeys(volume)) {
      if (ctx.signal?.aborted) return;
      const { entry, sequence } = mftFromKey(key.name);
      const r: Row = {
        table: 'oldUnassociated',
        ProgramName: 'Unassociated',
        ProgramID: '',
        ProductName: '',
        VolumeID: volume.name,
        CompanyName: '',
        VolumeIDLastWriteTimestamp: volume.lastWrite,
        FileID: key.name,
        FileIDLastWriteTimestamp: key.lastWrite,
        SHA1: '',
        FullPath: '',
        FileExtension: '',
        MFTEntryNumber: entry,
        MFTSequenceNumber: sequence,
        FileSize: null,
        FileVersionString: '',
        FileVersionNumber: '',
        FileDescription: '',
        SwitchBackContext: '',
        SizeOfImage: null,
        PEHeaderHash: '',
        PEHeaderChecksum: null,
        BinProductVersion: '0',
        BinFileVersion: '0',
        LinkerVersion: 0,
        BinaryType: 0,
        IsLocal: 0,
        GuessProgramID: 0,
        Created: null,
        LastModified: null,
        LastModifiedStore: null,
        LinkDate: null,
        LanguageID: null,
        Deleted: key.deleted,
      };
      for (const v of await hive.values(key)) {
        const d = v.data;
        const field = /^[0-9a-f]+$/i.test(v.name) ? OLD_FILE_VALUES[parseInt(v.name, 16)] : undefined;
        switch (field) {
          case 'ProductName':
          case 'CompanyName':
          case 'FileVersionNumber':
          case 'SwitchBackContext':
          case 'FileVersionString':
          case 'PEHeaderHash':
          case 'FileDescription':
          case 'FullPath':
          case 'ProgramID':
          // Kept exact: both are 64-bit and can pass what a double holds.
          case 'BinProductVersion':
          case 'BinFileVersion':
            r[field] = d;
            break;
          case 'SHA1':
            r.SHA1 = sha1(d);
            break;
          case 'LanguageID':
          case 'FileSize':
          case 'SizeOfImage':
          case 'PEHeaderChecksum':
            r[field] = int(d, key, field, warn, null);
            break;
          case 'LinkerVersion':
          case 'BinaryType':
          case 'IsLocal':
          case 'GuessProgramID':
            r[field] = int(d, key, field, warn);
            break;
          case 'LinkDate': {
            const s = int(d, key, field, warn, null);
            r.LinkDate = s ? unixtime(s) : null;
            break;
          }
          case 'LastModified':
          case 'Created':
          case 'LastModifiedStore':
            r[field] = fileTimeOf(d);
            break;
          default:
            unknown('File', key, v.name);
        }
      }
      // He skips entries with no path.
      if ((r.FullPath as string).length === 0) continue;
      r.FileExtension = extension(r.FullPath as string);
      const program = byId.get(r.ProgramID as string);
      if (program) {
        r.table = 'oldAssociated';
        r.ProgramName = program.ProgramName_0;
        if (!programFiles.has(program)) programFiles.set(program, []);
        (programFiles.get(program) as Row[]).push(r);
        program.FileEntries = (program.FileEntries as number) + 1;
      } else {
        yield r;
      }
    }
  }

  for (const p of programs) yield* programFiles.get(p) ?? [];
  yield* programs;
}

/** The regf header keeps the tail of the hive's own path at offset 48. */
function embeddedName(head: Uint8Array): string {
  if (head.length < 112) return '';
  return new TextDecoder('utf-16le').decode(head.subarray(48, 112)).split('\0')[0];
}

export const amcache: Parser = {
  id: 'amcache',
  name: 'Amcache',
  ezTool: 'AmcacheParser',
  extensions: ['.hve'],
  columns: FILE_NEW,
  tables,
  // An Amcache.hve is a registry hive, but what an analyst dropping one wants
  // is what AmcacheParser gives, so it is recognised by its name - the file's,
  // or the one the hive records for itself - ahead of the plain hive view.
  sniff(head: Uint8Array, filename: string): boolean {
    return magic(head, 'regf', 0) && /amcache/i.test(`${filename} ${embeddedName(head)}`);
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const hive = await openHive(reader, ctx);
    if (!hive) return;
    const files = hive.key(hive.root, 'Root\\InventoryApplicationFile');
    if (files) yield* parseNew(hive, files, ctx);
    else yield* parseOld(hive, ctx);
  },
};
