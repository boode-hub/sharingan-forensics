/**
 * SRUM, the System Resource Usage Monitor (SRUDB.dat): per-application
 * network use, connections, resource use, push notifications, energy use and
 * app timeline data, kept for about 30 days.
 *
 * Ported from Eric Zimmerman's Srum library and SrumECmd
 * (https://github.com/EricZimmerman/Srum: SrumData/Srum.cs, SrumECmd/Program.cs).
 * He reads the database through esent.dll; this reads it through src/core/ese.ts,
 * which returns the bytes esent returns (checked cell for cell against esent on
 * a real SRUDB.dat). The SOFTWARE hive, when opened with it (his -r), supplies
 * user names for SIDs and Wi-Fi network names for profile ids.
 *
 * Where his tool abandons a table at a row it cannot read (a null column, an
 * application or user id missing from the id map), this keeps the row with
 * those fields empty and says so.
 */
import type { Column, ColType, Ctx, Parser, Reader, Row, Table } from '../core/types';
import { filetime } from '../core/binary';
import { oaDate, openEse, type Ese, type EseTable } from '../core/ese';
import { openHive } from './registry/hive';
import { INTERFACE_TYPES, SID_PREFIXES, SID_SUFFIXES, SID_TYPES } from './srum/names';

const cols = (spec: string): Column[] =>
  spec
    .trim()
    .split(/\s+/)
    .map((s) => {
      const [key, type = 'str'] = s.split(':');
      return { key, label: key.replace(/([a-z])([A-Z])/g, '$1 $2'), type: type as ColType };
    });

// Each of his output classes, automapped in declaration order.
const WHO = 'ExeInfo ExeInfoDescription ExeTimestamp:date SidType Sid UserName';
export const tables: Table[] = [
  {
    id: 'appResourceUseInfo',
    label: 'AppResourceUseInfo',
    columns: cols(`Id:num Timestamp:date ${WHO} UserId:num AppId:num BackgroundBytesRead:num BackgroundBytesWritten:num
      BackgroundContextSwitches:num BackgroundCycleTime:num BackgroundNumberOfFlushes:num BackgroundNumReadOperations:num
      BackgroundNumWriteOperations:num FaceTime:num ForegroundBytesRead:num ForegroundBytesWritten:num
      ForegroundContextSwitches:num ForegroundCycleTime:num ForegroundNumberOfFlushes:num ForegroundNumReadOperations:num
      ForegroundNumWriteOperations:num`),
  },
  {
    id: 'networkUsages',
    label: 'NetworkUsages',
    columns: cols(`Id:num Timestamp:date ${WHO} UserId:num AppId:num BytesReceived:num BytesSent:num InterfaceLuid:num
      InterfaceType L2ProfileFlags:num L2ProfileId:num ProfileName`),
  },
  {
    id: 'networkConnections',
    label: 'NetworkConnections',
    columns: cols(`Id:num Timestamp:date ${WHO} UserId:num AppId:num ConnectedTime:num ConnectStartTime:date
      InterfaceLuid:num InterfaceType L2ProfileFlags:num L2ProfileId:num ProfileName`),
  },
  {
    id: 'pushNotifications',
    label: 'PushNotifications',
    columns: cols(`Id:num Timestamp:date ${WHO} UserId:num AppId:num NetworkType:num NotificationType:num PayloadSize:num`),
  },
  {
    id: 'energyUsage',
    label: 'EnergyUsage',
    columns: cols(`Id:num Timestamp:date ${WHO} UserId:num AppId:num IsLt:bool ConfigurationHash:num EventTimestamp:date
      StateTransition:num ChargeLevel:num CycleCount:num DesignedCapacity:num FullChargedCapacity:num ActiveAcTime:num
      ActiveDcTime:num ActiveDischargeTime:num ActiveEnergy:num CsAcTime:num CsDcTime:num CsDischargeTime:num CsEnergy:num`),
  },
  {
    id: 'vfuprov',
    label: 'vfuprov',
    columns: cols(`Id:num Timestamp:date UserId:num AppId:num ${WHO} StartTime:date EndTime:date Flags:num Duration`),
  },
  {
    id: 'appTimelineProvider',
    label: 'AppTimelineProvider',
    columns: cols(`Id:num Timestamp:date ${WHO} UserId:num AppId:num EndTime:date DurationMs:num`),
  },
];

/** GetSidTypeFromSidString. */
export function sidType(sid: string): string {
  let t = SID_TYPES[sid] ?? 'UnknownOrUserSid';
  if (t === 'UnknownOrUserSid') {
    for (const [p, name] of SID_PREFIXES) if (sid.startsWith(p)) t = name;
    for (const [p, s, name] of SID_SUFFIXES) if (sid.startsWith(p) && sid.endsWith(s)) t = name;
  }
  return t;
}

/** Srum's ConvertHexStringToSidString: sub-authorities read to the end of the blob. */
function sidString(b: Uint8Array | undefined): string {
  if (!b || b.length <= 8) return '';
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let sid = `S-${b[0]}-${dv.getInt32(4, false)}`;
  for (let i = 8; i < b.length; i += 4) {
    if (i + 4 > b.length) throw new Error(`SID blob of ${b.length} bytes ends inside a sub-authority`);
    sid += `-${dv.getUint32(i, true)}`;
  }
  return sid;
}

interface AppInfo {
  exeInfo: string;
  exeInfoDescription: string | null;
  timestamp: Date | null;
}

/** His AppInfo: a "!!name!...!yyyy/MM/dd:HH:mm:ss!unknown!description" entry split into its parts. */
function appInfo(raw: string): AppInfo {
  const info: AppInfo = { exeInfo: raw, exeInfoDescription: null, timestamp: null };
  if (!raw.startsWith('!!')) return info;
  const segs = raw.slice(2).split('!');
  if (segs.length < 4) return info;
  let exe = segs[0] === '' ? '!' : segs[0];
  for (let i = 1; i < segs.length - 3; i++) exe += segs[i] === '' ? '!' : `!${segs[i]}`;
  info.exeInfo = exe;
  info.exeInfoDescription = segs[segs.length - 1];
  const m = /^(\d{4})\/(\d{2})\/(\d{2}):(\d{2}):(\d{2}):(\d{2})$/.exec(segs[segs.length - 3]);
  if (!m) throw new Error(`app timestamp "${segs[segs.length - 3]}" is not yyyy/MM/dd:HH:mm:ss`);
  info.timestamp = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  return info;
}

/** TimeSpan.ToString() of a count of 100 ns ticks: [-][d.]hh:mm:ss[.fffffff]. */
function timeSpan(ticks: bigint): string {
  const sign = ticks < 0n ? '-' : '';
  let t = ticks < 0n ? -ticks : ticks;
  const frac = t % 10000000n;
  t /= 10000000n;
  const d = t / 86400n;
  t %= 86400n;
  const p = (n: bigint) => n.toString().padStart(2, '0');
  return `${sign}${d ? `${d}.` : ''}${p(t / 3600n)}:${p((t % 3600n) / 60n)}:${p(t % 60n)}${frac ? `.${frac.toString().padStart(7, '0')}` : ''}`;
}

/** DateTimeOffset.FromFileTime, which rejects a negative time or one past 9999. */
function fromFileTime(ticks: bigint): Date | null {
  if (ticks < 0n || ticks > 2650467743999999999n) throw new Error(`file time ${ticks} is out of range`);
  return filetime(ticks);
}

/** Wi-Fi profile names and account names from the SOFTWARE hive, as his constructor reads them. */
async function fromSoftware(reader: Reader, ctx: Ctx) {
  const sidToUser = new Map<string, string>();
  const ssids = new Map<number, string>();
  const hive = await openHive(reader, { warn: (o, m) => ctx.warn(o, `${reader.name}: ${m}`), signal: ctx.signal });
  if (!hive) return { sidToUser, ssids };
  const live = (k: Parameters<typeof hive.subkeys>[0]) => hive.subkeys(k).filter((s) => !s.deleted);
  const value = async (k: Parameters<typeof hive.subkeys>[0], name: string) =>
    (await hive.values(k)).find((v) => !v.deleted && v.name === name);

  const profiles = hive.key(hive.root, 'Microsoft\\Windows NT\\CurrentVersion\\ProfileList');
  for (const k of profiles ? live(profiles) : []) {
    const v = await value(k, 'ProfileImagePath');
    if (v) sidToUser.set(k.name, v.data.split(/[\\/]/).pop() ?? v.data);
  }
  const interfaces = hive.key(hive.root, 'Microsoft\\WlanSvc\\Interfaces');
  for (const i of interfaces ? live(interfaces) : []) {
    const prof = live(i).find((k) => k.name === 'Profiles');
    for (const p of prof ? live(prof) : []) {
      const meta = live(p).find((k) => k.name === 'MetaData');
      if (!meta) continue;
      const hints = await value(meta, 'Channel Hints');
      const index = await value(p, 'ProfileIndex');
      if (!hints || !index || hints.bytes.length < 4) continue;
      const len = new DataView(hints.bytes.buffer, hints.bytes.byteOffset, hints.bytes.byteLength).getInt32(0, true);
      const name = Array.from(hints.bytes.subarray(4, 4 + len), (c) => (c < 0x80 ? String.fromCharCode(c) : '?')).join('');
      const id = parseInt(index.data, 10);
      if (ssids.has(id)) ctx.warn(0, `${reader.name}: profile index ${id} appears twice; his tool stops here, this keeps the first`);
      else ssids.set(id, name);
    }
  }
  return { sidToUser, ssids };
}

export const srum: Parser = {
  id: 'srum',
  name: 'SRUM (SRUDB.dat)',
  ezTool: 'SrumECmd',
  extensions: [],
  columns: tables[0].columns,
  tables,
  sniff: (head: Uint8Array, filename: string) =>
    head.length >= 8 && head[4] === 0xef && head[5] === 0xcd && head[6] === 0xab && head[7] === 0x89 && /srudb/i.test(filename),
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const ese = await openEse(reader, ctx.warn);
    if (!ese) return;
    if (ese.state !== 3) {
      ctx.warn(0, `the database was not cleanly shut down (state ${ese.state}); esent, and so his tool, would first replay the SRU*.log files, which this does not`);
    }
    const software = ctx.siblings?.find((s) => /software/i.test(s.name));
    const { sidToUser, ssids } = software ? await fromSoftware(software, ctx) : { sidToUser: new Map<string, string>(), ssids: new Map<number, string>() };

    // BuildIdMap: application and user ids.
    const apps = new Map<number, AppInfo>();
    const users = new Map<number, { sid: string; sidType: string; userName: string }>();
    const idMap = ese.tables.find((t) => t.name === 'SruDbIdMapTable');
    if (idMap) {
      for await (const r of records(ese, idMap)) {
        const type = r.byte('IdType');
        const index = r.int32('IdIndex');
        const blob = r.bytes('IdBlob');
        if (index === null || type === null) continue;
        try {
          if (type <= 2) {
            const text = blob ? new TextDecoder('utf-16le').decode(blob).replace(/^\0+|\0+$/g, '') : '';
            apps.set(index, appInfo(text));
          } else if (type === 3) {
            const sid = sidString(blob);
            users.set(index, { sid, sidType: sidType(sid), userName: sidToUser.get(sid) ?? '' });
          }
        } catch (e) {
          ctx.warn(0, `SruDbIdMapTable id ${index}: ${(e as Error).message}`);
        }
      }
    } else ctx.warn(0, 'SruDbIdMapTable is missing, so no application or user can be named');

    const who = (table: string, appId: number | null, userId: number | null, missing: Set<string>) => {
      const app = appId === null ? undefined : apps.get(appId);
      const user = userId === null ? undefined : users.get(userId);
      if (!app) missing.add(`app id ${appId}`);
      if (!user) missing.add(`user id ${userId}`);
      return {
        ExeInfo: app?.exeInfo ?? null,
        ExeInfoDescription: app?.exeInfoDescription ?? null,
        ExeTimestamp: app?.timestamp ?? null,
        SidType: user?.sidType ?? 'UnknownOrUserSid',
        Sid: user?.sid ?? null,
        UserName: user?.userName ?? null,
        table,
      };
    };

    /** One of his Get* readers: every record of a table, each made into a row by `make`. */
    async function* read(name: string, table: string, make: (r: Rec, missing: Set<string>) => Row | null) {
      const t = ese!.tables.find((x) => x.name === name);
      if (!t) {
        ctx.warn(0, `table ${name} (${table}) is not in this database`);
        return;
      }
      const missing = new Set<string>();
      let skipped = 0;
      for await (const r of records(ese!, t)) {
        try {
          const row = make(r, missing);
          if (row) yield row;
        } catch (e) {
          skipped++;
          if (skipped <= 3) ctx.warn(0, `${table} (${name}): ${(e as Error).message}; row skipped`);
        }
        if (r.nulls.size) for (const n of r.nulls) missing.add(`an empty ${n}`);
      }
      if (skipped > 3) ctx.warn(0, `${table}: ${skipped} rows skipped in all`);
      if (missing.size) ctx.warn(0, `${table}: rows with ${[...missing].slice(0, 6).join(', ')}${missing.size > 6 ? ', ...' : ''}, where his tool stops reading the table; kept here with those fields empty`);
    }

    const iface = (luid: bigint | null) => {
      if (luid === null) return null;
      const v = Number(BigInt.asIntN(16, luid >> 48n));
      return INTERFACE_TYPES[v] ?? String(v);
    };
    // 64-bit values past 2^53 (a Wi-Fi interface LUID, a configuration hash) stay exact, as text.
    const num = (v: bigint | null) =>
      v === null ? null : v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString();

    yield* read('{973F5D5C-1D90-4944-BE8E-24B94231A174}', 'networkUsages', (r, m) => {
      const appId = r.int32('AppId');
      const userId = r.int32('UserId');
      const luid = r.int64('InterfaceLuid');
      const profile = r.int32('L2ProfileId');
      return {
        Id: r.int32('AutoIncId'),
        Timestamp: r.date('TimeStamp'),
        ...who('networkUsages', appId, userId, m),
        UserId: userId,
        AppId: appId,
        BytesReceived: num(r.int64('BytesRecvd')),
        BytesSent: num(r.int64('BytesSent')),
        InterfaceLuid: num(luid),
        InterfaceType: iface(luid),
        L2ProfileFlags: r.int32('L2ProfileFlags'),
        L2ProfileId: profile,
        ProfileName: (profile !== null && ssids.get(profile)) || '',
      };
    });

    const APP_RESOURCE = ['BackgroundBytesRead', 'BackgroundBytesWritten', 'BackgroundCycleTime', 'FaceTime', 'ForegroundBytesRead', 'ForegroundBytesWritten', 'ForegroundCycleTime'];
    yield* read('{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}', 'appResourceUseInfo', (r, m) => {
      const appId = r.int32('AppId');
      const userId = r.int32('UserId');
      const row: Row = { Id: r.int32('AutoIncId'), Timestamp: r.date('TimeStamp'), ...who('appResourceUseInfo', appId, userId, m), UserId: userId, AppId: appId };
      for (const c of tables[0].columns.slice(10)) row[c.key] = APP_RESOURCE.includes(c.key) ? num(r.int64(c.key)) : r.int32(c.key);
      return row;
    });

    yield* read('{DD6636C4-8929-4683-974E-22C046A43763}', 'networkConnections', (r, m) => {
      const appId = r.int32('AppId');
      const userId = r.int32('UserId');
      const luid = r.int64('InterfaceLuid');
      const profile = r.int32('L2ProfileId');
      const start = r.int64('ConnectStartTime');
      return {
        Id: r.int32('AutoIncId'),
        Timestamp: r.date('TimeStamp'),
        ...who('networkConnections', appId, userId, m),
        UserId: userId,
        AppId: appId,
        ConnectedTime: r.int32('ConnectedTime'),
        ConnectStartTime: start === null ? null : fromFileTime(start),
        InterfaceLuid: num(luid),
        InterfaceType: iface(luid),
        L2ProfileFlags: r.int32('L2ProfileFlags'),
        L2ProfileId: profile,
        ProfileName: (profile !== null && ssids.get(profile)) || '',
      };
    });

    yield* read('{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}', 'pushNotifications', (r, m) => {
      const appId = r.int32('AppId');
      const userId = r.int32('UserId');
      return {
        Id: r.int32('AutoIncId'),
        Timestamp: r.date('TimeStamp'),
        ...who('pushNotifications', appId, userId, m),
        UserId: userId,
        AppId: appId,
        NetworkType: r.int32('NetworkType'),
        NotificationType: r.int32('NotificationType'),
        PayloadSize: r.int32('PayloadSize'),
      };
    });

    // Energy: the long-term table first, then the other, whose ids he shifts past the first's when they collide.
    const energyIds = new Set<number>();
    let lastSeen = 0;
    const energy = (isLt: boolean) => (r: Rec) => {
      let id = r.int32('AutoIncId') ?? 0;
      if (!isLt && energyIds.has(id)) {
        while (energyIds.has(lastSeen)) lastSeen++;
        id += lastSeen;
      }
      energyIds.add(id);
      if (isLt) lastSeen = id;
      const event = isLt ? null : r.int64('EventTimestamp');
      const lt = (k: string) => (isLt ? r.int32(k) : -1);
      return {
        Id: id,
        Timestamp: r.date('TimeStamp'),
        ...who('energyUsage', null, null, new Set()),
        ExeInfo: null,
        ExeInfoDescription: null,
        ExeTimestamp: null,
        SidType: 'UnknownOrUserSid',
        Sid: null,
        UserName: null,
        UserId: r.int32('UserId'),
        AppId: r.int32('AppId'),
        IsLt: isLt,
        ConfigurationHash: num(r.int64('ConfigurationHash')),
        EventTimestamp: event !== null && event > 0n ? fromFileTime(event) : null,
        StateTransition: isLt ? -1 : r.int32('StateTransition'),
        ChargeLevel: isLt ? -1 : r.int32('ChargeLevel'),
        CycleCount: r.int32('CycleCount'),
        DesignedCapacity: r.int32('DesignedCapacity'),
        FullChargedCapacity: r.int32('FullChargedCapacity'),
        ActiveAcTime: lt('ActiveAcTime'),
        ActiveDcTime: lt('ActiveDcTime'),
        ActiveDischargeTime: lt('ActiveDischargeTime'),
        ActiveEnergy: lt('ActiveEnergy'),
        CsAcTime: lt('CsAcTime'),
        CsDcTime: lt('CsDcTime'),
        CsDischargeTime: lt('CsDischargeTime'),
        CsEnergy: lt('CsEnergy'),
      };
    };
    yield* read('{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT', 'energyUsage', energy(true));
    yield* read('{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}', 'energyUsage', energy(false));

    yield* read('{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}', 'vfuprov', (r, m) => {
      const appId = r.int32('AppId');
      const userId = r.int32('UserId');
      const start = r.int64('StartTime') ?? 0n;
      const end = r.int64('EndTime') ?? 0n;
      const w = who('vfuprov', appId, userId, m);
      return {
        Id: r.int32('AutoIncId'),
        Timestamp: r.date('TimeStamp'),
        UserId: userId,
        AppId: appId,
        ...w,
        StartTime: fromFileTime(start),
        EndTime: fromFileTime(end),
        Flags: r.int32('Flags'),
        Duration: timeSpan(end - start),
      };
    });

    yield* read('{5C8CF1C7-7257-4F13-B223-970EF5939312}', 'appTimelineProvider', (r, m) => {
      const appId = r.int32('AppId');
      const userId = r.int32('UserId');
      return {
        Id: r.int32('AutoIncId'),
        Timestamp: r.date('TimeStamp'),
        ...who('appTimelineProvider', appId, userId, m),
        UserId: userId,
        AppId: appId,
        EndTime: fromFileTime(r.int64('EndTime') ?? 0n),
        DurationMs: r.int32('DurationMS'),
      };
    });
  },
};

/** A record read the way his Api.RetrieveColumnAs* calls read it; `nulls` lists the columns asked for and found empty. */
interface Rec {
  nulls: Set<string>;
  byte(name: string): number | null;
  int32(name: string): number | null;
  int64(name: string): bigint | null;
  date(name: string): Date | null;
  bytes(name: string): Uint8Array | undefined;
}

async function* records(ese: Ese, t: EseTable): AsyncGenerator<Rec> {
  const ids = new Map(t.columns.map((c) => [c.name, c.id]));
  for await (const r of ese.rows(t)) {
    const nulls = new Set<string>();
    const get = (name: string, size: number) => {
      const id = ids.get(name);
      if (id === undefined) throw new Error(`${t.name} has no column ${name}`);
      const b = r.get(id);
      if (!b) {
        nulls.add(name);
        return null;
      }
      // ManagedEsent reads the leading bytes of a longer value and refuses a shorter one.
      if (b.length < size) throw new Error(`column ${name} holds ${b.length} bytes, fewer than ${size}`);
      return new DataView(b.buffer, b.byteOffset, b.byteLength);
    };
    yield {
      nulls,
      byte: (n) => get(n, 1)?.getUint8(0) ?? null,
      int32: (n) => get(n, 4)?.getInt32(0, true) ?? null,
      int64: (n) => get(n, 8)?.getBigInt64(0, true) ?? null,
      date: (n) => {
        const dv = get(n, 8);
        return dv ? oaDate(new Uint8Array(dv.buffer, dv.byteOffset, 8)) : null;
      },
      bytes: (n) => {
        const id = ids.get(n);
        return id === undefined ? undefined : r.get(id);
      },
    };
  }
}
