/**
 * ActivitiesCache.db, the Windows 10 Timeline: what was opened, focused,
 * copied and pasted, per user.
 *
 * Ported from Eric Zimmerman's WxTCmd (https://github.com/EricZimmerman/WxTCmd:
 * Program.cs, Classes/ActivityEntry.cs, ActivityOperationEntry.cs,
 * ActivityPackageIdEntry.cs, DisplayTextInfo.cs and his EpochConverter),
 * reading the database through the same SQLite engine as SQLECmd.
 *
 * Where his tool stops reading a table at a row it cannot parse (bad JSON, an
 * empty AppId list, a malformed %-escape), this skips that row with a warning
 * and reads the rest.
 */
import type { SqlValue } from 'sql.js';
import type { Column, ColType, Ctx, Parser, Reader, Row, Table } from '../core/types';
import { guid } from '../core/binary';
import { isSqlite, openSqlite } from './sqlite';

const cols = (spec: string): Column[] =>
  spec
    .trim()
    .split(/\s+/)
    .map((s) => {
      const [key, type = 'str'] = s.split(':');
      return { key, label: key.replace(/([a-z])([A-Z])/g, '$1 $2'), type: type as ColType };
    });

// His three CSV maps, in their Index order.
export const tables: Table[] = [
  {
    id: 'activity',
    label: 'Activity',
    columns: cols(`Id ActivityTypeOrg:num ActivityType Executable DisplayText ContentInfo Payload ClipboardPayload
      StartTime:date EndTime:date Duration LastModifiedTime:date LastModifiedOnClient:date
      OriginalLastModifiedOnClient:date ExpirationTime:date CreatedInCloud:date IsLocalOnly:bool ETag:num
      PackageIdHash PlatformDeviceId DevicePlatform TimeZone`),
  },
  {
    id: 'operations',
    label: 'ActivityOperations',
    columns: cols(`Id ActivityTypeOrg:num ActivityType Executable DisplayText ContentInfo Payload ClipboardPayload
      StartTime:date EndTime:date Duration LastModifiedTime:date LastModifiedTimeOnClient:date CreatedTime:date
      ExpirationTime:date OperationExpirationTime:date OperationOrder:num AppId OperationType:num Description
      PlatformDeviceId DevicePlatform TimeZone`),
  },
  {
    id: 'packageIds',
    label: 'Activity_PackageIDs',
    columns: cols('Id Platform Name AdditionalInformation Expires:date'),
  },
];

// The columns his ORM classes select. A table missing any of them makes his query fail.
const CLASS_COLUMNS: Record<string, string[]> = {
  Activity:
    'Id AppId PackageIdHash AppActivityId ActivityType ActivityStatus ParentActivityId Tag Group MatchId LastModifiedTime ExpirationTime Payload Priority IsLocalOnly PlatformDeviceId DsdDeviceId CreatedInCloud StartTime EndTime LastModifiedOnClient GroupAppActivityId ClipboardPayload EnterpriseId OriginalPayload UserActionState IsRead OriginalLastModifiedOnClient GroupItems LocalExpirationTime ETag'.split(' '),
  ActivityOperation:
    'OperationOrder Id OperationType AppId PackageHashId AppActivityId ActivityType ParentActivityId Tag Group MatchId LastModifiedTime ExpirationTime Payload Priority CreatedTime OperationExpirationTime PlatformDeviceId DdsDeviceId CreatedInCloud StartTime EndTime LastModifiedOnClient CorrelationVector GroupAppActivityId ClipboardPayload EnterpriseId UserActionState IsRead OriginalPayload OriginalLastModifiedOnClient UploadAllowedByPolicy PatchFields GroupItems ThrottleReleaseTime ETag'.split(' '),
  Activity_PackageId: 'ActivityId Platform PackageName ExpirationTime'.split(' '),
};

const ACTIVITY_TYPES: Record<number, string> = { 2: 'ToastNotification', 5: 'ExecuteOpen', 6: 'InFocus', 10: 'CloudClipboard', 16: 'CopyPaste' };

/** An int column as System.Data.SQLite's GetInt32 reads it: the low 32 bits of an integer. */
const int32 = (v: SqlValue | undefined): number | null =>
  typeof v === 'bigint' ? Number(BigInt.asIntN(32, v)) : typeof v === 'number' && Number.isInteger(v) ? v | 0 : null;

/** His EpochConverter: Unix seconds read as an int, with 0 (or anything unreadable) as no time. */
function epoch(v: SqlValue | undefined): Date | null {
  const s = int32(v);
  return s ? new Date(s * 1000) : null;
}

/** DateTimeOffset.MinValue, which his non-nullable times hold when the column has no time. */
const MIN_SECONDS = -62135596800;

/** TimeSpan.ToString(): [-][d.]hh:mm:ss. */
function timeSpan(seconds: number): string {
  const sign = seconds < 0 ? '-' : '';
  let s = Math.abs(seconds);
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const p = (n: number) => String(n).padStart(2, '0');
  return `${sign}${d ? `${d}.` : ''}${p(Math.floor(s / 3600))}:${p(Math.floor((s % 3600) / 60))}:${p(s % 60)}`;
}

/** His Duration: set when there is an end, it differs from the start, and it is after 1970. */
function duration(start: Date | null, end: Date | null): string | null {
  if (!end || (start && end.getTime() === start.getTime()) || end.getUTCFullYear() <= 1970) return null;
  const s = start ? start.getTime() / 1000 : MIN_SECONDS;
  return timeSpan(end.getTime() / 1000 - s);
}

/** Encoding.ASCII.GetString: anything past 0x7F reads as "?". */
function ascii(v: SqlValue | undefined): string {
  const b = typeof v === 'string' ? new TextEncoder().encode(v) : v instanceof Uint8Array ? v : new Uint8Array(0);
  let s = '';
  for (const x of b) s += x < 0x80 ? String.fromCharCode(x) : '?';
  return s;
}

/** ServiceStack's UrlDecode: '+' is a space, %XX a byte (a bad one throws), anything else its low byte, then UTF-8. */
function urlDecode(text: string | null): string | null {
  if (!text) return null;
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '+') bytes.push(32);
    else if (c === '%') {
      const hex = text.slice(i + 1, i + 3);
      if (!/^[0-9a-f]{1,2}$/i.test(hex)) throw new Error(`invalid %-escape "%${hex}" in ${text}`);
      bytes.push(parseInt(hex, 16));
      i += 2;
    } else bytes.push(text.charCodeAt(i) & 0xff);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

/** A JSON property as ServiceStack binds it: names compared ignoring case, the last one given winning. */
function prop(o: unknown, name: string): string | null {
  if (!o || typeof o !== 'object') return null;
  let v: unknown = undefined;
  for (const [k, x] of Object.entries(o)) if (k.toLowerCase() === name.toLowerCase()) v = x;
  if (v === undefined || v === null) return null;
  return typeof v === 'string' ? v : typeof v === 'object' ? JSON.stringify(v) : String(v);
}

type Names = Record<string, string>;

/** GuidMapping.GetDescriptionFromGuid. */
function guidName(names: Names, g: string): string {
  let key = g.toLowerCase();
  if (key.startsWith('{')) key = key.replaceAll('{', '').replaceAll('}', '');
  return names[key] ?? `Unmapped GUID: ${g}`;
}

/** A path whose first segment is a known-folder GUID, with the folder's name in its place. */
function guidPath(names: Names, path: string): string {
  const segs = path.split('\\');
  if (!segs[0].startsWith('{')) return path;
  segs[0] = guidName(names, segs[0]);
  return segs.join('\\');
}

/** What he takes from a Payload: the display text, content info, device platform and time zone. */
function payloadInfo(names: Names, payload: string) {
  const out = { displayText: '', contentInfo: '', devicePlatform: '', timeZone: '' };
  if (!payload.startsWith('{')) return out;
  const dti: unknown = JSON.parse(payload);
  out.timeZone = prop(dti, 'UserTimezone') ?? '';
  out.devicePlatform = prop(dti, 'DevicePlatform') ?? '';
  out.displayText = prop(dti, 'DisplayText') ?? '';
  const contentUri = prop(dti, 'ContentUri');
  const description = prop(dti, 'Description');
  if (contentUri !== null || description !== null) {
    out.displayText = `${prop(dti, 'DisplayText') ?? ''} (${prop(dti, 'AppDisplayName') ?? ''})`;
    const ci = urlDecode(contentUri);
    out.contentInfo = `${description ?? ''} (${ci ?? ''})`;
    // His known-folder substitution assumes the GUID sits at characters 6-41.
    if (ci !== null && ci.includes('{') && ci.includes('}')) {
      if (ci.length < 43) throw new Error(`ContentUri too short for his GUID substitution: ${ci}`);
      out.contentInfo = `${description ?? ''} (${ci.slice(0, 5)}${guidName(names, ci.slice(6, 42))}${ci.slice(43)})`;
    }
  }
  return out;
}

const guidText = (v: SqlValue | undefined) =>
  v instanceof Uint8Array ? guid(v) : typeof v === 'string' ? v.toLowerCase() : '00000000-0000-0000-0000-000000000000';
const str = (v: SqlValue | undefined): string | null => (v === null || v === undefined ? null : String(v));

function appIds(v: SqlValue | undefined): Array<{ application: string; platform: string }> {
  const list: unknown = JSON.parse(str(v) ?? 'null');
  if (!Array.isArray(list) || list.length === 0) throw new Error(`AppId holds no applications: ${str(v)}`);
  return list.map((x) => ({ application: prop(x, 'Application') ?? '', platform: prop(x, 'Platform') ?? '' }));
}

export const wxtcmd: Parser = {
  id: 'wxtcmd',
  name: 'Windows Timeline (ActivitiesCache.db)',
  ezTool: 'WxTCmd',
  extensions: [],
  columns: tables[0].columns,
  tables,
  sniff: (head: Uint8Array, filename: string) => isSqlite(head) && /activitiescache/i.test(filename),
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const [db, { GUID_NAMES: names }] = await Promise.all([openSqlite(reader, ctx), import('./lnk/guids')]);
    if (!db) return;

    /** Every row of a table as his ORM would load it, by column name. */
    function* select(table: string): Generator<Record<string, SqlValue>> {
      const info = db!.prepare(`PRAGMA table_info("${table}")`);
      const have = new Set<string>();
      while (info.step()) have.add(String(info.get()[1]).toLowerCase());
      info.free();
      if (have.size === 0) {
        ctx.warn(0, `${table} table does not exist`);
        return;
      }
      const missing = CLASS_COLUMNS[table].filter((c) => !have.has(c.toLowerCase()));
      if (missing.length) ctx.warn(0, `${table} lacks ${missing.join(', ')}, so his query would fail; read with those columns empty`);
      const st = db!.prepare(`SELECT * FROM "${table}"`);
      try {
        const names = st.getColumnNames().map((n) => n.toLowerCase());
        while (st.step()) {
          const vals = st.get(null, { useBigInt: true });
          const row: Record<string, SqlValue> = {};
          names.forEach((n, i) => (row[n] = vals[i]));
          yield row;
        }
      } finally {
        st.free();
      }
    }

    const each = function* <T>(table: string, make: (r: Record<string, SqlValue>) => T) {
      for (const r of select(table)) {
        try {
          yield make(r);
        } catch (e) {
          ctx.warn(0, `${table} row ${guidText(r.id ?? r.activityid)}: ${(e as Error).message}; row skipped`);
        }
      }
    };

    try {
      for (const row of each('ActivityOperation', (op) => {
        const ids = appIds(op.appid);
        const id =
          ids.find((t) => /^(windows_win32|x_exe_path)$/i.test(t.platform)) ?? ids[0];
        const exe = id.application.includes('.exe') ? guidPath(names, id.application) : id.application;
        let payload = ascii(op.payload);
        const info = payloadInfo(names, payload);
        if (!payload.startsWith('{')) payload = '(Binary data)';
        const start = epoch(op.starttime);
        const end = epoch(op.endtime);
        const type = int32(op.activitytype) ?? 0;
        return {
          table: 'operations',
          Id: guidText(op.id),
          ActivityTypeOrg: type,
          ActivityType: ACTIVITY_TYPES[type] ?? String(type),
          Executable: exe,
          DisplayText: info.displayText,
          ContentInfo: info.contentInfo,
          Payload: payload,
          ClipboardPayload: ascii(op.clipboardpayload),
          StartTime: start,
          EndTime: end,
          Duration: duration(start, end),
          LastModifiedTime: epoch(op.lastmodifiedtime),
          LastModifiedTimeOnClient: epoch(op.lastmodifiedonclient),
          CreatedTime: epoch(op.createdtime),
          ExpirationTime: epoch(op.expirationtime),
          OperationExpirationTime: epoch(op.operationexpirationtime),
          OperationOrder: int32(op.operationorder) ?? 0,
          AppId: str(op.appid),
          OperationType: int32(op.operationtype) ?? 0,
          Description: '',
          PlatformDeviceId: str(op.platformdeviceid),
          DevicePlatform: info.devicePlatform,
          TimeZone: info.timeZone,
        } satisfies Row;
      }))
        yield row;

      const PLATFORMS: Record<string, string> = { windows_win32: 'Win32', x_exe_path: 'ExecutablePath', packageId: 'Package' };
      for (const row of each('Activity_PackageId', (p) => {
        const name = str(p.packagename) ?? '';
        const platform = str(p.platform) ?? '';
        return {
          table: 'packageIds',
          Id: guidText(p.activityid),
          Platform: PLATFORMS[platform] ?? platform,
          Name: name,
          AdditionalInformation: name.includes('.exe') && name.startsWith('{') ? guidPath(names, name) : '',
          Expires: epoch(p.expirationtime),
        } satisfies Row;
      }))
        yield row;

      for (const row of each('Activity', (act) => {
        const ids = appIds(act.appid);
        const win32 = ids.find((t) => t.platform === 'windows_win32' || t.platform === 'x_exe_path');
        let exe = (win32 ?? ids.find((t) => t.platform === 'windows_universal') ?? ids[0]).application;
        if (exe.startsWith('{')) exe = guidPath(names, exe);
        let payload = ascii(act.payload);
        const info = payloadInfo(names, payload);
        if (!payload.startsWith('{')) payload = '(Binary data)';
        const start = epoch(act.starttime);
        const end = epoch(act.endtime);
        const type = int32(act.activitytype) ?? 0;
        return {
          table: 'activity',
          Id: guidText(act.id),
          ActivityTypeOrg: type,
          ActivityType: ACTIVITY_TYPES[type] ?? String(type),
          Executable: exe,
          DisplayText: info.displayText,
          ContentInfo: info.contentInfo,
          Payload: payload,
          ClipboardPayload: ascii(act.clipboardpayload),
          StartTime: start,
          EndTime: end,
          Duration: duration(start, end),
          LastModifiedTime: epoch(act.lastmodifiedtime),
          LastModifiedOnClient: epoch(act.lastmodifiedonclient),
          OriginalLastModifiedOnClient: epoch(act.originallastmodifiedonclient),
          ExpirationTime: epoch(act.expirationtime),
          CreatedInCloud: epoch(act.createdincloud),
          IsLocalOnly: int32(act.islocalonly) === 1,
          ETag: int32(act.etag) ?? 0,
          PackageIdHash: str(act.packageidhash),
          PlatformDeviceId: str(act.platformdeviceid),
          DevicePlatform: info.devicePlatform,
          TimeZone: info.timeZone,
        } satisfies Row;
      }))
        yield row;
    } finally {
      db.close();
    }
  },
};
