import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import type { Row } from '../core/types';
import { wxtcmd } from './wxtcmd';
import './index';

// fixtures/wxtcmd/ActivitiesCache.db is built by make.mjs. The values below
// are what WxTCmd's Program.cs makes of each row, worked through by hand.
const buf = new Uint8Array(readFileSync('fixtures/wxtcmd/ActivitiesCache.db'));
const load = () => run(wxtcmd, bufReader(buf, 'ActivitiesCache.db'));
const iso = (r: Row) =>
  Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v instanceof Date ? v.toISOString() : v]));
const T = '2023-11-14T22:13:20.000Z';
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const ID1 = '13121110-1514-1716-1819-1a1b1c1d1e1f';

describe('ActivitiesCache.db (WxTCmd)', () => {
  it('is what an ActivitiesCache.db opens as; other SQLite files stay with SQLECmd', async () => {
    expect((await detect(bufReader(buf, 'ActivitiesCache.db')))?.id).toBe('wxtcmd');
    expect((await detect(bufReader(buf, 'other.db')))?.id).toBe('sqlite');
  });

  it('writes his Activity rows', async () => {
    const { rows } = await load();
    const acts = rows.filter((r) => r.table === 'activity').map(iso);
    expect(acts).toHaveLength(3);
    expect(acts[0]).toMatchObject({
      Id: ID1,
      ActivityTypeOrg: 5,
      ActivityType: 'ExecuteOpen',
      Executable: 'System\\notepad.exe',
      DisplayText: 'notes.txt (Notepad)',
      // His known-folder substitution takes characters 6-41 of the decoded URI as a GUID
      // and drops character 42; on a file URI that is not a GUID at all.
      ContentInfo:
        'C:\\Users\\bob\\notes.txt (file:Unmapped GUID: //C:/Users/bob/notes v2.txt?VolumeId{D7A2E2B2-AAAA-BBBB-CCCC-100000000000}&ObjectId={11111111-2222-3333-4444-555555555555})',
      ClipboardPayload: '',
      StartTime: T,
      EndTime: at(90061),
      Duration: '1.01:01:01',
      LastModifiedTime: at(10),
      LastModifiedOnClient: at(5),
      OriginalLastModifiedOnClient: null,
      ExpirationTime: at(2592000),
      CreatedInCloud: null,
      IsLocalOnly: false,
      ETag: 7,
      PackageIdHash: 'hashA',
      PlatformDeviceId: 'devA',
      DevicePlatform: '',
      TimeZone: '',
    });
    expect(String(acts[0].Payload)).toMatch(/^\{"displayText":"notes.txt"/);
    expect(acts[1]).toMatchObject({
      ActivityType: 'InFocus',
      Executable: 'Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge',
      DisplayText: '',
      ContentInfo: '',
      TimeZone: 'Europe/London',
      DevicePlatform: 'Windows',
      Duration: null,
      IsLocalOnly: true,
      ExpirationTime: '1970-01-01T00:00:01.000Z', // 2^32 + 1, read as an int
    });
    expect(acts[2]).toMatchObject({
      ActivityType: 'CopyPaste',
      Executable: 'C:\\Tools\\app.exe',
      Payload: '(Binary data)',
      ClipboardPayload: '[{"content":"aGk=","formatName":"Text ??"}]',
      EndTime: null,
      Duration: null,
    });
  });

  it('writes his ActivityOperations rows', async () => {
    const ops = (await load()).rows.filter((r) => r.table === 'operations').map(iso);
    expect(ops).toHaveLength(2);
    expect(ops[0]).toMatchObject({
      Id: ID1,
      Executable: 'Windows\\explorer.exe', // platform matched ignoring case here, unlike Activity
      DisplayText: 'x ()',
      ContentInfo: 'd (http://example.com/a b)',
      StartTime: null,
      EndTime: null,
      Duration: null,
      CreatedTime: T,
      OperationExpirationTime: at(1),
      OperationOrder: 1,
      OperationType: 1,
      Description: '',
    });
    expect(ops[1]).toMatchObject({ Executable: 'notepad.exe', Payload: '(Binary data)', Duration: '01:01:01', OperationOrder: 2 });
  });

  it('writes his Activity_PackageIDs rows', async () => {
    const pkgs = (await load()).rows.filter((r) => r.table === 'packageIds').map(iso);
    expect(pkgs.map((p) => [p.Platform, p.AdditionalInformation])).toEqual([
      ['Win32', 'ProgramFilesX64\\Vendor\\tool.exe'],
      ['ExecutablePath', ''],
      ['Package', ''],
      ['windows_universal', ''],
    ]);
    expect(pkgs[0]).toMatchObject({ Id: ID1, Name: '{6D809377-6AF0-444B-8957-A3773F02200E}\\Vendor\\tool.exe', Expires: T });
  });

  it('skips the rows his tool would stop the table at, and says why', async () => {
    const { warnings } = await load();
    expect(warnings.map((w) => w.message)).toEqual([
      expect.stringMatching(/^ActivityOperation row .*: invalid %-escape "%zz".*; row skipped$/),
      expect.stringMatching(/^Activity row .*: AppId holds no applications: \[\]; row skipped$/),
    ]);
  });
});
