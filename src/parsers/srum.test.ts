import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { openEse } from '../core/ese';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import type { Row } from '../core/types';
import { sidType, srum } from './srum';
import './index';

// fixtures/srum/SRUDB.dat was written by Windows' own ESE engine (make.ps1).
// The expected rows are what SrumECmd's Srum.cs makes of it, worked by hand:
// the "!!" app entry split into name, time and description, SID types,
// interface types from the LUID's top 16 bits, the energy id shifted past the
// long-term table's, vfuprov's duration as TimeSpan text.
const buf = new Uint8Array(readFileSync('fixtures/srum/SRUDB.dat'));
const load = () => run(srum, bufReader(buf, 'SRUDB.dat'));
const iso = (r: Row) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v instanceof Date ? v.toISOString() : v]));
const of = (rows: Row[], t: string) => rows.filter((r) => r.table === t).map(iso);

const SVCHOST = '\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe';
const CALC = {
  ExeInfo: 'Microsoft.WindowsCalculator_8wekyb3d8bbwe!App',
  ExeInfoDescription: 'Calculator',
  ExeTimestamp: '2026-09-01T10:20:30.000Z',
};
const SYSTEM = { SidType: 'LocalSystem', Sid: 'S-1-5-18', UserName: '' };
const USER = { SidType: 'UnknownOrUserSid', Sid: 'S-1-5-21-111-222-333-1001', UserName: '' };
const ADMIN = { SidType: 'Administrator', Sid: 'S-1-5-21-111-222-333-500', UserName: '' };
const T = '2026-09-20T10:00:00.000Z';

describe('SRUDB.dat (SrumECmd)', () => {
  it('is recognised by the ESE signature and its name', async () => {
    expect((await detect(bufReader(buf, 'SRUDB.dat')))?.id).toBe('srum');
  });

  it('reads the ESE database, a long value included', async () => {
    const ese = await openEse(bufReader(buf, 'SRUDB.dat'), () => undefined);
    const idmap = ese?.tables.find((t) => t.name === 'SruDbIdMapTable');
    expect(idmap?.lvFdp).not.toBe(null);
    const blobs: number[] = [];
    for await (const r of ese!.rows(idmap!)) blobs.push(r.get(256)?.length ?? 0);
    expect(blobs).toEqual([106, 18, 162, 12, 28, 28, 6070]);
  });

  it('maps SIDs to his SidType names', () => {
    expect(sidType('S-1-5-18')).toBe('LocalSystem');
    expect(sidType('S-1-5-5-0-12345')).toBe('LogonId');
    expect(sidType('S-1-5-21-1-2-3-512')).toBe('DomainAdmins');
    expect(sidType('S-1-5-21-1-2-3-1001')).toBe('UnknownOrUserSid');
  });

  it('writes NetworkUsages, the interface type taken from the LUID', async () => {
    const [a, b] = of((await load()).rows, 'networkUsages');
    expect(a).toMatchObject({
      Id: 1,
      Timestamp: T,
      ExeInfo: SVCHOST,
      ExeInfoDescription: null,
      ExeTimestamp: null,
      ...SYSTEM,
      UserId: 4,
      AppId: 1,
      BytesReceived: 42,
      BytesSent: 1234567890123,
      InterfaceLuid: '19984723346456577', // 71 << 48 | 1: past 2^53, kept exact
      InterfaceType: 'IF_TYPE_IEEE80211',
      L2ProfileFlags: 0,
      L2ProfileId: 5,
      ProfileName: '',
    });
    expect(b).toMatchObject({ Id: 2, ...USER, AppId: 7, InterfaceLuid: 1688849860263936, InterfaceType: 'IF_TYPE_ETHERNET_CSMACD', L2ProfileFlags: 3 });
    expect(String(b.ExeInfo)).toMatch(/^\\Device\\HarddiskVolume3\\Tools\\a{3000}\.exe$/);
  });

  it('writes AppResourceUseInfo with a packaged app split into its parts', async () => {
    expect(of((await load()).rows, 'appResourceUseInfo')).toEqual([
      {
        table: 'appResourceUseInfo',
        Id: 1,
        Timestamp: T,
        ...CALC,
        ...ADMIN,
        UserId: 6,
        AppId: 3,
        BackgroundBytesRead: 1100,
        BackgroundBytesWritten: 1200,
        BackgroundContextSwitches: 5,
        BackgroundCycleTime: 200,
        BackgroundNumberOfFlushes: 15,
        BackgroundNumReadOperations: 13,
        BackgroundNumWriteOperations: 14,
        FaceTime: 300,
        ForegroundBytesRead: 600,
        ForegroundBytesWritten: 700,
        ForegroundContextSwitches: 4,
        ForegroundCycleTime: 100,
        ForegroundNumberOfFlushes: 10,
        ForegroundNumReadOperations: 8,
        ForegroundNumWriteOperations: 9,
      },
    ]);
  });

  it('writes NetworkConnections and PushNotifications', async () => {
    const { rows } = await load();
    expect(of(rows, 'networkConnections')).toEqual([
      expect.objectContaining({
        Id: 1,
        ExeInfo: 'DnsCache',
        ...SYSTEM,
        ConnectedTime: 3600,
        ConnectStartTime: '2026-09-20T09:00:00.000Z',
        InterfaceLuid: '19984723346456576',
        InterfaceType: 'IF_TYPE_IEEE80211',
        L2ProfileId: 5,
      }),
    ]);
    expect(of(rows, 'pushNotifications')).toEqual([
      expect.objectContaining({ Id: 1, ...CALC, ...USER, NetworkType: 1, NotificationType: 2, PayloadSize: 512 }),
    ]);
  });

  it('writes EnergyUsage, shifting a colliding id past the long-term table as he does', async () => {
    const [lt, normal] = of((await load()).rows, 'energyUsage');
    expect(lt).toMatchObject({
      Id: 1,
      IsLt: true,
      ExeInfo: null,
      SidType: 'UnknownOrUserSid',
      ConfigurationHash: 77,
      EventTimestamp: null,
      StateTransition: -1,
      ChargeLevel: -1,
      CycleCount: 9,
      DesignedCapacity: 50000,
      FullChargedCapacity: 45000,
      ActiveAcTime: 1,
      CsEnergy: 8,
    });
    expect(normal).toMatchObject({
      Id: 3, // AutoIncId 1 is taken by the LT row: lastSeen moves to 2, and 1 + 2 = 3
      IsLt: false,
      EventTimestamp: '2026-09-20T08:30:00.000Z',
      StateTransition: 1,
      ChargeLevel: 80,
      ActiveAcTime: -1,
      CsEnergy: -1,
    });
  });

  it('writes vfuprov and AppTimelineProvider', async () => {
    const { rows, warnings } = await load();
    expect(of(rows, 'vfuprov')).toEqual([
      expect.objectContaining({
        Id: 1,
        ExeInfo: SVCHOST,
        ...SYSTEM,
        StartTime: '2026-09-20T09:59:58.000Z',
        EndTime: '2026-09-20T09:59:59.500Z',
        Flags: 6,
        Duration: '00:00:01.5000000',
      }),
    ]);
    expect(of(rows, 'appTimelineProvider')).toEqual([
      expect.objectContaining({ Id: 1, ...CALC, ...USER, EndTime: '2026-09-20T11:00:00.000Z', DurationMs: 60000 }),
    ]);
    expect(warnings).toEqual([]);
  });
});
