import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import type { Row } from '../core/types';
import { amcache, invariantDate, tables } from './amcache';
import './index';

// Built by fixtures/amcache/make.mjs; every value below is what it wrote.
const load = async (name: string) =>
  run(amcache, bufReader(new Uint8Array(readFileSync(`fixtures/amcache/${name}`)), name));

const byTable = (rows: Row[], table: string) => rows.filter((r) => r.table === table);
const header = (id: string) =>
  (tables.find((t) => t.id === id)?.columns ?? []).map((c) => c.key).filter((k) => k !== 'Deleted');

describe('Amcache, Windows 10 layout', () => {
  it('is what an Amcache.hve opens as, ahead of the plain hive view', async () => {
    const buf = new Uint8Array(readFileSync('fixtures/amcache/Amcache-win10.hve'));
    // Recognised by the path the hive records for itself, so a renamed copy still is.
    expect((await detect(bufReader(buf, 'evidence-17.bin')))?.id).toBe('amcache');
  });

  it('writes his column order, including where CsvHelper places the unindexed ones', () => {
    expect(header('unassociated').join(',')).toBe(
      'ApplicationName,ProgramId,FileKeyLastWriteTimestamp,SHA1,IsOsComponent,FullPath,Name,FileExtension,LinkDate,ProductName,Size,Version,ProductVersion,LongPathHash,BinaryType,IsPeFile,BinFileVersion,BinProductVersion,Usn,Language,Description,OriginalFileName',
    );
    expect(header('programs').slice(0, 9).join(',')).toBe(
      'ProgramId,KeyLastWriteTimestamp,Name,Version,Publisher,InstallDateArpLastModified,InstallDate,InstallDateMsi,InstallDateFromLinkFile',
    );
  });

  it('associates a file with its program and leaves the rest unassociated', async () => {
    const { rows } = await load('Amcache-win10.hve');
    const [tool] = byTable(rows, 'associated');
    expect(tool).toMatchObject({
      ApplicationName: 'Tool Suite',
      SHA1: '4f5b8c1d2e3f4a5b6c7d8e9fa0b1c2d3e4f5a6b7',
      FullPath: 'c:\\program files\\tool suite\\tool.exe',
      FileExtension: '.exe',
      Size: 123456,
      Usn: 98765432,
      IsPeFile: true,
      IsOsComponent: false,
      BinaryType: 'pe64_amd64',
      Description: 'Tool Suite main program',
      Deleted: false,
    });
    expect((tool.LinkDate as Date).toISOString()).toBe('2009-07-13T23:32:37.000Z');

    const unassociated = byTable(rows, 'unassociated');
    expect(unassociated.map((r) => r.Name)).toEqual(['svchost.exe', 'dropper.exe']);
    // Older builds wrote Size as a hex string.
    expect(unassociated[0]).toMatchObject({ ApplicationName: 'Unassociated', Size: 0xc6f8, Language: 1033 });

    const [program] = byTable(rows, 'programs');
    expect(program).toMatchObject({
      Name: 'Tool Suite',
      Publisher: 'Example Corp',
      InstallDateArpLastModified: '02/18/2021 18:46:18',
      Language: 1033,
      FileEntries: 1,
    });
    expect((program.InstallDate as Date).toISOString()).toBe('2021-02-18T18:46:18.000Z');
  });

  it('reports a deleted file key under its live parent, as his Registry library attaches it', async () => {
    const { rows } = await load('Amcache-win10.hve');
    const dropper = rows.find((r) => r.Name === 'dropper.exe');
    expect(dropper).toMatchObject({
      Deleted: true,
      FullPath: 'c:\\users\\suspect\\appdata\\local\\temp\\dropper.exe',
      SHA1: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      Size: 4096,
    });
  });

  it('keeps an entry whose date will not parse, and says so', async () => {
    const { rows, warnings } = await load('Amcache-win10.hve');
    expect(rows.find((r) => r.Name === 'svchost.exe')?.LinkDate).toBeNull();
    expect(warnings.map((w) => w.message)).toEqual([
      'svchost.exe|1234567890abcdef: LinkDate is not a date ("13/45/2010 99:00:00"); left empty',
      'unknown value name in InventoryApplicationFile: BrandNewValue (first seen at key svchost.exe|1234567890abcdef); it is not in any column',
    ]);
  });

  it('reads the shortcut, device and driver keys', async () => {
    const { rows } = await load('Amcache-win10.hve');
    expect(byTable(rows, 'shortcuts')[0].LnkName).toBe(
      'c:\\programdata\\microsoft\\windows\\start menu\\programs\\tool suite.lnk',
    );
    expect(byTable(rows, 'deviceContainers')[0]).toMatchObject({
      FriendlyName: 'DESKTOP-TEST',
      IsMachineContainer: true,
      IsNetworked: false,
    });
    expect(byTable(rows, 'devicePnps')[0]).toMatchObject({
      Compid: 'USB\\Class_08&SubClass_06&Prot_50',
      MatchingId: 'usb\\class_08&subclass_06&prot_50',
      Stackid: '\\Driver\\USBSTOR',
      Service: 'USBSTOR',
    });
    expect(byTable(rows, 'devicePnps')[0]).not.toHaveProperty('DeviceState');
    const [driver] = byTable(rows, 'driverBinaries');
    // His int.Parse would reject a checksum past 2^31 and drop the driver.
    expect(driver).toMatchObject({ DriverCheckSum: 0xf0001234, DriverId: '1111222233334444555566667777888899990000' });
    expect((driver.DriverTimeStamp as Date).toISOString()).toBe('2019-12-07T09:08:57.000Z');
    expect((byTable(rows, 'driverPackages')[0].Date as Date).toISOString()).toBe('2006-06-21T00:00:00.000Z');
  });
});

describe('Amcache, Windows 8 layout', () => {
  it('reads hex-numbered values and his MFT split of the file key name', async () => {
    const { rows, warnings } = await load('Amcache-win8.hve');
    expect(warnings).toEqual([]);
    const [tool] = byTable(rows, 'oldAssociated');
    expect(tool).toMatchObject({
      ProgramName: 'Tool Suite',
      FullPath: 'C:\\Program Files\\Tool Suite\\tool.exe',
      MFTEntryNumber: 0x1a2b,
      MFTSequenceNumber: 3,
      FileSize: 123456,
      CompanyName: 'Example Corp',
    });
    expect((tool.LastModified as Date).toISOString()).toBe('2013-12-01T10:00:00.000Z');
    expect((tool.Created as Date).toISOString()).toBe('2013-11-30T09:00:00.000Z');
    expect((tool.LinkDate as Date).toISOString()).toBe('2009-07-13T23:32:37.000Z');

    // The key with no path is skipped, as he skips it.
    expect(byTable(rows, 'oldUnassociated').map((r) => r.FileID)).toEqual(['10000f00d']);

    const [program] = byTable(rows, 'oldPrograms');
    expect(program).toMatchObject({
      ProgramName_0: 'Tool Suite',
      LanguageCode_3: '1033',
      FileEntries: 1,
      // His switch stores values 13, 14 and 15 all in UnknownDword_13.
      UnknownDword_13: 8,
      UnknownDword_14: 0,
    });
    expect((program.InstallDateEpoch_a as Date).toISOString()).toBe('2014-01-01T00:00:00.000Z');
  });
});

describe('invariantDate', () => {
  it('reads month-first dates as DateTime.Parse does with the invariant culture', () => {
    expect(invariantDate('07/13/2009 23:32:37')?.toISOString()).toBe('2009-07-13T23:32:37.000Z');
    expect(invariantDate('7/4/2020 1:02:03 PM')?.toISOString()).toBe('2020-07-04T13:02:03.000Z');
    expect(invariantDate('2020-07-04 13:02:03')?.toISOString()).toBe('2020-07-04T13:02:03.000Z');
    expect(invariantDate('02/30/2020 00:00:00')).toBeNull();
    expect(invariantDate('13/01/2020 00:00:00')).toBeNull();
  });
});
