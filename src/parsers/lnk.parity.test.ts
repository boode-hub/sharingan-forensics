/**
 * Eric Zimmerman's own Lnk unit-test assertions, run against our parser.
 *
 * The values below are copied from Lnk.Test/TestMain.cs in
 * https://github.com/EricZimmerman/Lnk, and the sample files are his, from the
 * same MIT-licensed repository: a Windows 7 shortcut to a directory, a Windows
 * 8.1 store-app shortcut with no link info at all (the case where the target
 * ID list and property store are all an analyst has), an XP shortcut to a
 * network share, and Vista and XP shortcuts to programs.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { propertyName, parsePropertyStore } from '../core/propstore';
import { lnk } from './lnk';

async function load(name: string) {
  const buf = new Uint8Array(readFileSync(new URL(`../../fixtures/lnk/${name}`, import.meta.url)));
  const outcome = await run(lnk, bufReader(buf, name));
  return {
    outcome,
    target: outcome.rows.find((r) => r.entryType === 'Target') as Record<string, unknown>,
    items: outcome.rows.filter((r) => r.entryType === 'Shell Item'),
    blocks: outcome.rows.filter((r) => r.entryType === 'Extra Block'),
  };
}

describe('a Windows 7 shortcut to a directory', () => {
  it('matches his local.directory.seven assertions', async () => {
    const { target, outcome } = await load('local.directory.seven.lnk');

    expect(target.relativePath).toBe('..\\..\\Administrator');
    // He asserts DriveTypes.DriveFixed; LECmd prints that value's description.
    expect(target.driveType).toBe('Fixed storage media (Hard drive)');
    expect(target.volumeSerialNumber).toBe('502E1A8A');
    expect(target.volumeLabel).toBe('SSD-WIN7');
    expect(target.localPath).toBe('C:\\Users\\');

    expect(target.machineId).toBe('netbook');
    expect(target.machineMacAddress).toBe('00:13:77:d3:4a:59');
    // From LECmd's own vendor table.
    expect(target.machineMacVendor).toBe('SAMSUNG');

    // He asserts the parts separately; this is the same instant.
    expect((target.trackerCreatedOn as Date).toISOString()).toMatch(
      /^2010-07-10T20:59:48/,
    );

    expect(outcome.warnings).toEqual([]);
  });

  it('decodes the target ID list into the path the shell resolved', async () => {
    const { target, items } = await load('local.directory.seven.lnk');

    expect(items.map((i) => `${i.itemKind}:${i.path}`)).toEqual([
      'Root folder: GUID:This PC',
      'Drive letter:C:',
      // Its Beef0004 holds "Users" and "@shell32.dll,-21813"; with two strings
      // his GetStringsFromMultistring leaves the long name empty, and
      // ShellBag0X31 then takes the localised one. "Users" is the short name.
      'Directory:@shell32.dll,-21813',
      'Directory:Administrator',
    ]);
    expect(target.targetIdAbsolutePath).toBe('This PC\\C:\\@shell32.dll,-21813\\Administrator');
    expect(items[2].shortName).toBe('Users');
  });

  it('lists every extra data block the file carries', async () => {
    const { blocks } = await load('local.directory.seven.lnk');
    expect(blocks.map((b) => b.itemKind)).toEqual([
      'KnownFolderDataBlock',
      'PropertyStoreDataBlock',
      'TrackerDataBaseBlock',
    ]);
  });
});

describe('a Windows 8.1 store-app shortcut with no link info', () => {
  it('matches his PhotosApp assertions', async () => {
    const { target, outcome } = await load('PhotosApp.lnk');

    expect(target.relativePath).toBeNull();
    // He asserts VolumeInfo is null; LECmd prints "(None)" for the drive type
    // then, and leaves the other volume fields empty.
    expect(target.driveType).toBe('(None)');
    expect(target.volumeSerialNumber).toBeNull();
    expect(target.volumeLabel).toBeNull();

    expect(target.iconLocation).toBe('%windir%\\FileManager\\PhotosApp.exe');
    expect(String(target.extraBlocksPresent)).toContain('EnvironmentVariableDataBlock');
    expect(outcome.warnings).toEqual([]);
  });

  it('reads the environment variable block, which is the only path there is', async () => {
    const { blocks } = await load('PhotosApp.lnk');
    const env = blocks.find((b) => b.itemKind === 'EnvironmentVariableDataBlock');
    expect(env?.path).toBe('%windir%\\FileManager\\PhotosApp.exe');
  });

  it('decodes the property store block as his Win81Lnk test expects', async () => {
    const buf = new Uint8Array(readFileSync(new URL('../../fixtures/lnk/PhotosApp.lnk', import.meta.url)));
    const at = Buffer.from(buf).indexOf(Buffer.from([0x09, 0x00, 0x00, 0xa0])) - 4;
    const size = new DataView(buf.buffer, buf.byteOffset + at, 4).getUint32(0, true);
    const sheets = parsePropertyStore(buf.subarray(at + 8, at + size), {});
    expect(sheets).toHaveLength(6);
    const tile = sheets.find((s) => s.guid === '86d40b4d-9069-443c-819a-2a54090dccec');
    expect(tile?.properties).toHaveLength(9);
    expect(tile?.properties[0]).toEqual(['2', 'Assets\\PhotosSmallLogo.png']);
    expect(propertyName('86d40b4d-9069-443c-819a-2a54090dccec', '2')).toBe('Tile Small Image Location');

    // And the extra block row shows it the way his ToString lays it out.
    const { blocks } = await load('PhotosApp.lnk');
    const store = blocks.find((b) => b.itemKind === 'PropertyStoreDataBlock');
    expect(String(store?.path)).toContain(
      '86d40b4d-9069-443c-819a-2a54090dccec\\2      Tile Small Image Location           ==> Assets\\PhotosSmallLogo.png',
    );
  });
});

describe('a Windows XP shortcut to a file on a network share', () => {
  it('matches his RemoteFileLnk assertions', async () => {
    const { target, items, blocks, outcome } = await load('remote.file.xp.lnk');
    expect(target.relativePath).toBeNull();
    expect(target.driveType).toBe('(None)');
    expect(target.networkPath).toBe('\\\\ALS-FICHIERS3\\QUALITÉ');
    expect(items.find((i) => i.itemKind === 'Domain/Workgroup name')?.path).toBe('Aldec_lyon');
    expect(target.commonPath).toBe('Archives\\Méthodologie WAS\\Norme de développement JAVA.doc');
    expect(target.machineId).toBe('als-fichiers3');
    expect(target.machineMacAddress).toBe('00:0f:1f:f7:c0:dc');
    expect((target.trackerCreatedOn as Date).toISOString()).toMatch(/^2006-02-08T07:52:55/);
    expect(blocks).toHaveLength(1);
    const last = items[items.length - 1];
    expect(last.path).toBe('Norme de développement JAVA.doc');
    expect(last.mftEntry).toBeNull();
    expect(last.mftSequence).toBeNull();
    expect(outcome.warnings).toEqual([]);
  });
});

describe('a Windows Vista shortcut to a program', () => {
  it('matches his WinVistaLnk assertions', async () => {
    const { target, items, blocks } = await load('Windows Update.lnk');
    expect(target.relativePath).toBe('..\\..\\..\\..\\Windows\\System32\\wuapp.exe');
    expect(target.driveType).toBe('Fixed storage media (Hard drive)');
    expect(target.volumeSerialNumber).toBe('D85CC709');
    expect(target.volumeLabel).toBe('TestOS');
    expect(target.localPath).toBe('D:\\Windows\\System32\\wuapp.exe');
    expect(target.machineMacAddress).toBe('f1:53:4b:e4:3d:84');
    expect(target.machineId).toBe('lh-ixn3n2mx5l20');
    expect((target.trackerCreatedOn as Date).toISOString()).toMatch(/^2006-11-02T15:20:21/);
    expect(blocks).toHaveLength(4);
    const last = items[items.length - 1];
    expect(last.path).toBe('wuapp.exe');
    expect(last.mftEntry).toBe(39556);
    expect(last.mftSequence).toBe(1);
    expect(blocks.find((b) => b.itemKind === 'SpecialFolderDataBlock')?.path).toMatch(/^Folder ID: 37;/);
  });
});

describe('a Windows XP shortcut to a program', () => {
  it('matches his WinXPProgramLnk assertions', async () => {
    const { target, items, blocks } = await load('WordPad.lnk');
    expect(target.relativePath).toBe('..\\..\\..\\..\\..\\Program Files\\Windows NT\\Accessories\\wordpad.exe');
    expect(target.driveType).toBe('Fixed storage media (Hard drive)');
    expect(target.volumeSerialNumber).toBe('E0F7E847');
    expect(target.volumeLabel).toBe('');
    expect(target.localPath).toBe('C:\\Program Files\\Windows NT\\Accessories\\wordpad.exe');
    expect(target.machineMacAddress).toBe('ff:bf:e3:1c:f8:45');
    expect(target.machineId).toBe('xppro');
    expect((target.trackerCreatedOn as Date).toISOString()).toMatch(/^2016-01-13T11:23:16/);
    expect(blocks).toHaveLength(2);
    const last = items[items.length - 1];
    expect(last.path).toBe('wordpad.exe');
    expect(last.mftEntry).toBeNull();
  });
});
